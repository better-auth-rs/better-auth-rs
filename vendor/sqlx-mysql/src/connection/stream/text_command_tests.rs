use super::error_transport_support::*;
use super::*;
use crate::arguments::{Arguments, IntoArguments};
use crate::executor::Executor;
use crate::transaction::{MySqlTransactionManager, TransactionManager};
use crate::{MySql, MySqlArguments, MySqlTextCommand};
use futures_util::{FutureExt, TryStreamExt};

fn command() -> MySqlTextCommand {
    let mut sql: Vec<u16> = "select missing_value /* ".encode_utf16().collect();
    sql.extend([0xd800, 0x0041, 0xdc00, 0xd83d, 0xde00]);
    sql.extend(" */".encode_utf16());
    MySqlTextCommand::new(sql)
}

fn exact_error(error: &Error, command: &MySqlTextCommand, number: u16) {
    database_error(error, Some(command.sql()), number);
    let native = error
        .as_database_error()
        .unwrap()
        .downcast_ref::<MySqlDatabaseError>();
    assert_eq!(native.sql_utf16(), Some(command.logical_sql()));
}

#[test]
fn explicit_text_sends_com_query_and_retains_logical_utf16() {
    let (mut connection, socket) = connection();
    let command = command();
    socket.error(1054, "unknown column");
    let error = ready(connection.execute(command.query())).unwrap_err();
    exact_error(&error, &command, 1054);
    assert_eq!(
        socket.commands(),
        [[&[3], command.sql().as_bytes()].concat()]
    );
    assert!(command.sql().contains('\u{fffd}'));
    assert!(command.sql().contains('\u{1f600}'));
    assert!(connection.inner.cache_statement.is_empty());
    assert!(connection.inner.stream.waiting.is_empty());

    let empty = MySqlTextCommand::new(Vec::new());
    socket.error(1065, "empty query");
    let error = ready(connection.execute(empty.query())).unwrap_err();
    exact_error(&error, &empty, 1065);
    assert_eq!(socket.commands().last(), Some(&vec![3]));
}

#[test]
fn empty_binary_arguments_still_prepare_after_an_explicit_text_command() {
    let (mut connection, socket) = connection();
    let command = MySqlTextCommand::new("select missing_value".encode_utf16().collect());
    socket.error(1054, "text error");
    let error = ready(connection.execute(command.query())).unwrap_err();
    exact_error(&error, &command, 1054);
    prepare_ok(&socket, 0);
    socket.error(1054, "prepared error");
    let error = ready(connection.execute(sqlx_core::query::query(command.sql()))).unwrap_err();
    database_error(&error, Some(command.sql()), 1054);
    assert_eq!(
        error
            .as_database_error()
            .unwrap()
            .downcast_ref::<MySqlDatabaseError>()
            .sql_utf16(),
        None
    );
    assert_eq!(
        socket
            .commands()
            .iter()
            .map(|packet| packet[0])
            .collect::<Vec<_>>(),
        [3, 0x16, 0x17]
    );
}

#[test]
fn cancelled_text_response_keeps_its_units_after_the_command_is_dropped() {
    for split in [0, 2, 6] {
        let (mut connection, socket) = connection();
        let command = command();
        let expected = command.clone();
        let mut payload = vec![0xff];
        payload.extend(1054_u16.to_le_bytes());
        payload.extend(b"#HY000old partial error");
        let length = u32::try_from(payload.len()).unwrap().to_le_bytes();
        let mut frame = length[..3].to_vec();
        frame.push(1);
        frame.extend(payload);
        socket.0.lock().unwrap().incoming.extend(&frame[..split]);
        assert!(connection.execute(command.query()).now_or_never().is_none());
        drop(command);
        socket.0.lock().unwrap().incoming.extend(&frame[split..]);
        let next = MySqlTextCommand::new("select next_value".encode_utf16().collect());
        let error = ready(connection.execute(next.query())).unwrap_err();
        exact_error(&error, &expected, 1054);
        assert_eq!(socket.commands().len(), 1);
        assert!(connection.inner.stream.waiting.is_empty());
        socket.error(1054, "next error");
        let error = ready(connection.execute(next.query())).unwrap_err();
        exact_error(&error, &next, 1054);
        assert_eq!(socket.commands().len(), 2);
    }
}

#[test]
fn cancelled_text_flush_and_queued_rollback_retain_separate_provenance() {
    let (mut connection, socket) = connection();
    let command = command();
    socket.0.lock().unwrap().block_write = true;
    assert!(connection.execute(command.query()).now_or_never().is_none());
    assert!(socket.commands().is_empty());
    connection.inner.transaction_depth = 1;
    MySqlTransactionManager::start_rollback(&mut connection);
    socket.0.lock().unwrap().block_write = false;
    socket.error(1054, "text failed");
    socket.error(1205, "rollback failed");
    let error = ready(connection.execute("select next_value")).unwrap_err();
    exact_error(&error, &command, 1054);
    let error = ready(connection.execute("select next_value")).unwrap_err();
    database_error(&error, Some("ROLLBACK"), 1205);
    assert_eq!(
        error
            .as_database_error()
            .unwrap()
            .downcast_ref::<MySqlDatabaseError>()
            .sql_utf16(),
        None
    );
    assert_eq!(
        socket.commands(),
        [
            [&[3], command.sql().as_bytes()].concat(),
            [&[3], b"ROLLBACK".as_slice()].concat(),
        ]
    );
    assert!(connection.inner.stream.waiting.is_empty());
}

#[test]
fn text_stream_failure_after_a_row_retains_the_original_command() {
    let (mut connection, socket) = connection();
    let command = command();
    socket.respond(&[1]);
    column(&socket);
    socket.respond(&[1, b'7']);
    socket.error(1366, "row failed");
    let mut rows = connection.fetch(command.query());
    assert!(ready(rows.try_next()).unwrap().is_some());
    let error = ready(rows.try_next()).unwrap_err();
    exact_error(&error, &command, 1366);
    drop(rows);
    assert!(connection.inner.stream.waiting.is_empty());
}

#[test]
fn a_text_command_cannot_acquire_different_sql_or_binary_parameters() {
    let (mut connection, socket) = connection();
    let command = command();
    let query = sqlx_core::query::query_with::<MySql, _>("select different_value", command.clone());
    let error = ready(connection.execute(query)).unwrap_err();
    assert!(matches!(error, Error::Protocol(_)));
    assert!(socket.commands().is_empty());
    assert!(connection.inner.stream.waiting.is_empty());
    let mut arguments: MySqlArguments = command.into_arguments();
    assert!(Arguments::add(&mut arguments, 7_i32).is_err());
    assert_eq!(arguments.len(), 0);
}
