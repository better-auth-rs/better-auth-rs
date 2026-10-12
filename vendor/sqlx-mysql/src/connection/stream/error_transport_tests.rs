use super::*;
use crate::common::StatementCache;
use crate::connection::{Connection, MySqlConnection, MySqlConnectionInner};
use crate::executor::Executor;
use crate::io::ReadBuf;
use crate::transaction::{MySqlTransactionManager, TransactionManager};
use futures_util::{FutureExt, TryStreamExt};
use std::future::Future;
use std::io;
use std::sync::Mutex;
use std::task::{Context, Poll};

#[derive(Default)]
struct Wire {
    incoming: VecDeque<u8>,
    outgoing: Vec<u8>,
    block_write: bool,
    read_error: Option<io::ErrorKind>,
}

#[derive(Clone, Default)]
struct TestSocket(Arc<Mutex<Wire>>);

impl Socket for TestSocket {
    fn try_read(&mut self, buffer: &mut dyn ReadBuf) -> io::Result<usize> {
        let mut wire = self.0.lock().unwrap();
        if let Some(error) = wire.read_error.take() {
            return Err(error.into());
        }
        if wire.incoming.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let count = buffer.remaining_mut().min(wire.incoming.len());
        let bytes: Vec<_> = wire.incoming.drain(..count).collect();
        buffer.put_slice(&bytes);
        Ok(count)
    }

    fn try_write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut wire = self.0.lock().unwrap();
        if wire.block_write {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        wire.outgoing.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn poll_read_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_write_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl TestSocket {
    fn respond(&self, payload: &[u8]) {
        let mut wire = self.0.lock().unwrap();
        let length = u32::try_from(payload.len()).unwrap().to_le_bytes();
        wire.incoming.extend(&length[..3]);
        wire.incoming.push_back(1);
        wire.incoming.extend(payload);
    }

    fn error(&self, number: u16, message: &str) {
        let mut payload = vec![0xff];
        payload.extend(number.to_le_bytes());
        payload.extend(b"#HY000");
        payload.extend(message.as_bytes());
        self.respond(&payload);
    }

    fn commands(&self) -> Vec<Vec<u8>> {
        let wire = self.0.lock().unwrap();
        let mut bytes = wire.outgoing.as_slice();
        let mut commands = Vec::new();
        while !bytes.is_empty() {
            let length =
                usize::try_from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])).unwrap();
            commands.push(bytes[4..4 + length].to_vec());
            bytes = &bytes[4 + length..];
        }
        commands
    }
}

fn connection() -> (MySqlConnection, TestSocket) {
    let socket = TestSocket::default();
    let stream = MySqlStream::with_socket(
        CharSet::utf8mb4,
        Collation::utf8mb4_unicode_ci,
        &MySqlConnectOptions::new(),
        socket.clone(),
    )
    .boxed_socket();
    let connection = MySqlConnection {
        inner: Box::new(MySqlConnectionInner {
            stream,
            transaction_depth: 0,
            status_flags: Status::empty(),
            cache_statement: StatementCache::new(8),
            log_settings: Default::default(),
        }),
    };
    (connection, socket)
}

fn ready<F: Future>(future: F) -> F::Output {
    future
        .now_or_never()
        .expect("The scripted response must complete without a runtime")
}

fn database_error(error: &Error, sql: Option<&str>, number: u16) {
    let native = error
        .as_database_error()
        .unwrap()
        .downcast_ref::<MySqlDatabaseError>();
    assert_eq!(native.sql(), sql);
    assert_eq!(native.number(), number);
    assert_eq!(native.code(), Some("HY000"));
}

fn prepare_ok(socket: &TestSocket, parameters: u16) {
    let mut payload = vec![0];
    payload.extend(7_u32.to_le_bytes());
    payload.extend(0_u16.to_le_bytes());
    payload.extend(parameters.to_le_bytes());
    payload.extend([0, 0, 0]);
    socket.respond(&payload);
}

fn column(socket: &TestSocket) {
    let mut payload = Vec::new();
    for text in ["def", "", "", "", "v", ""] {
        payload.push(u8::try_from(text.len()).unwrap());
        payload.extend(text.as_bytes());
    }
    payload.push(0x0c);
    payload.extend(45_u16.to_le_bytes());
    payload.extend(11_u32.to_le_bytes());
    payload.push(3); // MYSQL_TYPE_LONG
    payload.extend([0, 0, 0, 0, 0]);
    socket.respond(&payload);
}

#[test]
fn text_errors_retain_sent_sql_and_native_classification() {
    let (mut connection, socket) = connection();
    let sql = "insert into `items` values ('private-value')";
    socket.error(1062, "duplicate");
    let error = ready(connection.execute(sql)).unwrap_err();
    database_error(&error, Some(sql), 1062);
    assert!(error.as_database_error().unwrap().is_unique_violation());
    assert_eq!(socket.commands(), [[&[3], sql.as_bytes()].concat()]);
    assert!(connection.inner.stream.waiting.is_empty());
    socket.error(1065, "Query was empty");
    let empty = ready(connection.execute("")).unwrap_err();
    database_error(&empty, Some(""), 1065);
    assert_eq!(socket.commands().last(), Some(&vec![3]));
}

#[test]
fn prepare_and_cached_execute_errors_retain_the_template() {
    let (mut connection, socket) = connection();
    let sql = "insert into items values (?)";
    socket.error(1064, "prepare failed");
    let error = ready(connection.execute(sqlx_core::query::query(sql).bind("first"))).unwrap_err();
    database_error(&error, Some(sql), 1064);

    prepare_ok(&socket, 1);
    column(&socket);
    socket.error(1062, "execute failed");
    let error = ready(connection.execute(sqlx_core::query::query(sql).bind("second"))).unwrap_err();
    database_error(&error, Some(sql), 1062);

    socket.error(1062, "cached execute failed");
    let error = ready(connection.execute(sqlx_core::query::query(sql).bind("third"))).unwrap_err();
    database_error(&error, Some(sql), 1062);
    let commands = socket.commands();
    assert_eq!(
        commands
            .iter()
            .map(|command| command[0])
            .collect::<Vec<_>>(),
        [0x16, 0x16, 0x17, 0x17]
    );
    assert_eq!(&commands[0][1..], sql.as_bytes());
    assert_eq!(&commands[1][1..], sql.as_bytes());
    assert!(!commands[2]
        .windows(sql.len())
        .any(|window| window == sql.as_bytes()));
}

#[test]
fn stream_error_after_a_row_retains_the_dispatched_query() {
    let (mut connection, socket) = connection();
    let sql = "select v from items";
    socket.respond(&[1]);
    column(&socket);
    socket.respond(&[1, b'7']);
    socket.error(1366, "row stream failed");
    let mut rows = connection.fetch(sql);
    assert!(ready(rows.try_next()).unwrap().is_some());
    let error = ready(rows.try_next()).unwrap_err();
    database_error(&error, Some(sql), 1366);
}

#[test]
fn cancellation_drain_never_assigns_an_old_error_to_the_next_query() {
    let (mut connection, socket) = connection();
    assert!(connection
        .execute("select old_query")
        .now_or_never()
        .is_none());
    socket.error(1054, "old query failed");
    let error = ready(connection.execute("select next_query")).unwrap_err();
    database_error(&error, Some("select old_query"), 1054);
    assert_eq!(socket.commands().len(), 1);
    socket.error(1054, "new query failed");
    let error = ready(connection.execute("select next_query")).unwrap_err();
    database_error(&error, Some("select next_query"), 1054);
    assert_eq!(socket.commands().len(), 2);
}

#[test]
fn cancellation_during_prepare_header_or_metadata_retains_old_sql() {
    for metadata in [false, true] {
        let (mut connection, socket) = connection();
        if metadata {
            prepare_ok(&socket, 2);
            column(&socket);
        }
        assert!(connection
            .prepare("select old_query")
            .now_or_never()
            .is_none());
        socket.error(1054, "old prepare failed");
        let error = ready(connection.execute("select next_query")).unwrap_err();
        database_error(&error, Some("select old_query"), 1054);
        assert_eq!(socket.commands().len(), 1);
        assert!(connection.inner.stream.waiting.is_empty());
    }
}

#[test]
fn successful_cancelled_prepare_metadata_is_drained_before_dispatch() {
    for deprecated_eof in [false, true] {
        let (mut connection, socket) = connection();
        if !deprecated_eof {
            connection
                .inner
                .stream
                .capabilities
                .remove(Capabilities::DEPRECATE_EOF);
        }
        prepare_ok(&socket, 2);
        column(&socket);
        assert!(connection
            .prepare("select old_query")
            .now_or_never()
            .is_none());
        column(&socket);
        if !deprecated_eof {
            socket.respond(&[0xfe, 0, 0, 0, 0]);
        }
        socket.error(1054, "new query failed");
        let error = ready(connection.execute("select next_query")).unwrap_err();
        database_error(&error, Some("select next_query"), 1054);
        assert_eq!(
            socket
                .commands()
                .iter()
                .map(|command| command[0])
                .collect::<Vec<_>>(),
            [0x16, 3]
        );
    }
}

#[test]
fn cancellation_during_flush_keeps_the_queued_command_owner() {
    let (mut connection, socket) = connection();
    socket.0.lock().unwrap().block_write = true;
    assert!(connection
        .execute("select old_query")
        .now_or_never()
        .is_none());
    assert!(socket.commands().is_empty());
    socket.0.lock().unwrap().block_write = false;
    socket.error(1054, "old query failed");
    let error = ready(connection.execute("select next_query")).unwrap_err();
    database_error(&error, Some("select old_query"), 1054);
    assert_eq!(socket.commands().len(), 1);
}

#[test]
fn queued_rollback_keeps_a_separate_error_owner() {
    let (mut connection, socket) = connection();
    assert!(connection
        .execute("select old_query")
        .now_or_never()
        .is_none());
    connection.inner.transaction_depth = 1;
    MySqlTransactionManager::start_rollback(&mut connection);
    socket.error(1054, "old query failed");
    socket.error(1205, "rollback failed");
    let error = ready(connection.execute("select next_query")).unwrap_err();
    database_error(&error, Some("select old_query"), 1054);
    let error = ready(connection.execute("select next_query")).unwrap_err();
    database_error(&error, Some("ROLLBACK"), 1205);
    assert_eq!(socket.commands().len(), 2);
    assert!(connection.inner.stream.waiting.is_empty());
}

#[test]
fn completed_result_is_removed_before_the_consumer_drops_the_stream() {
    for row_result in [false, true] {
        let (mut connection, socket) = connection();
        if row_result {
            socket.respond(&[1]);
            column(&socket);
            // With DEPRECATE_EOF, the terminal 0xfe packet has the OK packet shape.
            socket.respond(&[0xfe, 0, 0, 0, 0, 0, 0]);
        } else {
            socket.respond(&[0, 0, 0, 0, 0, 0, 0]);
        }
        let mut results = connection.fetch_many("select completed_query");
        assert!(matches!(
            ready(results.try_next()).unwrap(),
            Some(either::Either::Left(_))
        ));
        drop(results);
        assert!(connection.inner.stream.waiting.is_empty());
        ready(connection.inner.stream.wait_until_ready()).unwrap();
    }
}

#[test]
fn non_sql_errors_and_argument_encoding_failures_do_not_acquire_sql() {
    let (mut connection, socket) = connection();
    socket.error(1047, "unsupported command");
    let error = ready(connection.ping()).unwrap_err();
    database_error(&error, None, 1047);

    let query = sqlx_core::query::query_with_result::<crate::MySql, crate::MySqlArguments>(
        "select unsent_query",
        Err("argument encoding failed".into()),
    );
    let error = ready(connection.execute(query)).unwrap_err();
    assert!(matches!(error, Error::Encode(_)));
    assert_eq!(socket.commands().len(), 1);
    assert!(connection.inner.stream.waiting.is_empty());
}

#[test]
fn cancellation_during_result_metadata_does_not_finish_at_the_metadata_eof() {
    for deprecated_eof in [false, true] {
        let (mut connection, socket) = connection();
        if !deprecated_eof {
            connection
                .inner
                .stream
                .capabilities
                .remove(Capabilities::DEPRECATE_EOF);
        }
        socket.respond(&[1]);
        {
            let mut rows = connection.fetch("select old_query");
            assert!(rows.try_next().now_or_never().is_none());
        }
        column(&socket);
        if !deprecated_eof {
            socket.respond(&[0xfe, 0, 0, 0, 0]);
        }
        socket.respond(&[1, b'7']);
        socket.error(1366, "old row failed");
        let error = ready(connection.execute("select next_query")).unwrap_err();
        database_error(&error, Some("select old_query"), 1366);
        assert_eq!(socket.commands().len(), 1);
        assert!(connection.inner.stream.waiting.is_empty());
    }
}

#[test]
fn missing_sqlstate_and_unknown_error_numbers_are_retained_without_classification() {
    let (mut connection, socket) = connection();
    let mut payload = vec![0xff];
    payload.extend(60000_u16.to_le_bytes());
    payload.extend(b"unknown server error");
    socket.respond(&payload);
    let error = ready(connection.execute("select unknown_error")).unwrap_err();
    let native = error
        .as_database_error()
        .unwrap()
        .downcast_ref::<MySqlDatabaseError>();
    assert_eq!(native.sql(), Some("select unknown_error"));
    assert_eq!(native.number(), 60000);
    assert_eq!(native.code(), None);
    assert_eq!(native.message(), "unknown server error");
    assert_eq!(
        error.as_database_error().unwrap().kind(),
        crate::error::ErrorKind::Other
    );
}

#[test]
fn nonpersistent_execute_error_survives_statement_close_without_a_response() {
    let (mut connection, socket) = connection();
    let sql = "select prepared_value";
    prepare_ok(&socket, 0);
    socket.error(1054, "execute failed");
    let error =
        ready(connection.execute(sqlx_core::query::query(sql).persistent(false))).unwrap_err();
    database_error(&error, Some(sql), 1054);
    assert_eq!(
        socket
            .commands()
            .iter()
            .map(|command| command[0])
            .collect::<Vec<_>>(),
        [0x16, 0x17, 0x19]
    );
    assert!(connection.inner.stream.waiting.is_empty());
}

#[test]
fn later_result_error_keeps_the_query_after_the_first_result_is_dropped() {
    let (mut connection, socket) = connection();
    let sql = "select first_result; select missing_value";
    socket.respond(&[0, 0, 0, 8, 0, 0, 0]);
    {
        let mut results = connection.fetch_many(sql);
        assert!(matches!(
            ready(results.try_next()).unwrap(),
            Some(either::Either::Left(_))
        ));
    }
    socket.error(1054, "later result failed");
    let error = ready(connection.execute("select next_query")).unwrap_err();
    database_error(&error, Some(sql), 1054);
    assert_eq!(socket.commands().len(), 1);
    assert!(connection.inner.stream.waiting.is_empty());
}

#[test]
fn cancellation_inside_packet_headers_and_bodies_preserves_the_old_command() {
    for split in [2, 6] {
        let (mut connection, socket) = connection();
        let mut payload = vec![0xff];
        payload.extend(1054_u16.to_le_bytes());
        payload.extend(b"#HY000old partial error");
        let length = u32::try_from(payload.len()).unwrap().to_le_bytes();
        let mut frame = length[..3].to_vec();
        frame.push(1);
        frame.extend(payload);
        socket.0.lock().unwrap().incoming.extend(&frame[..split]);
        assert!(connection
            .execute("select old_query")
            .now_or_never()
            .is_none());
        socket.0.lock().unwrap().incoming.extend(&frame[split..]);
        let error = ready(connection.execute("select next_query")).unwrap_err();
        database_error(&error, Some("select old_query"), 1054);
        assert_eq!(
            error.as_database_error().unwrap().message(),
            "old partial error"
        );
        assert_eq!(socket.commands().len(), 1);
        assert!(connection.inner.stream.packet_size.is_none());
        assert!(connection.inner.stream.waiting.is_empty());
    }
}

#[test]
fn cancellation_between_maximum_packet_fragments_retains_the_complete_error() {
    let (mut connection, socket) = connection();
    let mut first = vec![0xff];
    first.extend(1054_u16.to_le_bytes());
    first.extend(b"#HY000");
    first.resize(0xFF_FF_FF, b'x');
    socket.respond(&first);
    assert!(connection
        .execute("select old_query")
        .now_or_never()
        .is_none());
    socket.respond(b"tail");
    let error = ready(connection.execute("select next_query")).unwrap_err();
    database_error(&error, Some("select old_query"), 1054);
    let message = error.as_database_error().unwrap().message();
    assert_eq!(message.len(), 0xFF_FF_FF - 9 + 4);
    assert!(message.ends_with("tail"));
    assert_eq!(socket.commands().len(), 1);
    assert!(connection.inner.stream.packet_buffer.is_empty());
    assert!(connection.inner.stream.waiting.is_empty());
}

#[test]
fn transport_failure_during_drain_retains_its_original_io_error() {
    let (mut connection, socket) = connection();
    assert!(connection
        .execute("select old_query")
        .now_or_never()
        .is_none());
    socket.0.lock().unwrap().read_error = Some(io::ErrorKind::ConnectionReset);
    let error = ready(connection.execute("select next_query")).unwrap_err();
    let Error::Io(source) = error else {
        panic!("The original transport error must remain an I/O error");
    };
    assert_eq!(source.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(socket.commands().len(), 1);
}

#[test]
fn cancelled_ping_errors_remain_non_sql_and_block_the_next_dispatch() {
    for split in [0, 2, 6] {
        let (mut connection, socket) = connection();
        let mut payload = vec![0xff];
        payload.extend(1047_u16.to_le_bytes());
        payload.extend(b"#HY000old ping error");
        let length = u32::try_from(payload.len()).unwrap().to_le_bytes();
        let mut frame = length[..3].to_vec();
        frame.push(1);
        frame.extend(payload);
        socket.0.lock().unwrap().incoming.extend(&frame[..split]);
        assert!(connection.ping().now_or_never().is_none());
        socket.0.lock().unwrap().incoming.extend(&frame[split..]);
        let error = ready(connection.execute("select next_query")).unwrap_err();
        database_error(&error, None, 1047);
        assert_eq!(
            error.as_database_error().unwrap().message(),
            "old ping error"
        );
        assert_eq!(socket.commands(), [vec![0x0e]]);
        assert!(connection.inner.stream.waiting.is_empty());

        socket.error(1054, "current SQL error");
        let error = ready(connection.execute("select next_query")).unwrap_err();
        database_error(&error, Some("select next_query"), 1054);
        assert_eq!(socket.commands().len(), 2);
    }
}

#[test]
fn successful_ping_responses_are_consumed_before_the_next_query() {
    for cancelled in [false, true] {
        let (mut connection, socket) = connection();
        if cancelled {
            assert!(connection.ping().now_or_never().is_none());
        }
        socket.respond(&[0, 0, 0, 0, 0, 0, 0]);
        if !cancelled {
            ready(connection.ping()).unwrap();
            assert!(connection.inner.stream.waiting.is_empty());
        }
        socket.error(1054, "current SQL error");
        let error = ready(connection.execute("select next_query")).unwrap_err();
        database_error(&error, Some("select next_query"), 1054);
        assert_eq!(
            socket
                .commands()
                .iter()
                .map(|command| command[0])
                .collect::<Vec<_>>(),
            [0x0e, 3]
        );
        assert!(connection.inner.stream.waiting.is_empty());
    }
}

#[test]
fn cancelled_ping_flush_keeps_its_owner_before_a_queued_rollback() {
    let (mut connection, socket) = connection();
    socket.0.lock().unwrap().block_write = true;
    assert!(connection.ping().now_or_never().is_none());
    assert!(socket.commands().is_empty());
    connection.inner.transaction_depth = 1;
    MySqlTransactionManager::start_rollback(&mut connection);
    socket.0.lock().unwrap().block_write = false;
    socket.error(1047, "old ping error");
    socket.error(1205, "rollback error");
    let error = ready(connection.execute("select next_query")).unwrap_err();
    database_error(&error, None, 1047);
    let error = ready(connection.execute("select next_query")).unwrap_err();
    database_error(&error, Some("ROLLBACK"), 1205);
    assert_eq!(
        socket.commands(),
        [vec![0x0e], [&[3], b"ROLLBACK".as_slice()].concat()]
    );
    assert!(connection.inner.stream.waiting.is_empty());
}
