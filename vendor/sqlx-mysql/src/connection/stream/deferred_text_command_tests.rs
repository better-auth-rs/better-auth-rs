use super::error_transport_support::*;
use super::*;
use crate::arguments::{Arguments, IntoArguments};
use crate::executor::Executor;
use crate::{MySql, MySqlArguments, MySqlDeferredTextCommand, MySqlTextCommand};
use futures_util::FutureExt;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

#[derive(Debug)]
struct NativeFailure(Arc<()>);

impl std::fmt::Display for NativeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native formatting failure")
    }
}

impl std::error::Error for NativeFailure {}

fn check_native_error(error: &Error, command: &MySqlTextCommand) {
    database_error(error, Some(command.sql()), 1054);
    assert_eq!(
        error
            .as_database_error()
            .unwrap()
            .downcast_ref::<MySqlDatabaseError>()
            .sql_utf16(),
        Some(command.logical_sql()),
    );
}

#[test]
fn deferred_text_formats_live_values_once_per_execution() {
    let (mut connection, socket) = connection();
    let value = Arc::new(Mutex::new(vec![0xd800]));
    let calls = Arc::new(AtomicUsize::new(0));
    let command = MySqlDeferredTextCommand::new("select ?".into(), {
        let value = Arc::clone(&value);
        let calls = Arc::clone(&calls);
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            let mut sql: Vec<u16> = "select missing /* ".encode_utf16().collect();
            sql.extend(value.lock().unwrap().iter().copied());
            sql.extend(" */".encode_utf16());
            Ok(sql)
        }
    });
    let clone = command.clone();
    let _ = format!("{clone:?}");
    let query = clone.query();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    socket.error(1054, "first execution");
    let error = ready(connection.execute(query)).unwrap_err();
    let expected = MySqlTextCommand::new(
        "select missing /* "
            .encode_utf16()
            .chain([0xd800])
            .chain(" */".encode_utf16())
            .collect(),
    );
    check_native_error(&error, &expected);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    *value.lock().unwrap() = vec![0xdc00, 0x0041];
    socket.error(1054, "second execution");
    let error = ready(connection.execute(command.query())).unwrap_err();
    let updated = MySqlTextCommand::new(
        "select missing /* "
            .encode_utf16()
            .chain([0xdc00, 0x0041])
            .chain(" */".encode_utf16())
            .collect(),
    );
    check_native_error(&error, &updated);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        socket.commands(),
        [
            [&[3], expected.sql().as_bytes()].concat(),
            [&[3], updated.sql().as_bytes()].concat(),
        ]
    );
    assert!(connection.inner.cache_statement.is_empty());
}

#[test]
fn deferred_text_rejects_different_templates_before_native_callbacks() {
    let (mut connection, socket) = connection();
    let calls = Arc::new(AtomicUsize::new(0));
    let command = MySqlDeferredTextCommand::new("select ?".into(), {
        let calls = Arc::clone(&calls);
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok("select 1".encode_utf16().collect())
        }
    });
    let query = sqlx_core::query::query_with::<MySql, _>("select different", command.clone());
    assert!(matches!(
        ready(connection.execute(query)),
        Err(Error::Protocol(_))
    ));
    let mut arguments: MySqlArguments = command.into_arguments();
    assert!(Arguments::add(&mut arguments, 7_i32).is_err());
    assert_eq!(arguments.len(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(socket.commands().is_empty());
    assert!(connection.inner.stream.waiting.is_empty());
}

#[test]
fn deferred_failure_preserves_boxed_identity_and_pending_command_ownership() {
    let (mut connection, socket) = connection();
    let old = MySqlTextCommand::new(
        "select old_missing"
            .encode_utf16()
            .chain([0xd800])
            .collect(),
    );
    assert!(connection.execute(old.query()).now_or_never().is_none());
    let identity = Arc::new(());
    let calls = Arc::new(AtomicUsize::new(0));
    let failed = MySqlDeferredTextCommand::new("select ?".into(), {
        let identity = Arc::clone(&identity);
        let calls = Arc::clone(&calls);
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(Box::new(NativeFailure(Arc::clone(&identity))))
        }
    });
    for _ in 0..2 {
        let Error::Encode(error) = ready(connection.execute(failed.query())).unwrap_err() else {
            panic!("Formatting must retain the boxed native error");
        };
        assert!(Arc::ptr_eq(
            &error.downcast_ref::<NativeFailure>().unwrap().0,
            &identity
        ));
        assert_eq!(socket.commands().len(), 1);
        assert_eq!(connection.inner.stream.waiting.len(), 1);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let next = MySqlDeferredTextCommand::new("select next".into(), {
        let calls = Arc::clone(&calls);
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok("select next".encode_utf16().collect())
        }
    });
    socket.error(1054, "old command failed");
    let error = ready(connection.execute(next.query())).unwrap_err();
    check_native_error(&error, &old);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(socket.commands().len(), 1);
    assert!(connection.inner.stream.waiting.is_empty());
    socket.error(1054, "next command failed");
    let error = ready(connection.execute(next.query())).unwrap_err();
    check_native_error(
        &error,
        &MySqlTextCommand::new("select next".encode_utf16().collect()),
    );
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert_eq!(socket.commands().len(), 2);
}
