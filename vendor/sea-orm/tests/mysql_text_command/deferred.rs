use super::*;
use futures_util::FutureExt;
use sea_orm::ConnAcquireErr;
use std::{
    pin::pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Debug)]
struct NativeFailure(Arc<()>);

impl std::fmt::Display for NativeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native formatting failure")
    }
}

impl std::error::Error for NativeFailure {}

fn failing_statement(calls: &Arc<AtomicUsize>, identity: &Arc<()>) -> Statement {
    let calls = Arc::clone(calls);
    let identity = Arc::clone(identity);
    Statement::from_mysql_text_deferred("SELECT ?".into(), move || {
        calls.fetch_add(1, Ordering::SeqCst);
        Err(Box::new(NativeFailure(Arc::clone(&identity))))
    })
}

fn check_failure(error: &DbErr, identity: &Arc<()>) -> TestResult {
    let (DbErr::Exec(RuntimeErr::SqlxError(source)) | DbErr::Query(RuntimeErr::SqlxError(source))) =
        error
    else {
        return Err(format!("Expected the original SQLx error: {error}").into());
    };
    let sqlx::Error::Encode(source) = source.as_ref() else {
        return Err("Expected native formatting error".into());
    };
    let source = source
        .downcast_ref::<NativeFailure>()
        .ok_or("Missing original native failure")?;
    assert!(Arc::ptr_eq(&source.0, identity));
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn live_deferred_pool_failure_and_cancellation_do_not_format() -> TestResult {
    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?);
    options
        .max_connections(1)
        .min_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .sqlx_logging(false);
    let database = Database::connect(options).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let identity = Arc::new(());
    let statement = failing_statement(&calls, &identity);
    let result: TestResult = async {
        let held = database.get_mysql_connection_pool().acquire().await?;
        assert!(
            database
                .execute_raw(statement.clone())
                .now_or_never()
                .is_none()
        );
        assert!(
            database
                .stream_raw(statement.clone())
                .now_or_never()
                .is_none()
        );
        let error = database
            .query_one_raw(statement.clone())
            .await
            .expect_err("Exhausted pool must time out");
        assert!(matches!(
            error,
            DbErr::ConnectionAcquire(ConnAcquireErr::Timeout)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(held);
        let error = database
            .query_one_raw(statement.clone())
            .await
            .expect_err("Acquired query must format");
        check_failure(&error, &identity)?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            database
                .query_one_raw(text("SELECT 1 AS value"))
                .await?
                .is_some()
        );
        Ok(())
    }
    .await;
    database.clone().close().await?;
    result?;
    for error in [
        database
            .execute_raw(statement.clone())
            .await
            .expect_err("Closed execute must fail"),
        database
            .query_one_raw(statement.clone())
            .await
            .expect_err("Closed query must fail"),
        database
            .query_all_raw(statement.clone())
            .await
            .expect_err("Closed queries must fail"),
        database
            .stream_raw(statement)
            .await
            .expect_err("Closed stream must fail"),
    ] {
        assert!(matches!(
            error,
            DbErr::ConnectionAcquire(ConnAcquireErr::ConnectionClosed)
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn live_deferred_transaction_waits_for_stream_lock_and_releases_on_error() -> TestResult {
    let database = database().await?;
    let result = async {
        let id = connection_id(&database).await?;
        let transaction = database.begin().await?;
        let calls = Arc::new(AtomicUsize::new(0));
        let identity = Arc::new(());
        let statement = failing_statement(&calls, &identity);
        let held = transaction.stream_raw(text("SELECT 1 AS value")).await?;
        assert!(
            transaction
                .execute_raw(statement.clone())
                .now_or_never()
                .is_none()
        );
        assert!(
            transaction
                .stream_raw(statement.clone())
                .now_or_never()
                .is_none()
        );
        let error = {
            let mut pending = pin!(transaction.query_one_raw(statement.clone()));
            assert!(pending.as_mut().now_or_never().is_none());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            drop(held);
            pending
                .await
                .expect_err("Acquired transaction query must format")
        };
        check_failure(&error, &identity)?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let error = transaction
            .execute_raw(statement.clone())
            .await
            .expect_err("Execute must format");
        check_failure(&error, &identity)?;
        let error = transaction
            .query_all_raw(statement.clone())
            .await
            .expect_err("Query all must format");
        check_failure(&error, &identity)?;
        let mut rows = transaction.stream_raw(statement).await?;
        let error = rows
            .try_next()
            .await
            .expect_err("Transaction stream must format");
        check_failure(&error, &identity)?;
        drop(rows);
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(connection_id(&transaction).await?, id);
        transaction.rollback().await?;
        assert_eq!(connection_id(&database).await?, id);
        Ok(())
    }
    .await;
    database.close().await?;
    result
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn live_deferred_reexecution_and_streams_use_current_native_values() -> TestResult {
    let database = database().await?;
    let result = async {
        let prepared = prepared_count(&database).await?;
        let sql = Arc::new(Mutex::new(
            "SELECT 7 AS value".encode_utf16().collect::<Vec<_>>(),
        ));
        let calls = Arc::new(AtomicUsize::new(0));
        let statement = Statement::from_mysql_text_deferred("SELECT ? AS value".into(), {
            let sql = Arc::clone(&sql);
            let calls = Arc::clone(&calls);
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(sql.lock().unwrap().clone())
            }
        });
        let mut immutable = statement.clone();
        immutable.sql = "SELECT unsent_value".into();
        immutable.values = Some(sea_query::Values(vec![9.into()]));
        assert_eq!(immutable.to_string(), "SELECT ? AS value");
        let _ = format!("{immutable:?}");
        assert!(immutable.mysql_text_sql().is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let unpolled = database.stream_raw(statement.clone()).await?;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(unpolled);
        let row = database
            .query_one_raw(immutable)
            .await?
            .ok_or("Missing first row")?;
        assert_eq!(row.try_get::<i32>("", "value")?, 7);
        *sql.lock().unwrap() = "SELECT 8 AS value".encode_utf16().collect();
        let rows = database.query_all_raw(statement.clone()).await?;
        assert_eq!(rows[0].try_get::<i32>("", "value")?, 8);
        *sql.lock().unwrap() = "SELECT 9 AS value".encode_utf16().collect();
        let rows = database
            .stream_raw(statement.clone())
            .await?
            .try_collect::<Vec<_>>()
            .await?;
        assert_eq!(rows[0].try_get::<i32>("", "value")?, 9);
        let transaction = database.begin().await?;
        let unpolled = transaction.stream_raw(statement.clone()).await?;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        drop(unpolled);
        *sql.lock().unwrap() = "SELECT 10 AS value".encode_utf16().collect();
        let rows = transaction
            .stream_raw(statement.clone())
            .await?
            .try_collect::<Vec<_>>()
            .await?;
        assert_eq!(rows[0].try_get::<i32>("", "value")?, 10);
        let units = native_sql("SELECT missing_column FROM (SELECT 1) AS missing");
        *sql.lock().unwrap() = units.clone();
        let error = transaction
            .execute_raw(statement)
            .await
            .expect_err("Missing column must fail");
        check_error(&error, &units, 1054)?;
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        transaction.rollback().await?;
        assert_eq!(prepared_count(&database).await?, prepared);
        Ok(())
    }
    .await;
    database.close().await?;
    result
}
