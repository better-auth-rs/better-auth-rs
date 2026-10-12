use crate::connection::Connection;
use crate::error::{BoxDynError, Error};
use crate::executor::Executor;
use crate::{MySql, MySqlConnection, MySqlDatabaseError, MySqlPoolOptions};
use futures_util::TryStreamExt;
use sqlx_core::query::query;
use sqlx_core::query_scalar::query_scalar;

fn check(error: &Error, sql: &str, number: u16) {
    let source = error.as_database_error().unwrap();
    let native = source.downcast_ref::<MySqlDatabaseError>();
    assert_eq!(native.sql(), Some(sql));
    assert_eq!(native.number(), number);
    assert_eq!(source.message(), native.message());
}

#[test]
#[ignore = "requires DATABASE_URL and the sqlx/runtime-tokio feature in MySQL CI"]
fn live_text_and_prepared_server_errors_keep_the_dispatched_sql() -> Result<(), BoxDynError> {
    sqlx_core::rt::test_block_on(async {
        let mut connection = MySqlConnection::connect(&std::env::var("DATABASE_URL")?).await?;
        connection
            .execute("CREATE TEMPORARY TABLE ba_transport (id INTEGER PRIMARY KEY)")
            .await?;
        connection
            .execute("INSERT INTO ba_transport VALUES (1)")
            .await?;
        let text = "INSERT INTO ba_transport VALUES (1) /* exact text command */";
        let error = connection.execute(text).await.unwrap_err();
        check(&error, text, 1062);
        assert!(error.as_database_error().unwrap().is_unique_violation());
        let template = "INSERT INTO ba_transport VALUES (?) /* exact prepared command */";
        for _ in 0..2 {
            let error = query::<MySql>(template)
                .bind(1_i32)
                .execute(&mut connection)
                .await
                .unwrap_err();
            check(&error, template, 1062);
            assert!(error.as_database_error().unwrap().is_unique_violation());
        }
        let count: i64 = query_scalar("SELECT COUNT(*) FROM ba_transport")
            .fetch_one(&mut connection)
            .await?;
        assert_eq!(count, 1);
        let empty = connection.execute("").await.unwrap_err();
        check(&empty, "", 1065);
        connection.close().await?;
        Ok(())
    })
}

#[test]
#[ignore = "requires DATABASE_URL and the sqlx/runtime-tokio feature in MySQL CI"]
fn live_cancelled_stream_error_is_drained_before_the_next_command() -> Result<(), BoxDynError> {
    sqlx_core::rt::test_block_on(async {
        let mut connection = MySqlConnection::connect(&std::env::var("DATABASE_URL")?).await?;
        connection.execute("SET @ba_transport_next = 0").await?;
        let old = "SELECT 7; SELECT missing_column FROM (SELECT 1) AS ba_transport_missing";
        {
            let mut rows = connection.fetch(old);
            assert!(rows.try_next().await?.is_some());
        }
        let next = "SET @ba_transport_next = 1";
        let error = connection.execute(next).await.unwrap_err();
        check(&error, old, 1054);
        let value: i64 = query_scalar("SELECT @ba_transport_next")
            .fetch_one(&mut connection)
            .await?;
        assert_eq!(
            value, 0,
            "The next command must not run when draining fails"
        );
        connection.execute(next).await?;
        let value: i64 = query_scalar("SELECT @ba_transport_next")
            .fetch_one(&mut connection)
            .await?;
        assert_eq!(value, 1);
        connection.close().await?;
        Ok(())
    })
}

#[test]
#[ignore = "requires DATABASE_URL and the sqlx/runtime-tokio feature in MySQL CI"]
fn live_transaction_stream_failure_keeps_connection_and_rollback_ownership(
) -> Result<(), BoxDynError> {
    sqlx_core::rt::test_block_on(async {
        let pool = MySqlPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL")?)
            .await?;
        let mut connection = pool.acquire().await?;
        let id: u64 = query_scalar("SELECT CONNECTION_ID()")
            .fetch_one(&mut *connection)
            .await?;
        connection
            .execute("CREATE TEMPORARY TABLE ba_transport_transaction (id INTEGER PRIMARY KEY)")
            .await?;
        let mut transaction = connection.begin().await?;
        (&mut *transaction)
            .execute("INSERT INTO ba_transport_transaction VALUES (1)")
            .await?;
        let old = "SELECT id FROM ba_transport_transaction; INSERT INTO ba_transport_transaction VALUES (1)";
        {
            let mut rows = (&mut *transaction).fetch(old);
            assert!(rows.try_next().await?.is_some());
        }
        let error = (&mut *transaction).execute("SELECT 9").await.unwrap_err();
        check(&error, old, 1062);
        let transaction_id: u64 = query_scalar("SELECT CONNECTION_ID()")
            .fetch_one(&mut *transaction)
            .await?;
        assert_eq!(transaction_id, id);
        transaction.rollback().await?;
        let count: i64 = query_scalar("SELECT COUNT(*) FROM ba_transport_transaction")
            .fetch_one(&mut *connection)
            .await?;
        assert_eq!(count, 0);
        drop(connection);
        let id_after: u64 = query_scalar("SELECT CONNECTION_ID()")
            .fetch_one(&pool)
            .await?;
        assert_eq!(id_after, id);
        pool.close().await;
        Ok(())
    })
}
