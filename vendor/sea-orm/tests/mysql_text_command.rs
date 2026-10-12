use futures_util::TryStreamExt;
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, DbErr, RuntimeErr,
    Statement, StreamTrait, TransactionTrait,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn text(sql: &str) -> Statement {
    Statement::from_mysql_text(sql.encode_utf16().collect())
}

fn native_sql(prefix: &str) -> Vec<u16> {
    let mut units: Vec<u16> = prefix.encode_utf16().collect();
    units.extend(" /* ".encode_utf16());
    units.extend([0xd800, 0xdc00, 0xd800, 0x0041, 0xdc00]);
    units.extend(" */".encode_utf16());
    units
}

fn check_error(error: &DbErr, logical: &[u16], number: u16) -> TestResult {
    let (DbErr::Exec(RuntimeErr::SqlxError(source)) | DbErr::Query(RuntimeErr::SqlxError(source))) =
        error
    else {
        return Err(format!("Expected the original SQLx error: {error}").into());
    };
    let source = source
        .as_database_error()
        .and_then(|error| error.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>())
        .ok_or("Expected native MySQL database error")?;
    assert_eq!(source.sql_utf16(), Some(logical));
    assert_eq!(
        source.sql(),
        Some(String::from_utf16_lossy(logical).as_str())
    );
    assert_eq!(source.number(), number);
    Ok(())
}

async fn database() -> TestResult<DatabaseConnection> {
    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?);
    options
        .max_connections(1)
        .min_connections(1)
        .sqlx_logging(false);
    Ok(Database::connect(options).await?)
}

async fn connection_id(connection: &impl ConnectionTrait) -> TestResult<u64> {
    Ok(connection
        .query_one_raw(text("SELECT CONNECTION_ID() AS id"))
        .await?
        .ok_or("Missing connection ID")?
        .try_get("", "id")?)
}

async fn prepared_count(connection: &impl ConnectionTrait) -> TestResult<u64> {
    let row = connection
        .query_one_raw(text("SHOW SESSION STATUS LIKE 'Com_stmt_prepare'"))
        .await?
        .ok_or("Missing prepared statement counter")?;
    Ok(row.try_get::<String>("", "Value")?.parse()?)
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn live_text_pool_queries_preserve_protocol_and_logical_sql() -> TestResult {
    let database = database().await?;
    let result = async {
        let id = connection_id(&database).await?;
        let prepared = prepared_count(&database).await?;
        let units = native_sql("SELECT missing_column FROM (SELECT 1) AS missing");
        let error = database
            .execute_raw(Statement::from_mysql_text(units.clone()))
            .await
            .expect_err("Missing column must fail");
        check_error(&error, &units, 1054)?;

        let mut value: Vec<u16> = "SELECT '".encode_utf16().collect();
        value.extend([0xd800, 0x0041, 0xdc00]);
        value.extend("' AS value".encode_utf16());
        let rows = database
            .query_all_raw(Statement::from_mysql_text(value))
            .await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].try_get::<String>("", "value")?, "\u{fffd}A\u{fffd}");

        let mut immutable = text("SELECT 7 AS value");
        immutable.sql = "SELECT unsent_value".into();
        immutable.values = Some(sea_query::Values(vec![9.into()]));
        assert_eq!(immutable.to_string(), "SELECT 7 AS value");
        let row = database
            .query_one_raw(immutable)
            .await?
            .ok_or("Missing immutable result")?;
        assert_eq!(row.try_get::<i32>("", "value")?, 7);

        let stream_units =
            native_sql("SELECT 7 AS value; SELECT missing_column FROM (SELECT 1) AS missing");
        let mut rows = database
            .stream_raw(Statement::from_mysql_text(stream_units.clone()))
            .await?;
        assert_eq!(
            rows.try_next()
                .await?
                .ok_or("Missing streamed row")?
                .try_get::<i32>("", "value")?,
            7
        );
        let error = rows
            .try_next()
            .await
            .expect_err("The second result must fail");
        check_error(&error, &stream_units, 1054)?;
        drop(rows);
        assert_eq!(connection_id(&database).await?, id);
        assert_eq!(prepared_count(&database).await?, prepared);

        let empty = database
            .execute_raw(Statement::from_mysql_text(Vec::new()))
            .await
            .expect_err("An empty query must fail");
        check_error(&empty, &[], 1065)?;
        let _ = database
            .query_one_raw(Statement::from_string(
                DbBackend::MySql,
                "SELECT 9 AS value",
            ))
            .await?;
        assert_eq!(prepared_count(&database).await?, prepared + 1);
        Ok(())
    }
    .await;
    database.close().await?;
    result
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn live_text_transaction_keeps_atomic_updates_and_rollback() -> TestResult {
    let database = database().await?;
    let result = async {
        database.execute_raw(text("CREATE TEMPORARY TABLE ba_text_quota (id INTEGER PRIMARY KEY, quota INTEGER) ENGINE=InnoDB")).await?;
        database.execute_raw(text("INSERT INTO ba_text_quota VALUES (1, 1)")).await?;
        let id = connection_id(&database).await?;
        let transaction = database.begin().await?;
        assert_eq!(connection_id(&transaction).await?, id);
        let statement = text("UPDATE ba_text_quota SET quota = quota - 1 WHERE id = 1 AND quota > 0");
        assert_eq!(transaction.execute_raw(statement.clone()).await?.rows_affected(), 1);
        assert_eq!(transaction.execute_raw(statement).await?.rows_affected(), 0);
        let rows = transaction.query_all_raw(text("SELECT quota FROM ba_text_quota")).await?;
        assert_eq!(rows[0].try_get::<i32>("", "quota")?, 0);
        transaction.rollback().await?;
        let row = database.query_one_raw(text("SELECT quota FROM ba_text_quota")).await?.ok_or("Missing rolled-back row")?;
        assert_eq!(row.try_get::<i32>("", "quota")?, 1);
        assert_eq!(connection_id(&database).await?, id);
        Ok(())
    }.await;
    database.close().await?;
    result
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn live_cancelled_text_transaction_stream_keeps_old_error_and_connection() -> TestResult {
    let database = database().await?;
    let result = async {
        let id = connection_id(&database).await?;
        let transaction = database.begin().await?;
        transaction
            .execute_raw(text("SET @ba_text_next = 0"))
            .await?;
        let units =
            native_sql("SELECT 7 AS value; SELECT missing_column FROM (SELECT 1) AS missing");
        {
            let mut rows = transaction
                .stream_raw(Statement::from_mysql_text(units.clone()))
                .await?;
            assert!(rows.try_next().await?.is_some());
        }
        let error = transaction
            .execute_raw(text("SET @ba_text_next = 1"))
            .await
            .expect_err("The cancelled command must fail during drain");
        check_error(&error, &units, 1054)?;
        let row = transaction
            .query_one_raw(text("SELECT @ba_text_next AS value"))
            .await?
            .ok_or("Missing next-command marker")?;
        assert_eq!(row.try_get::<i64>("", "value")?, 0);
        assert_eq!(connection_id(&transaction).await?, id);
        transaction
            .execute_raw(text("SET @ba_text_next = 1"))
            .await?;
        transaction.rollback().await?;
        assert_eq!(connection_id(&database).await?, id);
        Ok(())
    }
    .await;
    database.close().await?;
    result
}

#[path = "mysql_text_command/deferred.rs"]
mod deferred;
