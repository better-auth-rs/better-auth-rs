use super::*;
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend};
use std::{error::Error, sync::Arc};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn check_source<'a>(error: &'a AuthError, original: &DbErr) -> TestResult<&'a DatabaseError> {
    let AuthError::Database(database) = error else {
        return Err(format!("Expected a typed database error: {error}").into());
    };
    let source = database
        .cause()
        .source()
        .and_then(|source| source.downcast_ref::<DbErr>());
    assert_eq!(source, Some(original));
    if let (
        Some(
            DbErr::Exec(RuntimeErr::SqlxError(actual))
            | DbErr::Query(RuntimeErr::SqlxError(actual)),
        ),
        DbErr::Exec(RuntimeErr::SqlxError(expected))
        | DbErr::Query(RuntimeErr::SqlxError(expected)),
    ) = (source, original)
    {
        assert!(
            Arc::ptr_eq(actual, expected),
            "The SQLx source must not be reconstructed"
        );
    }
    Ok(database)
}

#[test]
fn custom_database_error_retains_source_and_original_diagnostic() -> TestResult {
    let source = DbErr::Custom("custom query failure".into());
    let error = map_db_err(source.clone());
    assert!(matches!(
        check_source(&error, &source)?,
        DatabaseError::Query(_)
    ));
    let diagnostic = "Database error: Query error: custom query failure";
    assert_eq!(error.to_string(), diagnostic);
    assert_eq!(error.message_value()?, diagnostic.into());
    Ok(())
}

async fn uniqueness(database: &DatabaseConnection) -> TestResult {
    let _ = database
        .execute_unprepared(
            "CREATE TEMPORARY TABLE ba_error_values (id INTEGER PRIMARY KEY, value INTEGER)",
        )
        .await?;
    let _ = database
        .execute_unprepared("INSERT INTO ba_error_values VALUES (1, 7)")
        .await?;
    let source = database
        .execute_unprepared("INSERT INTO ba_error_values VALUES (1, 8)")
        .await
        .err()
        .ok_or("Duplicate primary key must fail")?;
    let Some(SqlErr::UniqueConstraintViolation(message)) = source.sql_err() else {
        return Err("Duplicate primary key must retain its driver classification".into());
    };
    let error = map_db_err(source.clone());
    assert!(check_source(&error, &source)?.is_unique_constraint());
    assert_eq!(
        error.to_string(),
        format!("Database error: Unique constraint violation: {message}")
    );
    let native = error.raw_value().cloned().ok_or("Missing native error")?;
    if database.get_database_backend() != DbBackend::Sqlite {
        assert_eq!(native.model_property("message")?, message.into());
    }
    let marker: FieldValue = FieldMap::new().into();
    native.set_model_property("callbackMarker", marker.clone())?;
    let thrown = error.into_thrown_value()?;
    assert!(thrown.strict_equals(&native));
    assert!(
        thrown
            .model_property("callbackMarker")?
            .strict_equals(&marker)
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_database_error_preserves_uniqueness_and_source() -> TestResult {
    let database = Database::connect("sqlite::memory:").await?;
    let result = uniqueness(&database).await;
    database.close().await?;
    result
}

fn check_postgres_response(value: &FieldValue, source: &DbErr) -> TestResult {
    let (DbErr::Exec(RuntimeErr::SqlxError(source)) | DbErr::Query(RuntimeErr::SqlxError(source))) =
        source
    else {
        return Err("Expected the original SQLx execution error".into());
    };
    let source = source
        .as_database_error()
        .and_then(|source| source.try_downcast_ref::<sqlx::postgres::PgDatabaseError>())
        .ok_or("Expected the original PostgreSQL ErrorResponse")?;
    assert_eq!(
        value.model_property("length")?,
        source.response_length().into()
    );
    for (name, code) in [
        ("severity", b'S'),
        ("position", b'P'),
        ("internalPosition", b'p'),
        ("internalQuery", b'q'),
        ("line", b'L'),
    ] {
        assert_eq!(
            value.model_property(name)?,
            source.field(code).map(FieldValue::from).unwrap_or_default(),
            "{name} must retain the original ErrorResponse field"
        );
    }
    Ok(())
}

async fn postgres_metadata(database: &DatabaseConnection) -> TestResult {
    let source = database
        .execute_unprepared("SELECT CAST('accepted' AS INTEGER)")
        .await
        .err()
        .ok_or("Invalid integer cast must fail")?;
    let error = map_db_err(source.clone());
    assert!(matches!(
        check_source(&error, &source)?,
        DatabaseError::Query(_)
    ));
    assert_eq!(
        error.message_value()?,
        "invalid input syntax for type integer: \"accepted\"".into()
    );
    let value = error.into_thrown_value()?;
    check_postgres_response(&value, &source)?;
    assert_eq!(value.model_property("name")?, "error".into());
    assert_eq!(value.model_property("severity")?, "ERROR".into());
    assert_eq!(value.model_property("code")?, "22P02".into());
    assert!(value.model_property("position")?.is_string());
    assert!(value.model_property("internalPosition")?.is_undefined());
    assert!(value.model_property("internalQuery")?.is_undefined());
    assert!(value.enumerable_fields()?.contains_key("length"));
    assert!(!value.enumerable_fields()?.contains_key("message"));

    let source = database
        .execute_unprepared(
            "DO $$ BEGIN RAISE EXCEPTION 'carrier message' USING
             ERRCODE = 'P0001', DETAIL = 'carrier detail', HINT = 'carrier hint',
             SCHEMA = 'carrier_schema', TABLE = 'carrier_table', COLUMN = 'carrier_column',
             DATATYPE = 'carrier_type', CONSTRAINT = 'carrier_constraint'; END $$",
        )
        .await
        .err()
        .ok_or("The explicit PostgreSQL exception must fail")?;
    let error = map_db_err(source.clone());
    let _ = check_source(&error, &source)?;
    let value = error.into_thrown_value()?;
    check_postgres_response(&value, &source)?;
    for (name, expected) in [
        ("message", "carrier message"),
        ("code", "P0001"),
        ("detail", "carrier detail"),
        ("hint", "carrier hint"),
        ("schema", "carrier_schema"),
        ("table", "carrier_table"),
        ("column", "carrier_column"),
        ("dataType", "carrier_type"),
        ("constraint", "carrier_constraint"),
    ] {
        assert_eq!(value.model_property(name)?, expected.into(), "{name}");
    }
    for name in ["where", "file", "line", "routine"] {
        assert!(value.model_property(name)?.is_string(), "{name}");
    }
    assert!(value.model_property("position")?.is_undefined());

    let source = database
        .execute_unprepared("DO $$ BEGIN EXECUTE 'SELECT CAST(''accepted'' AS INTEGER)'; END $$")
        .await
        .err()
        .ok_or("The internal PostgreSQL query must fail")?;
    let error = map_db_err(source.clone());
    let _ = check_source(&error, &source)?;
    let value = error.into_thrown_value()?;
    check_postgres_response(&value, &source)?;
    assert!(value.model_property("position")?.is_undefined());
    assert!(value.model_property("internalPosition")?.is_string());
    assert_eq!(
        value.model_property("internalQuery")?,
        "SELECT CAST('accepted' AS INTEGER)".into()
    );
    Ok(())
}

async fn mysql_metadata(database: &DatabaseConnection) -> TestResult {
    let _ = database
        .execute_unprepared("SET SESSION sql_mode = 'STRICT_TRANS_TABLES'")
        .await?;
    let source = database
        .execute_unprepared("INSERT INTO ba_error_values VALUES (2, 'accepted')")
        .await
        .err()
        .ok_or("Invalid integer insert must fail")?;
    let error = map_db_err(source.clone());
    assert!(matches!(
        check_source(&error, &source)?,
        DatabaseError::Query(_)
    ));
    let value = error.into_thrown_value()?;
    assert_eq!(value.model_property("name")?, "Error".into());
    assert_eq!(value.model_property("errno")?, 1366.0.into());
    assert_eq!(value.model_property("sqlState")?, "HY000".into());
    assert_eq!(
        value.model_property("message")?,
        value.model_property("sqlMessage")?
    );
    assert_eq!(
        value.model_property("code")?,
        "ER_TRUNCATED_WRONG_VALUE_FOR_FIELD".into()
    );
    assert_eq!(
        value.model_property("sql")?,
        "INSERT INTO ba_error_values VALUES (2, 'accepted')".into()
    );
    assert_eq!(
        value
            .enumerable_fields()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["code", "errno", "sqlState", "sqlMessage", "sql"],
    );
    let sql = "SIGNAL SQLSTATE '45000' SET MYSQL_ERRNO = 60000, MESSAGE_TEXT = 'unknown code'";
    let source = database
        .execute_unprepared(sql)
        .await
        .err()
        .ok_or("SIGNAL must fail")?;
    let error = map_db_err(source.clone());
    let _ = check_source(&error, &source)?;
    let unknown = error.into_thrown_value()?;
    assert!(unknown.has_property("code")?);
    assert!(unknown.model_property("code")?.is_undefined());
    assert_eq!(unknown.model_property("sql")?, sql.into());
    let source = database
        .execute_unprepared("")
        .await
        .err()
        .ok_or("An empty query must fail")?;
    let error = map_db_err(source.clone());
    let _ = check_source(&error, &source)?;
    let empty = error.into_thrown_value()?;
    assert_eq!(empty.model_property("code")?, "ER_EMPTY_QUERY".into());
    assert_eq!(empty.model_property("errno")?, 1065.0.into());
    assert!(empty.has_property("sql")?);
    assert!(empty.model_property("sql")?.is_undefined());
    assert!(!value.enumerable_fields()?.contains_key("message"));
    Ok(())
}

async fn live_database(variable: &str) -> TestResult {
    let mut options = ConnectOptions::new(std::env::var(variable)?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let worker = database.clone();
    let result = tokio::spawn(async move {
        uniqueness(&worker).await?;
        match worker.get_database_backend() {
            DbBackend::Postgres => postgres_metadata(&worker).await,
            DbBackend::MySql => mysql_metadata(&worker).await,
            DbBackend::Sqlite => Err("Expected a server database".into()),
            backend => Err(format!(
                "Unsupported database backend for metadata acceptance: {backend:?}"
            )
            .into()),
        }
    })
    .await;
    database.close().await?;
    result?
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn live_postgres_database_error_metadata() -> TestResult {
    live_database("BETTER_AUTH_TEST_POSTGRES_URL").await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn live_mysql_database_error_metadata() -> TestResult {
    live_database("BETTER_AUTH_TEST_MYSQL_URL").await
}

#[cfg(test)]
mod mysql_text;
