use better_auth::seaorm::{
    Database, DatabaseConnection,
    sea_orm::{ConnectOptions, ConnectionTrait, DbBackend, Statement},
};
use serde_json::{Value, json};
use std::future::Future;

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(super) async fn observe<const N: usize>(
    database: &DatabaseConnection,
    backend: DbBackend,
    table_names: [String; N],
) -> TestResult<Value> {
    let parameters = (1..=N)
        .map(|index| match backend {
            DbBackend::Postgres => format!("${index}"),
            _ => "?".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let sql = match backend {
        DbBackend::Postgres => {
            format!(
                r#"SELECT table_name AS "table", CAST(ordinal_position AS text) AS "position",
            column_name AS "name", data_type AS "type", udt_name AS "nativeType",
            CAST(character_maximum_length AS text) AS "maxLength",
            CAST(datetime_precision AS text) AS "datetimePrecision",
            is_nullable AS "nullable", column_default AS "default"
            FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name IN ({parameters})
            ORDER BY table_name, ordinal_position"#
            )
        }
        DbBackend::MySql => {
            format!(
                r"SELECT TABLE_NAME AS `table`, CAST(ORDINAL_POSITION AS CHAR) AS `position`,
            COLUMN_NAME AS `name`, DATA_TYPE AS `type`, COLUMN_TYPE AS `nativeType`,
            CAST(CHARACTER_MAXIMUM_LENGTH AS CHAR) AS `maxLength`,
            CAST(DATETIME_PRECISION AS CHAR) AS `datetimePrecision`,
            IS_NULLABLE AS `nullable`, COLUMN_DEFAULT AS `default`
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN ({parameters})
            ORDER BY TABLE_NAME, ORDINAL_POSITION"
            )
        }
        _ => {
            return Err("The server catalog test requires PostgreSQL or MySQL".into());
        }
    };
    let mut columns = Vec::new();
    for row in database
        .query_all_raw(Statement::from_sql_and_values(
            backend,
            sql,
            table_names.map(Into::into),
        ))
        .await?
    {
        columns.push(json!({
            "table": row.try_get::<String>("", "table")?,
            "position": row.try_get::<String>("", "position")?,
            "name": row.try_get::<String>("", "name")?,
            "type": row.try_get::<String>("", "type")?,
            "nativeType": row.try_get::<String>("", "nativeType")?,
            "maxLength": row.try_get::<Option<String>>("", "maxLength")?,
            "datetimePrecision": row.try_get::<Option<String>>("", "datetimePrecision")?,
            "nullable": row.try_get::<String>("", "nullable")?,
            "default": row.try_get::<Option<String>>("", "default")?,
        }));
    }
    Ok(json!(columns))
}

pub(super) async fn in_postgres_catalog<F, Fut>(check: F) -> TestResult
where
    F: FnOnce(DatabaseConnection) -> Fut + Send + 'static,
    Fut: Future<Output = TestResult> + Send + 'static,
{
    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let schema = format!(
        "ba_catalog_{}",
        better_auth::__private_core::uuid::Uuid::new_v4().simple()
    );
    let _ = database
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await?;
    let result = async {
        let _ = database
            .execute_unprepared(&format!("SET search_path TO {schema}"))
            .await?;
        let worker = database.clone();
        tokio::spawn(async move { check(worker).await }).await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    let cleanup = database
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await;
    let closed = database.close().await;
    let _ = cleanup?;
    closed?;
    result
}

pub(super) async fn in_mysql_catalog<F, Fut>(check: F) -> TestResult
where
    F: FnOnce(DatabaseConnection) -> Fut + Send + 'static,
    Fut: Future<Output = TestResult> + Send + 'static,
{
    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let name = format!(
        "ba_catalog_{}",
        better_auth::__private_core::uuid::Uuid::new_v4().simple()
    );
    let _ = database
        .execute_unprepared(&format!("CREATE DATABASE `{name}`"))
        .await?;
    let result = async {
        let _ = database
            .execute_unprepared(&format!("USE `{name}`"))
            .await?;
        let worker = database.clone();
        tokio::spawn(async move { check(worker).await }).await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    let cleanup = database
        .execute_unprepared(&format!("DROP DATABASE `{name}`"))
        .await;
    let closed = database.close().await;
    let _ = cleanup?;
    closed?;
    result
}
