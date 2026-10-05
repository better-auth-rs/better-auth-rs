use better_auth::seaorm::{
    Database, DatabaseConnection,
    sea_orm::{ConnectOptions, ConnectionTrait, DbBackend, EntityName, Statement},
};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

mod postgres {
    include!(env!("BETTER_AUTH_SERVER_POSTGRES_CATALOG_SCHEMA"));
}

mod mysql {
    include!(env!("BETTER_AUTH_SERVER_MYSQL_CATALOG_SCHEMA"));
}

async fn observe(
    database: &DatabaseConnection,
    backend: DbBackend,
    table_names: [String; 2],
) -> TestResult<Value> {
    let sql = match backend {
        DbBackend::Postgres => {
            r#"SELECT table_name AS "table", CAST(ordinal_position AS text) AS "position",
            column_name AS "name", data_type AS "type", udt_name AS "nativeType",
            CAST(character_maximum_length AS text) AS "maxLength",
            CAST(datetime_precision AS text) AS "datetimePrecision",
            is_nullable AS "nullable", column_default AS "default"
            FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name IN ($1, $2)
            ORDER BY table_name, ordinal_position"#
        }
        DbBackend::MySql => {
            r"SELECT TABLE_NAME AS `table`, CAST(ORDINAL_POSITION AS CHAR) AS `position`,
            COLUMN_NAME AS `name`, DATA_TYPE AS `type`, COLUMN_TYPE AS `nativeType`,
            CAST(CHARACTER_MAXIMUM_LENGTH AS CHAR) AS `maxLength`,
            CAST(DATETIME_PRECISION AS CHAR) AS `datetimePrecision`,
            IS_NULLABLE AS `nullable`, COLUMN_DEFAULT AS `default`
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (?, ?)
            ORDER BY TABLE_NAME, ORDINAL_POSITION"
        }
        DbBackend::Sqlite => {
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

async fn check(database: &DatabaseConnection, backend: DbBackend) -> TestResult {
    let (label, table_names) = match backend {
        DbBackend::Postgres => {
            let _schema = postgres::AppAuthSchema;
            postgres::create_auth_tables(database).await?;
            (
                "postgres",
                [
                    postgres::user::Entity.table_name().to_owned(),
                    postgres::account::Entity.table_name().to_owned(),
                ],
            )
        }
        DbBackend::MySql => {
            let _schema = mysql::AppAuthSchema;
            mysql::create_auth_tables(database).await?;
            (
                "mysql",
                [
                    mysql::user::Entity.table_name().to_owned(),
                    mysql::account::Entity.table_name().to_owned(),
                ],
            )
        }
        DbBackend::Sqlite => {
            return Err("The server catalog test requires PostgreSQL or MySQL".into());
        }
    };
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/user-account-{label}-catalog-1.7.6.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?)?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(fixture.get("database"), Some(&json!(label)));
    let actual = observe(database, backend, table_names).await?;
    assert_eq!(
        &actual,
        fixture
            .get("columns")
            .ok_or("Missing upstream catalog columns")?,
        "{label} catalog"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the CI upstream catalog fixture"]
async fn live_postgres_user_account_catalog_matches_upstream() -> TestResult {
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
        tokio::spawn(async move { check(&worker, DbBackend::Postgres).await }).await??;
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

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and the CI upstream catalog fixture"]
async fn live_mysql_user_account_catalog_matches_upstream() -> TestResult {
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
        tokio::spawn(async move { check(&worker, DbBackend::MySql).await }).await??;
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
