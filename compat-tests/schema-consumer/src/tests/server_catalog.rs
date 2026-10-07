use super::server_catalog_support::{TestResult, in_mysql_catalog, in_postgres_catalog, observe};
use better_auth::seaorm::{
    DatabaseConnection,
    sea_orm::{DbBackend, EntityName},
};
use serde_json::{Value, json};

pub(super) mod postgres {
    include!(env!("BETTER_AUTH_SERVER_POSTGRES_CATALOG_SCHEMA"));
}

pub(super) mod mysql {
    include!(env!("BETTER_AUTH_SERVER_MYSQL_CATALOG_SCHEMA"));
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
        _ => {
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
    in_postgres_catalog(|database| async move { check(&database, DbBackend::Postgres).await }).await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and the CI upstream catalog fixture"]
async fn live_mysql_user_account_catalog_matches_upstream() -> TestResult {
    in_mysql_catalog(|database| async move { check(&database, DbBackend::MySql).await }).await
}
