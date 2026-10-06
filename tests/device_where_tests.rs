#![cfg(feature = "seaorm2")]

#[path = "support/device_where_contract.rs"]
mod contract;
#[path = "support/device_where_model.rs"]
mod fixture;
#[path = "support/device_where_inventory.rs"]
mod inventory;

use better_auth_core::store::EphemeralStore;
use better_auth_seaorm::sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection};
use std::sync::Arc;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn memory_device_where_matches_upstream_rows_callbacks_and_consumption() -> TestResult {
    let captured = contract::load("memory")?;
    contract::run(
        Arc::new(EphemeralStore::new(Arc::new(contract::config()))),
        "memory",
        &inventory::paired(&captured, "memory"),
    )
    .await?;
    Ok(())
}

async fn sql_contract(database: DatabaseConnection, backend: &str) -> TestResult {
    let captured = contract::load(backend)?;
    let store = fixture::setup(contract::config(), database).await?;
    contract::run(
        Arc::new(store),
        backend,
        &inventory::paired(&captured, backend),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn sqlite_device_where_matches_upstream_rows_callbacks_and_consumption() -> TestResult {
    sql_contract(Database::connect("sqlite::memory:").await?, "sqlite").await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create isolated test schemas"]
async fn live_postgres_device_where_matches_upstream_rows_callbacks_and_consumption() -> TestResult
{
    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let schema = format!("ba_device_where_{}", uuid::Uuid::new_v4().simple());
    let _ = database
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await?;
    let worker = database.clone();
    let worker_schema = schema.clone();
    let result = tokio::spawn(async move {
        let _ = worker
            .execute_unprepared(&format!("SET search_path TO {worker_schema}"))
            .await?;
        sql_contract(worker, "postgres").await
    })
    .await;
    let cleanup = database
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await;
    let closed = database.close().await;
    let _ = cleanup?;
    closed?;
    result??;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and permission to create isolated test databases"]
async fn live_mysql_device_where_matches_upstream_rows_callbacks_and_consumption() -> TestResult {
    let mut url = reqwest::Url::parse(&std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?)?;
    let mut options = ConnectOptions::new(url.as_str());
    let _ = options.max_connections(1).sqlx_logging(false);
    let admin = Database::connect(options).await?;
    let database_name = format!("ba_device_where_{}", uuid::Uuid::new_v4().simple());
    let _ = admin
        .execute_unprepared(&format!("CREATE DATABASE `{database_name}`"))
        .await?;
    url.set_path(&database_name);
    let result = async {
        let mut options = ConnectOptions::new(url.as_str());
        let _ = options.max_connections(1).sqlx_logging(false);
        let database = Database::connect(options).await?;
        let worker = database.clone();
        let result = tokio::spawn(async move { sql_contract(worker, "mysql").await }).await;
        let closed = database.close().await;
        result??;
        closed?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    let cleanup = admin
        .execute_unprepared(&format!("DROP DATABASE `{database_name}`"))
        .await;
    let closed = admin.close().await;
    let _ = cleanup?;
    closed?;
    result
}
