#[path = "../../../../tests/support/api_key_field_contract.rs"]
mod contract;

use super::server_catalog_support::{TestResult, in_mysql_catalog, in_postgres_catalog};
use better_auth::seaorm::{Database, SeaOrmStore};
use std::sync::Arc;

mod mapped {
    include!(env!("BETTER_AUTH_API_KEY_FIELDS_SQLITE_SCHEMA"));
}
mod postgres {
    include!(env!("BETTER_AUTH_API_KEY_FIELDS_POSTGRES_SCHEMA"));
}
mod mysql {
    include!(env!("BETTER_AUTH_API_KEY_FIELDS_MYSQL_SCHEMA"));
}

#[tokio::test]
async fn generated_api_key_columns_preserve_complete_field_policies_usage_and_errors()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for scenario in contract::Scenario::all() {
        let database = Database::connect("sqlite::memory:").await?;
        mapped::create_auth_tables(&database).await?;
        let store = SeaOrmStore::<mapped::AppAuthSchema>::new(contract::config(), database.clone())
            .with_plugin_schema::<mapped::AppPluginSchema>();
        contract::contract(Arc::new(store), "sqlite", scenario).await?;
        database.close().await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn live_postgres_api_key_usage_dates_match_complete_pinned_operations() -> TestResult {
    in_postgres_catalog(async |database| {
        postgres::create_auth_tables(&database).await?;
        let store = SeaOrmStore::<postgres::AppAuthSchema>::new(contract::config(), database)
            .with_plugin_schema::<postgres::AppPluginSchema>();
        contract::usage_dates::contract(Arc::new(store), "postgres").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn live_mysql_api_key_usage_dates_match_complete_pinned_operations() -> TestResult {
    in_mysql_catalog(async |database| {
        mysql::create_auth_tables(&database).await?;
        let store = SeaOrmStore::<mysql::AppAuthSchema>::new(contract::config(), database)
            .with_plugin_schema::<mysql::AppPluginSchema>();
        contract::usage_dates::contract(Arc::new(store), "mysql").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn generated_api_key_usage_dates_match_complete_pinned_operations()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database = Database::connect("sqlite::memory:").await?;
    mapped::create_auth_tables(&database).await?;
    let store = SeaOrmStore::<mapped::AppAuthSchema>::new(contract::config(), database.clone())
        .with_plugin_schema::<mapped::AppPluginSchema>();
    contract::usage_dates::contract(Arc::new(store), "sqlite").await?;
    database.close().await?;
    Ok(())
}
