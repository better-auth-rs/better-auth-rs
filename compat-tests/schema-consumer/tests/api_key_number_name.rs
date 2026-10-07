#[path = "../../../tests/support/api_key_number_name_contract.rs"]
mod contract;
#[path = "../src/tests/sqlite_catalog.rs"]
mod sqlite_catalog;

use better_auth::{
    AuthSchema,
    seaorm::{
        Database, DatabaseConnection, SeaOrmAccountModel, SeaOrmPluginSchema, SeaOrmSessionModel,
        SeaOrmStore, SeaOrmUserModel, SeaOrmVerificationModel,
        sea_orm::{ConnectionTrait, DbBackend, Statement},
    },
};
use contract::{Scenario, TestResult};
use serde_json::{Value, json};
use std::sync::Arc;

mod required {
    include!(env!("BETTER_AUTH_API_KEY_NUMBER_NAME_REQUIRED_SCHEMA"));
}
mod optional {
    include!(env!("BETTER_AUTH_API_KEY_NUMBER_NAME_OPTIONAL_SCHEMA"));
}

async fn stored(database: &DatabaseConnection) -> TestResult<Value> {
    let columns = database
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT name FROM pragma_table_info('apikey') ORDER BY cid",
        ))
        .await?;
    let fields = columns
        .iter()
        .map(|row| {
            let name = row.try_get::<String>("", "name")?;
            Ok(format!(
                "'{}', \"{}\"",
                name.replace('\'', "''"),
                name.replace('"', "\"\"")
            ))
        })
        .collect::<TestResult<Vec<_>>>()?
        .join(", ");
    let rows = database
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            format!("SELECT json_object({fields}) AS data FROM apikey ORDER BY id"),
        ))
        .await?;
    Ok(Value::Array(
        rows.iter()
            .map(|row| Ok(serde_json::from_str(&row.try_get::<String>("", "data")?)?))
            .collect::<TestResult<_>>()?,
    ))
}

async fn run<S: AuthSchema, P: SeaOrmPluginSchema>(
    database: DatabaseConnection,
    required: bool,
    scenario: Scenario,
) -> TestResult
where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    let case = contract::fixture("sqlite", required, scenario)?;
    let (catalog, ddl) = sqlite_catalog::observe(
        &database,
        "apikey",
        "The generated API Key table must exist",
    )
    .await?;
    assert_eq!(
        catalog, case.catalog["catalog"],
        "Complete SQLite columns, indexes, and foreign keys"
    );
    let declarations = |ddl: &Value| -> TestResult<Value> {
        Ok(Value::Array(ddl.as_array().ok_or("Missing SQLite DDL")?.iter().map(|row| {
            json!({"type":row["type"], "name":row["name"], "tbl_name":row["tbl_name"], "hasSql":!row["sql"].is_null()})
        }).collect()))
    };
    assert_eq!(declarations(&ddl)?, declarations(&case.catalog["ddl"])?);
    let store =
        SeaOrmStore::<S>::new(contract::config(), database.clone()).with_plugin_schema::<P>();
    contract::contract(Arc::new(store), case, scenario, move || {
        let database = database.clone();
        async move { stored(&database).await }
    })
    .await
}

async fn run_scenario(scenario: Scenario) -> TestResult {
    for required in [true, false] {
        let database = Database::connect("sqlite::memory:").await?;
        let result = if required {
            required::create_auth_tables(&database).await?;
            run::<required::AppAuthSchema, required::AppPluginSchema>(
                database.clone(),
                true,
                scenario,
            )
            .await
        } else {
            optional::create_auth_tables(&database).await?;
            run::<optional::AppAuthSchema, optional::AppPluginSchema>(
                database.clone(),
                false,
                scenario,
            )
            .await
        };
        database.close().await?;
        result?;
    }
    Ok(())
}

#[tokio::test]
async fn generated_sqlite_api_key_number_name_matches_pinned_http_and_storage() -> TestResult {
    run_scenario(Scenario::Defaults).await
}

#[tokio::test]
async fn generated_sqlite_api_key_number_name_order_matches_pinned_http_and_storage() -> TestResult
{
    run_scenario(Scenario::Ordering).await
}
