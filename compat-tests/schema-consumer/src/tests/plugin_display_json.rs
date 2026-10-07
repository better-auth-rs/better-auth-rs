#[path = "../../../../tests/support/plugin_display_json_contract.rs"]
mod contract;

use super::server_catalog_support::{self as server_catalog, TestResult};
use better_auth::{
    AuthSchema, FieldValue,
    seaorm::{
        Database, DatabaseConnection, SeaOrmAccountModel, SeaOrmPluginModel, SeaOrmPluginSchema,
        SeaOrmSessionModel, SeaOrmStore, SeaOrmUserModel, SeaOrmVerificationModel,
        sea_orm::{
            ConnectionTrait, DbBackend, EntityName, EntityTrait, Iden, Iterable, ModelTrait,
            Statement,
        },
    },
};
use contract::Target;
use serde_json::{Map, Value, json};
use std::sync::Arc;

mod sqlite_api_key_name {
    include!(env!("BETTER_AUTH_DISPLAY_JSON_SQLITE_API_KEY_NAME_SCHEMA"));
}
mod sqlite_passkey_name {
    include!(env!("BETTER_AUTH_DISPLAY_JSON_SQLITE_PASSKEY_NAME_SCHEMA"));
}
mod sqlite_passkey_aaguid {
    include!(env!(
        "BETTER_AUTH_DISPLAY_JSON_SQLITE_PASSKEY_AAGUID_SCHEMA"
    ));
}
mod postgres_api_key_name {
    include!(env!(
        "BETTER_AUTH_DISPLAY_JSON_POSTGRES_API_KEY_NAME_SCHEMA"
    ));
}
mod postgres_passkey_name {
    include!(env!(
        "BETTER_AUTH_DISPLAY_JSON_POSTGRES_PASSKEY_NAME_SCHEMA"
    ));
}
mod postgres_passkey_aaguid {
    include!(env!(
        "BETTER_AUTH_DISPLAY_JSON_POSTGRES_PASSKEY_AAGUID_SCHEMA"
    ));
}
mod mysql_api_key_name {
    include!(env!("BETTER_AUTH_DISPLAY_JSON_MYSQL_API_KEY_NAME_SCHEMA"));
}
mod mysql_passkey_name {
    include!(env!("BETTER_AUTH_DISPLAY_JSON_MYSQL_PASSKEY_NAME_SCHEMA"));
}
mod mysql_passkey_aaguid {
    include!(env!("BETTER_AUTH_DISPLAY_JSON_MYSQL_PASSKEY_AAGUID_SCHEMA"));
}

fn quote(backend: DbBackend, name: &str) -> String {
    if backend == DbBackend::MySql {
        format!("`{}`", name.replace('`', "``"))
    } else {
        format!("\"{}\"", name.replace('"', "\"\""))
    }
}

async fn stored<M: SeaOrmPluginModel>(
    database: &DatabaseConnection,
    target: Target,
) -> TestResult<Value> {
    let backend = database.get_database_backend();
    let table = M::Entity::default().table_name().to_owned();
    assert_eq!(table, target.table());
    let mut observations = Vec::new();
    for model in M::Entity::find().all(database).await? {
        let mut row = Map::new();
        for column in M::Column::iter() {
            let name = column.to_string();
            let mut value = better_auth::seaorm::__private_field_value(model.get(column))?;
            if backend != DbBackend::Postgres
                && let FieldValue::Bool(boolean) = value
            {
                value = f64::from(u8::from(boolean)).into();
            }
            row.insert(
                name,
                value
                    .json()?
                    .ok_or("SQL columns cannot contain Undefined")?,
            );
        }
        let keys = row.keys().cloned().collect::<Vec<_>>();
        let column = quote(backend, "stored_display");
        let cast = if backend == DbBackend::MySql {
            "CHAR"
        } else {
            "TEXT"
        };
        let parameter = if backend == DbBackend::Postgres {
            "$1"
        } else {
            "?"
        };
        let metadata = database.query_one_raw(Statement::from_sql_and_values(backend,
            format!("SELECT {column} IS NULL AS {}, CAST({column} AS {cast}) AS {} FROM {} WHERE {} = {parameter}", quote(backend, "displaySqlNull"), quote(backend, "displayText"), quote(backend, &table), quote(backend, "id")),
            [contract::ID.into()])).await?.ok_or("Missing display physical row")?;
        let sql_null = if backend == DbBackend::Postgres {
            json!(metadata.try_get::<bool>("", "displaySqlNull")?)
        } else {
            json!(metadata.try_get::<i64>("", "displaySqlNull")?)
        };
        observations.push(json!({"row": row, "keys": keys, "displaySqlNull": sql_null, "displayText": metadata.try_get::<Option<String>>("", "displayText")?}));
    }
    Ok(Value::Array(observations))
}

async fn round_trip<S: AuthSchema, P: SeaOrmPluginSchema>(
    database: DatabaseConnection,
    backend: &str,
    target: Target,
) -> TestResult
where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    let expected = contract::fixture(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../tests/fixtures/plugin-display-json-{backend}-1.7.6.json"
        )),
        backend,
        target,
    )?;
    let store =
        SeaOrmStore::<S>::new(contract::config(), database.clone()).with_plugin_schema::<P>();
    contract::contract(Arc::new(store), backend, target, expected, move || {
        let database = database.clone();
        async move {
            if target == Target::ApiKeyName {
                stored::<P::ApiKey>(&database, target).await
            } else {
                stored::<P::Passkey>(&database, target).await
            }
        }
    })
    .await
}

async fn check(database: DatabaseConnection, backend: &str, target: Target) -> TestResult {
    macro_rules! generated {
        ($module:ident) => {{
            $module::create_auth_tables(&database).await?;
            round_trip::<$module::AppAuthSchema, $module::AppPluginSchema>(
                database, backend, target,
            )
            .await
        }};
    }
    match (backend, target) {
        ("sqlite", Target::ApiKeyName) => generated!(sqlite_api_key_name),
        ("sqlite", Target::PasskeyName) => generated!(sqlite_passkey_name),
        ("sqlite", Target::PasskeyAaguid) => generated!(sqlite_passkey_aaguid),
        ("postgres", Target::ApiKeyName) => generated!(postgres_api_key_name),
        ("postgres", Target::PasskeyName) => generated!(postgres_passkey_name),
        ("postgres", Target::PasskeyAaguid) => generated!(postgres_passkey_aaguid),
        ("mysql", Target::ApiKeyName) => generated!(mysql_api_key_name),
        ("mysql", Target::PasskeyName) => generated!(mysql_passkey_name),
        ("mysql", Target::PasskeyAaguid) => generated!(mysql_passkey_aaguid),
        _ => Err("Unknown JSON display consumer backend".into()),
    }
}

#[tokio::test]
async fn generated_sqlite_plugin_display_json() -> TestResult {
    for target in Target::ALL {
        let database = Database::connect("sqlite::memory:").await?;
        let result = check(database.clone(), "sqlite", target).await;
        database.close().await?;
        result?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the upstream fixture"]
async fn live_postgres_plugin_display_json() -> TestResult {
    for target in Target::ALL {
        server_catalog::in_postgres_catalog(move |database| async move {
            check(database, "postgres", target).await
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and the upstream fixture"]
async fn live_mysql_plugin_display_json() -> TestResult {
    for target in Target::ALL {
        server_catalog::in_mysql_catalog(move |database| async move {
            check(database, "mysql", target).await
        })
        .await?;
    }
    Ok(())
}
