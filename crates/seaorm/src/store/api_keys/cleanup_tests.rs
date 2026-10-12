use super::*;
use better_auth_core::{
    AuthConfig, AuthRecordFields, FieldDate,
    id::{IdGeneration, IdGenerator},
    store::UserStore,
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
        UserFieldType,
    },
};
use sea_orm::{ConnectOptions, Database, DatabaseConnection, DbBackend, Statement};
use serde_json::{Value as JsonValue, json};
use std::sync::{Arc, Mutex};

mod models;
mod observation;
#[path = "../../../../../tests/support/device_where_values.rs"]
mod values;

type Trace = Arc<Mutex<Vec<JsonValue>>>;
type Store<M> = SeaOrmStore<models::CoreSchema, crate::OrganizationModels, crate::PluginModels<M>>;

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Required SQL cleanup observation is absent"))
}

fn fixture(backend: &str, baseline: bool) -> AuthResult<JsonValue> {
    let contract = if baseline {
        "api-key-cleanup-reference-baseline"
    } else {
        "api-key-cleanup-fields-sql"
    };
    let path = format!(
        "{}/../../tests/fixtures/{contract}-{backend}-1.7.6.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let source = std::fs::read_to_string(&path)
        .map_err(|error| AuthError::internal(format!("Cannot read {path}: {error}")))?;
    Ok(serde_json::from_str(&source)?)
}

fn configured<M: crate::SeaOrmPluginModel<Record = ApiKey>>(
    database: DatabaseConnection,
    scenario: &JsonValue,
    events: &Trace,
) -> AuthResult<Store<M>> {
    let mut config =
        AuthConfig::new("ordinary-cleanup-fields-secret-at-least-thirty-two-characters");
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    config.telemetry.enabled = false;
    config.advanced.database.generate_id = Some(if required(scenario["serial"].as_bool())? {
        IdGeneration::Serial
    } else {
        IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(format!("{}-query-id", request.model)))
        }))
    });
    let input_events = events.clone();
    let output_events = events.clone();
    let declaration = UserFieldConfig {
        field_type: match required(scenario["type"].as_str())? {
            "date" => UserFieldType::Date,
            "json" => UserFieldType::Json,
            _ => return Err(AuthError::internal("Unknown SQL cleanup field type")),
        },
        required: Some(false),
        field_name: Some("stored_expiry".into()),
        references: required(scenario["reference"].as_bool())?.then(|| UserFieldReference {
            model: "user".into(),
            field: "id".into(),
            ..Default::default()
        }),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                observation::record(
                    &input_events,
                    json!(["input", "expiresAt", values::observe(&value)?]),
                )?;
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                observation::record(
                    &output_events,
                    json!(["output", "expiresAt", values::observe(&value)?]),
                )?;
                Ok(value)
            })),
        }),
        ..Default::default()
    };
    let mut store = SeaOrmStore::<models::CoreSchema>::new(config, database)
        .with_plugin_schema::<crate::PluginModels<M>>();
    store.model_fields.register_model_fields(
        EntityRole::ApiKey,
        UserConfig {
            additional_fields: Some([("expiresAt".into(), declaration)].into()),
        },
    )?;
    Ok(store)
}

async fn replay<M: crate::SeaOrmPluginModel<Record = ApiKey>>(
    database: DatabaseConnection,
    case: &JsonValue,
    current: &FieldDate,
    backend: &str,
) -> AuthResult<()> {
    let events = Trace::default();
    let store = configured::<M>(database.clone(), &case["scenario"], &events)?;
    if let Some(owners) = case.get("ownerSetup") {
        for expected in required(owners.as_array())? {
            let input = required(expected.get("input"))?;
            let fields = values::revive(required(input.get("data"))?)?.enumerable_fields()?;
            let before = observation::stored(&database).await?;
            let result = store
                .create_user_fields_optional(fields)
                .await
                .and_then(|user| user.map(|user| user.field_values()).transpose())
                .and_then(|fields| {
                    fields
                        .map(|fields| values::observe(&fields.into()))
                        .transpose()
                })
                .map(|result| result.unwrap_or(JsonValue::Null));
            observation::check(
                &database, &events, &before, result, expected, backend, false,
            )
            .await?;
        }
    }
    let setup = required(case["setup"].as_array())?;
    assert_eq!(setup.len(), 3);
    for expected in setup {
        let input = required(expected.get("input"))?;
        let fields = values::revive(required(input.get("data"))?)?.enumerable_fields()?;
        let before = observation::stored(&database).await?;
        let result = store
            .create_api_key_record(fields)
            .await
            .and_then(|fields| {
                fields
                    .map(|fields| values::observe(&fields.into()))
                    .transpose()
            })
            .map(|result| result.unwrap_or(JsonValue::Null));
        observation::check(
            &database, &events, &before, result, expected, backend, false,
        )
        .await?;
    }
    let steps = required(case["steps"].as_array())?;
    assert_eq!(steps.len(), 2);
    for (index, expected) in steps.iter().enumerate() {
        assert_eq!(expected["attempt"], index + 1);
        assert_eq!(expected["method"], "deleteMany");
        assert_eq!(
            expected["input"],
            json!({"model":"apikey","where":[
                {"field":"expiresAt","operator":"lt","value":values::observe(&current.clone().into())?},
                {"field":"expiresAt","operator":"ne","value":null},
            ]})
        );
        let before = observation::stored(&database).await?;
        let result = store
            .delete_expired_api_keys_before(current.clone())
            .await
            .map(|count| json!(count));
        observation::check(&database, &events, &before, result, expected, backend, true).await?;
    }
    Ok(())
}

async fn contract(database: &DatabaseConnection, backend: &str) -> AuthResult<()> {
    let captured = fixture(backend, false)?;
    let baseline = fixture(backend, true)?;
    assert_eq!(required(captured.get("version"))?, "1.7.6");
    assert_eq!(required(captured.get("backend"))?, backend);
    assert_eq!(
        required(baseline.get("version"))?,
        required(captured.get("version"))?
    );
    assert_eq!(
        required(baseline.get("backend"))?,
        required(captured.get("backend"))?
    );
    let baseline_cases = required(required(baseline.get("cases"))?.as_array())?;
    assert_eq!(baseline_cases.len(), 1);
    let baseline_case = required(baseline_cases.first())?;
    let baseline_scenario = required(baseline_case.get("scenario"))?;
    assert_eq!(
        required(baseline_scenario.get("name"))?,
        "mapped-serial-reference-valid"
    );
    let cases = required(required(captured.get("cases"))?.as_array())?;
    assert_eq!(
        cases
            .iter()
            .map(|case| required(required(case.get("scenario"))?.get("name")).cloned())
            .collect::<AuthResult<Vec<_>>>()?,
        [
            json!("mapped-date"),
            json!("mapped-json"),
            json!("mapped-serial-reference")
        ]
    );
    for capture in [&captured, &baseline] {
        let FieldValue::Date(current) = values::revive(&capture["current"])? else {
            return Err(AuthError::internal("SQL cleanup clock must be a Date"));
        };
        for case in required(capture["cases"].as_array())? {
            observation::migrate(database, case, &baseline).await?;
            let scenario = required(case.get("scenario"))?;
            let result = match required(required(scenario.get("name"))?.as_str())? {
                "mapped-date" => {
                    replay::<models::date::Model>(database.clone(), case, &current, backend).await
                }
                "mapped-json" if backend == "sqlite" => {
                    replay::<models::sqlite_json::Model>(database.clone(), case, &current, backend)
                        .await
                }
                "mapped-json" => {
                    replay::<models::native_json::Model>(database.clone(), case, &current, backend)
                        .await
                }
                "mapped-serial-reference" | "mapped-serial-reference-valid" => {
                    replay::<models::serial::Model>(database.clone(), case, &current, backend).await
                }
                _ => return Err(AuthError::internal("Unknown SQL cleanup scenario")),
            };
            let cleanup = observation::drop_tables(database).await;
            result?;
            cleanup?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_api_key_cleanup_matches_complete_upstream_field_contract() -> AuthResult<()> {
    let mut options = ConnectOptions::new("sqlite::memory:");
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await.map_err(map_db_err)?;
    let result = contract(&database, "sqlite").await;
    let closed = database.close().await.map_err(map_db_err);
    result?;
    closed
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create isolated schemas"]
async fn live_postgres_api_key_cleanup_matches_complete_upstream_field_contract() -> AuthResult<()>
{
    live_contract("postgres", "BETTER_AUTH_TEST_POSTGRES_URL").await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and permission to create isolated databases"]
async fn live_mysql_api_key_cleanup_matches_complete_upstream_field_contract() -> AuthResult<()> {
    live_contract("mysql", "BETTER_AUTH_TEST_MYSQL_URL").await
}

async fn live_contract(backend: &str, variable: &str) -> AuthResult<()> {
    let url = std::env::var(variable).map_err(|error| AuthError::internal(error.to_string()))?;
    let mut options = ConnectOptions::new(url);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await.map_err(map_db_err)?;
    let name = format!("ba_cleanup_{}", uuid::Uuid::new_v4().simple());
    let (create, select, drop) = if backend == "postgres" {
        (
            format!("CREATE SCHEMA {name}"),
            format!("SET search_path TO {name}"),
            format!("DROP SCHEMA {name} CASCADE"),
        )
    } else {
        (
            format!("CREATE DATABASE `{name}`"),
            format!("USE `{name}`"),
            format!("DROP DATABASE `{name}`"),
        )
    };
    let _ = database
        .execute_unprepared(&create)
        .await
        .map_err(map_db_err)?;
    let result = async {
        let _ = database
            .execute_unprepared(&select)
            .await
            .map_err(map_db_err)?;
        contract(&database, backend).await
    }
    .await;
    let cleanup = database.execute_unprepared(&drop).await.map_err(map_db_err);
    let closed = database.close().await.map_err(map_db_err);
    result?;
    let _ = cleanup?;
    closed
}
