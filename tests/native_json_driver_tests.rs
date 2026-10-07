#![cfg(feature = "seaorm2")]
#![expect(
    clippy::panic_in_result_fn,
    clippy::expect_used,
    reason = "The paired contract must fail on fixture drift, callback loss, or database behavior differences."
)]

#[path = "support/native_json_driver_model.rs"]
mod fixture;
#[path = "support/device_where_values.rs"]
mod values;

use better_auth::{AuthConfig, BetterAuth, plugins::DeviceAuthorizationPlugin};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRecordFields, AuthRequest,
    AuthResponse, AuthResult, AuthRoute, AuthSchema, CreateDeviceCode, DeviceCode, FieldMap,
    FieldValue, UpdateDeviceCode,
    error::DatabaseError,
    id::{IdGeneration, IdGenerator},
    store::schema::EntityRole,
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use better_auth_seaorm::sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
type Trace = Arc<Mutex<Vec<Value>>>;
const CASES: [&str; 10] = [
    "null",
    "string-ordinary",
    "string-json-scalar",
    "string-json-null",
    "date-valid",
    "date-invalid",
    "array-empty",
    "array-scalars",
    "array-nested",
    "array-runtime-values",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    version: String,
    backend: String,
    columns: Vec<Value>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Case {
    name: String,
    input: Value,
    created: Observation,
    created_read: Observation,
    seeded: Observation,
    updated: Observation,
    updated_read: Observation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    returned: bool,
    result: Option<Value>,
    error: Option<Error>,
    events: Vec<Value>,
    stored: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Error {
    name: String,
    message: String,
    properties: Value,
}

struct Fields(Trace);

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "native-json-driver-fields"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        let callback = |phase: &'static str| {
            let trace = self.0.clone();
            UserFieldTransform::new(move |value| {
                trace
                    .lock()
                    .expect("native JSON callback trace")
                    .push(json!({
                        "phase": phase, "field": "payload", "value": values::observe(&value)?,
                    }));
                Ok(value)
            })
        };
        context.register_model_fields(
            EntityRole::DeviceCode,
            UserConfig {
                additional_fields: Some(
                    [(
                        "payload".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Json,
                            field_name: Some("stored_payload".into()),
                            required: Some(false),
                            transform: Some(FieldTransforms {
                                input: Some(callback("input")),
                                output: Some(callback("output")),
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        )
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn config(id: Arc<Mutex<String>>) -> AuthConfig {
    let mut config = AuthConfig::new("ordinary-native-json-driver-secret-at-least-32-characters")
        .base_url("http://native-json-driver.test");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |_| {
            Ok(Some(id.lock().expect("native JSON fixture ID").clone()))
        })));
    config
}

fn input(id: &str, payload: FieldValue) -> AuthResult<CreateDeviceCode> {
    Ok(CreateDeviceCode {
        device_code: id.into(),
        user_code: "ABCD2345".into(),
        user_id: None,
        expires_at: "2032-01-02T03:04:05.000Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .map_err(|error| AuthError::internal(error.to_string()))?
            .into(),
        status: "pending".into(),
        last_polled_at: None,
        polling_interval: Some(5.0),
        client_id: Some("ordinary-client".into()),
        scope: None.into(),
        additional_fields: FieldMap::from([("payload".into(), payload)]),
    })
}

fn canonical(value: Value) -> AuthResult<Value> {
    Ok(serde_json::from_str(
        &better_auth_core::utils::json::stringify(&value)?,
    )?)
}

async fn check(
    database: &DatabaseConnection,
    trace: &Trace,
    result: AuthResult<Option<DeviceCode>>,
    expected: &Observation,
    label: &str,
    backend: &str,
) -> TestResult {
    let events = std::mem::take(&mut *trace.lock().expect("native JSON callback trace"));
    assert_eq!(
        canonical(json!(events))?,
        json!(expected.events),
        "{label} callbacks"
    );
    assert_eq!(
        fixture::stored(database).await?,
        expected.stored,
        "{label} raw storage"
    );
    assert_eq!(
        result.is_ok(),
        expected.returned,
        "{label} return/error: {result:?}"
    );
    match result {
        Ok(row) => {
            assert!(
                expected.error.is_none(),
                "{label} success must have no error"
            );
            let result = row
                .map(|row| values::observe(&FieldValue::from(row.field_values()?)))
                .transpose()?
                .unwrap_or(Value::Null);
            assert_eq!(
                canonical(result)?,
                expected.result.clone().unwrap_or(Value::Null),
                "{label} result"
            );
        }
        Err(AuthError::Database(DatabaseError::Query(message))) => {
            let expected = expected.error.as_ref().expect("captured database error");
            assert!(
                expected.properties.is_object(),
                "complete driver metadata stays in the fixture"
            );
            // Bun compares all driver metadata. Rust exposes the database message with SQLx wrappers.
            let diagnostic = match backend {
                "postgres" => {
                    assert_eq!(expected.name, "error");
                    format!(
                        "Query Error: error returned from database: {}",
                        expected.message
                    )
                }
                "mysql" => {
                    assert_eq!(expected.name, "Error");
                    assert_eq!(expected.properties["code"], "ER_INVALID_JSON_TEXT");
                    assert_eq!(expected.properties["errno"], 3140);
                    assert_eq!(expected.properties["sqlState"], "22032");
                    format!(
                        "Query Error: error returned from database: 3140 (22032): {}",
                        expected.message
                    )
                }
                _ => return Err(format!("{label} unexpected SQL error: {message}").into()),
            };
            assert_eq!(message, diagnostic, "{label} diagnostic");
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

async fn contract(database: DatabaseConnection, backend: &str) -> TestResult {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "tests/fixtures/native-json-driver-{backend}-1.7.6.json"
    ));
    let captured: Capture = serde_json::from_slice(&std::fs::read(path)?)?;
    assert_eq!(captured.version, "1.7.6");
    assert_eq!(captured.backend, backend);
    assert_eq!(captured.columns.len(), 11);
    assert_eq!(
        captured
            .cases
            .iter()
            .map(|case| case.name.as_str())
            .collect::<Vec<_>>(),
        CASES
    );
    let trace = Trace::default();
    let id = Arc::new(Mutex::new(String::new()));
    let config = config(id.clone());
    let raw = fixture::setup(config.clone(), database.clone()).await?;
    let auth = BetterAuth::new(config)
        .store_arc(raw)
        .plugin(DeviceAuthorizationPlugin::new())
        .plugin(Fields(trace.clone()))
        .build()
        .await?;
    for case in captured.cases {
        for (phase, expected) in [("create", &case.created), ("update", &case.seeded)] {
            fixture::reset(&database).await?;
            assert_eq!(fixture::stored(&database).await?, json!([]));
            assert!(trace.lock().expect("empty callback trace").is_empty());
            let current_id = format!("{phase}-{}", case.name);
            *id.lock().expect("native JSON fixture ID") = current_id.clone();
            let payload = if phase == "create" {
                values::revive(&case.input)?
            } else {
                FieldValue::from(FieldMap::from([(
                    "seed".into(),
                    FieldValue::from("ordinary"),
                )]))
            };
            let result = auth
                .store()
                .create_device_code(input(&current_id, payload)?)
                .await
                .map(Some);
            check(
                &database,
                &trace,
                result,
                expected,
                &format!("{backend}/{} {phase}", case.name),
                backend,
            )
            .await?;
            if phase == "update" {
                let result = auth
                    .store()
                    .update_device_code(
                        &current_id.clone().into(),
                        UpdateDeviceCode {
                            additional_fields: FieldMap::from([(
                                "payload".into(),
                                values::revive(&case.input)?,
                            )]),
                            ..Default::default()
                        },
                    )
                    .await
                    .map(Some);
                check(
                    &database,
                    &trace,
                    result,
                    &case.updated,
                    &format!("{backend}/{} updated", case.name),
                    backend,
                )
                .await?;
            }
            let result = auth
                .store()
                .get_device_code_by_device_code(&current_id)
                .await;
            let expected = if phase == "create" {
                &case.created_read
            } else {
                &case.updated_read
            };
            check(
                &database,
                &trace,
                result,
                expected,
                &format!("{backend}/{} {phase} read", case.name),
                backend,
            )
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_native_json_matches_upstream_driver_boundaries() -> TestResult {
    contract(Database::connect("sqlite::memory:").await?, "sqlite").await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create isolated test schemas"]
async fn live_postgres_native_json_matches_upstream_driver_boundaries() -> TestResult {
    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let schema = format!("ba_native_json_{}", uuid::Uuid::new_v4().simple());
    let _ = database
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await?;
    let worker = database.clone();
    let worker_schema = schema.clone();
    let result = tokio::spawn(async move {
        let _ = worker
            .execute_unprepared(&format!("SET search_path TO {worker_schema}"))
            .await?;
        contract(worker, "postgres").await
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
async fn live_mysql_native_json_matches_upstream_driver_boundaries() -> TestResult {
    let mut url = reqwest::Url::parse(&std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?)?;
    let mut options = ConnectOptions::new(url.as_str());
    let _ = options.max_connections(1).sqlx_logging(false);
    let admin = Database::connect(options).await?;
    let database_name = format!("ba_native_json_{}", uuid::Uuid::new_v4().simple());
    let _ = admin
        .execute_unprepared(&format!("CREATE DATABASE `{database_name}`"))
        .await?;
    url.set_path(&database_name);
    let result = async {
        let mut options = ConnectOptions::new(url.as_str());
        let _ = options.max_connections(1).sqlx_logging(false);
        let database = Database::connect(options).await?;
        let worker = database.clone();
        let result = tokio::spawn(async move { contract(worker, "mysql").await }).await;
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
