use better_auth::{AuthConfig, BetterAuth, plugins::DeviceAuthorizationPlugin};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRecordFields, AuthRequest,
    AuthResponse, AuthResult, AuthRoute, AuthSchema, AuthStore, CreateDeviceCode, CreateUser,
    DeviceCode, DeviceCodeOwnership, DeviceCodeWhere, FieldMap, FieldValue, WhereMode,
    WhereOperator,
    error::DatabaseError,
    id::IdGeneration,
    store::{DeviceCodeStore, schema::EntityRole, transaction},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
        UserFieldType,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[path = "device_where_values.rs"]
mod values;
use values::{observe, revive};
#[path = "device_where_references.rs"]
mod references;
pub(crate) use references::load_references;
#[path = "device_where_reference_sets.rs"]
mod reference_sets;
pub(crate) use reference_sets::load_reference_sets;
#[path = "device_where_reference_values.rs"]
mod reference_values;
pub(crate) use reference_values::load_reference_values;
#[path = "device_where_reference_defaults.rs"]
mod reference_defaults;
pub(crate) use reference_defaults::load_reference_defaults;

type Trace = Arc<Mutex<Vec<Value>>>;

pub(crate) struct RunConfig<'a> {
    pub(crate) auth: AuthConfig,
    pub(crate) owner_ref_type: UserFieldType,
    pub(crate) owner_id: Option<&'a str>,
}

const FIELDS: [(&str, UserFieldType); 7] = [
    ("label", UserFieldType::String),
    ("quantity", UserFieldType::Number),
    ("flag", UserFieldType::Boolean),
    ("moment", UserFieldType::Date),
    ("labels", UserFieldType::StringArray),
    ("payload", UserFieldType::Json),
    ("ownerRef", UserFieldType::String),
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fixture {
    pub(crate) version: String,
    pub(crate) backend: String,
    pub(crate) groups: Vec<Group>,
    #[serde(rename = "idGeneration")]
    id_generation: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Group {
    pub(crate) serial: bool,
    pub(crate) cases: Vec<Case>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Case {
    pub(crate) name: String,
    transaction: bool,
    #[serde(rename = "where")]
    condition: Vec<Value>,
    seeded: Value,
    seed_events: Vec<Value>,
    before: Vec<Value>,
    events: Vec<Value>,
    result: Value,
    error: Option<CapturedError>,
    after: Vec<Value>,
    rollback: Option<references::Rollback>,
    storage: Option<references::Storage>,
    #[serde(skip)]
    entry: references::Entry,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturedError {
    name: String,
    message: String,
}

struct Fields(UserConfig);

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "device-where-fields"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(EntityRole::DeviceCode, self.0.clone())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

pub(crate) fn config(serial: bool) -> AuthConfig {
    let mut config = AuthConfig::new("ordinary-device-where-contract-at-least-32-characters")
        .base_url("http://device-where.test");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.advanced.database.generate_id = serial.then_some(IdGeneration::Serial);
    config
}

#[expect(
    clippy::expect_used,
    reason = "The fixture must retain every callback in declaration order"
)]
fn policies(trace: &Trace, owner_ref_type: &UserFieldType) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            FIELDS
                .into_iter()
                .map(|(name, field_type)| {
                    let callback = |phase: &'static str| {
                        let trace = trace.clone();
                        UserFieldTransform::new(move |value| {
                            trace.lock().expect("Device Where trace lock").push(json!({
                                "phase": phase,
                                "field": name,
                                "value": observe(&value)?,
                            }));
                            Ok(value)
                        })
                    };
                    (
                        name.into(),
                        UserFieldConfig {
                            field_type: if name == "ownerRef" {
                                owner_ref_type.clone()
                            } else {
                                field_type
                            },
                            field_name: Some(format!("stored_{name}")),
                            required: Some(false),
                            references: (name == "ownerRef").then(|| UserFieldReference {
                                model: "user".into(),
                                field: "id".into(),
                                ..Default::default()
                            }),
                            transform: Some(FieldTransforms {
                                input: Some(callback("input")),
                                output: Some(callback("output")),
                            }),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

#[expect(
    clippy::expect_used,
    reason = "The fixture recorder must remain available"
)]
fn take(trace: &Trace) -> Vec<Value> {
    std::mem::take(&mut *trace.lock().expect("Device Where trace lock"))
}

fn canonical_numbers(value: &mut Value) -> AuthResult<()> {
    match value {
        Value::Number(number) if number.is_f64() => {
            *value = serde_json::from_str(
                &number
                    .as_f64()
                    .ok_or_else(|| AuthError::internal("Finite fixture number"))?
                    .to_string(),
            )?;
        }
        Value::Array(values) => {
            for value in values {
                canonical_numbers(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                canonical_numbers(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract compares complete rows after verifying their persisted identities"
)]
fn visible(row: &DeviceCode, seeded: &DeviceCode) -> AuthResult<Value> {
    assert_eq!(row.id, seeded.id);
    assert_eq!(row.user_id, seeded.user_id);
    let mut object = row.field_values()?;
    let _ = object.insert("id".into(), FieldValue::from("<device-id>"));
    let _ = object.insert("userId".into(), FieldValue::from("<owner-id>"));
    for (field, _) in FIELDS {
        let _ = object.entry(field.into()).or_insert(FieldValue::Undefined);
    }
    let mut value = observe(&FieldValue::from(object))?;
    canonical_numbers(&mut value)?;
    Ok(value)
}

#[expect(
    clippy::expect_used,
    reason = "Storage observations require the complete callback input for every declared field"
)]
async fn stored(
    reader: &dyn DeviceCodeStore,
    trace: &Trace,
    seeded: &DeviceCode,
) -> AuthResult<Vec<Value>> {
    let row = reader
        .get_device_code_by_device_code(&seeded.device_code)
        .await?;
    let events = take(trace);
    let Some(row) = row else {
        assert!(events.is_empty());
        return Ok(Vec::new());
    };
    let mut value = visible(&row, seeded)?;
    let object = value.as_object_mut().expect("complete stored Device");
    assert_eq!(events.len(), FIELDS.len());
    for ((field, _), event) in FIELDS.into_iter().zip(events) {
        assert_eq!(event.get("phase"), Some(&json!("output")));
        assert_eq!(event.get("field"), Some(&json!(field)));
        let raw = event
            .get("value")
            .expect("raw field callback value")
            .clone();
        let _ = object.remove(field);
        if raw != json!({"type":"undefined"}) {
            let _ = object.insert(format!("stored_{field}"), raw);
        }
    }
    canonical_numbers(&mut value)?;
    Ok(vec![value])
}

fn stored_semantics(rows: &[Value], backend: &str) -> AuthResult<Vec<Value>> {
    let mut rows = rows.to_vec();
    if backend == "sqlite" {
        for row in &mut rows {
            let object = row
                .as_object_mut()
                .ok_or_else(|| AuthError::internal("Captured stored Device object"))?;
            let expiry = object
                .remove("expiresAt")
                .ok_or_else(|| AuthError::internal("Captured SQLite expiry"))?;
            // Compare the native timestamp's value; SQL text spelling is outside the Device Where contract.
            let _ = object.insert("expiresAt".into(), json!({"type":"date", "value":expiry}));
        }
    }
    Ok(rows)
}

#[expect(
    clippy::expect_used,
    clippy::panic_in_result_fn,
    reason = "Captured query shape and scalar input values must be complete before consumption"
)]
fn condition(case: &Case, source: &DeviceCode) -> AuthResult<DeviceCodeOwnership> {
    if case.storage.is_none() {
        assert_eq!(case.condition.len(), 3);
        assert_eq!(
            case.condition.first(),
            Some(&json!({"field":"id", "value":"<device-id>"}))
        );
        assert_eq!(
            case.condition.last(),
            Some(&json!({"field":"status", "value":"approved"}))
        );
    }
    let query = case.condition.get(1).expect("ownership predicate");
    let operator = match query
        .get("operator")
        .and_then(Value::as_str)
        .expect("captured operator")
    {
        "eq" => WhereOperator::Eq,
        "ne" => WhereOperator::Ne,
        "lt" => WhereOperator::Lt,
        "lte" => WhereOperator::Lte,
        "gt" => WhereOperator::Gt,
        "gte" => WhereOperator::Gte,
        "in" => WhereOperator::In,
        "not_in" => WhereOperator::NotIn,
        "contains" => WhereOperator::Contains,
        "starts_with" => WhereOperator::StartsWith,
        "ends_with" => WhereOperator::EndsWith,
        value => {
            return Err(AuthError::internal(format!(
                "Uninventoried Where operator {value}"
            )));
        }
    };
    let mode = match query.get("mode").and_then(Value::as_str) {
        None | Some("sensitive") => WhereMode::Sensitive,
        Some("insensitive") => WhereMode::Insensitive,
        mode => {
            return Err(AuthError::internal(format!(
                "Uninventoried Where mode {mode:?}"
            )));
        }
    };
    let mut condition = DeviceCodeWhere {
        field: query
            .get("field")
            .and_then(Value::as_str)
            .expect("captured field")
            .into(),
        operator,
        mode,
        value: revive(query.get("value").expect("captured predicate value"))?,
    };
    if case.name.ends_with("same-object") {
        use_returned_value(&mut condition, source)?;
    }
    assert_eq!(
        Some(&observe(&condition.value)?),
        query.get("value"),
        "captured ownership value"
    );
    Ok(match case.entry {
        references::Entry::Where => DeviceCodeOwnership::Where(condition),
        references::Entry::FieldEquals => {
            assert_eq!(condition.operator, WhereOperator::Eq);
            assert_eq!(condition.mode, WhereMode::Sensitive);
            DeviceCodeOwnership::FieldEquals {
                field: condition.field,
                value: condition.value,
            }
        }
        references::Entry::FieldIn | references::Entry::FieldNotIn => {
            assert_eq!(condition.mode, WhereMode::Sensitive);
            let values = condition
                .value
                .as_array()
                .ok_or_else(|| {
                    AuthError::internal("Typed Device sets require captured candidates")
                })?
                .to_vec();
            if matches!(case.entry, references::Entry::FieldIn) {
                assert_eq!(condition.operator, WhereOperator::In);
                DeviceCodeOwnership::FieldIn {
                    field: condition.field,
                    values,
                }
            } else {
                assert_eq!(condition.operator, WhereOperator::NotIn);
                DeviceCodeOwnership::FieldNotIn {
                    field: condition.field,
                    values,
                }
            }
        }
    })
}

fn use_returned_value(condition: &mut DeviceCodeWhere, source: &DeviceCode) -> AuthResult<()> {
    let value = source
        .additional_fields
        .get(&condition.field)
        .ok_or_else(|| AuthError::internal("The captured source field must exist"))?
        .clone();
    condition.value = if matches!(condition.operator, WhereOperator::In | WhereOperator::NotIn) {
        FieldValue::from(vec![value])
    } else {
        value
    };
    Ok(())
}

#[expect(
    clippy::expect_used,
    reason = "The contract requires exact input traces and diagnostic messages while propagating store failures"
)]
pub(crate) async fn run<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    cases: &[&Case],
    options: RunConfig<'_>,
) -> AuthResult<()> {
    let RunConfig {
        auth: config,
        owner_ref_type,
        owner_id,
    } = options;
    let serial = matches!(config.advanced.database.generate_id(), IdGeneration::Serial);
    let trace = Trace::default();
    let storage_trace = Trace::default();
    let auth = BetterAuth::new(config.clone())
        .store_arc(raw.clone())
        .plugin(DeviceAuthorizationPlugin::new())
        .plugin(Fields(policies(&trace, &owner_ref_type)))
        .build()
        .await?;
    let reader = BetterAuth::new(config)
        .store_arc(raw)
        .plugin(DeviceAuthorizationPlugin::new())
        .plugin(Fields(policies(&storage_trace, &owner_ref_type)))
        .build()
        .await?;
    let mut owner_input = CreateUser::new()
        .with_name("Where owner")
        .with_email("owner@device-where.test");
    owner_input.id = owner_id.map(str::to_owned);
    let owner = auth.store().create_user(owner_input).await?;
    if let Some(owner_id) = owner_id {
        assert_eq!(
            owner.id.typed()?,
            owner_id,
            "Fixtures retain the supplied owner ID"
        );
    }
    if serial {
        assert_eq!(owner.id.typed()?, "1", "Serial fixtures start with owner 1");
    }
    // Compare the same read projection before and after Device consumption.
    let owner_before = auth
        .store()
        .get_user_by_id(owner.id.typed()?)
        .await?
        .ok_or_else(|| AuthError::internal("The created owner must exist before consumption"))?;
    for case in cases {
        let mut additional_fields = FieldMap::new();
        let inputs = case
            .seed_events
            .iter()
            .filter(|event| event.get("phase") == Some(&json!("input")))
            .collect::<Vec<_>>();
        assert_eq!(inputs.len(), FIELDS.len());
        for ((name, _), event) in FIELDS.into_iter().zip(inputs) {
            assert_eq!(event.get("field"), Some(&json!(name)));
            let value = event.get("value").expect("captured seed input");
            if value != &json!({"type":"undefined"}) {
                let _ = additional_fields.insert(name.into(), revive(value)?);
            }
        }
        let seeded = auth
            .store()
            .create_device_code(CreateDeviceCode {
                device_code: "ordinary-device".into(),
                user_code: "ordinary-user".into(),
                user_id: Some(owner.id.typed()?.clone()),
                expires_at: "2032-01-02T03:04:05.000Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .expect("fixed expiry")
                    .into(),
                status: "approved".into(),
                last_polled_at: None,
                polling_interval: Some(5000.0),
                client_id: Some("ordinary-client".into()),
                scope: Some("read".into()).into(),
                additional_fields,
            })
            .await?;
        assert!(!seeded.id.typed()?.is_empty());
        assert_eq!(seeded.user_id.as_deref(), Some(owner.id.typed()?.as_str()));
        let mut seed_events = json!(take(&trace));
        canonical_numbers(&mut seed_events)?;
        assert_eq!(
            seed_events,
            json!(case.seed_events),
            "{backend}/{} seed callbacks",
            case.name
        );
        assert_eq!(
            visible(&seeded, &seeded)?,
            case.seeded,
            "{backend}/{} seed row",
            case.name
        );
        let before = stored(reader.store().as_ref(), &storage_trace, &seeded).await?;
        assert_eq!(
            before,
            stored_semantics(&case.before, backend)?,
            "{backend}/{} before",
            case.name
        );
        let mut ownership = condition(case, &seeded)?;
        let consumed = if case.storage.is_some() {
            references::consume(auth.store().as_ref(), case, &seeded, ownership).await
        } else if case.transaction {
            let expected = seeded.clone();
            let select_source = case.name.starts_with("transaction-selected-");
            transaction(auth.store().as_ref(), move |tx| {
                Box::pin(async move {
                    if select_source {
                        let source = tx
                            .get_device_code_by_device_code(&expected.device_code)
                            .await?
                            .ok_or_else(|| {
                                AuthError::internal("The transaction must select the seeded Device")
                            })?;
                        let DeviceCodeOwnership::Where(condition) = &mut ownership else {
                            return Err(AuthError::internal(
                                "The captured transaction must use a Where condition",
                            ));
                        };
                        use_returned_value(condition, &source)?;
                    }
                    tx.consume_device_code(&expected, &ownership).await
                })
            })
            .await
        } else {
            auth.store().consume_device_code(&seeded, &ownership).await
        };
        let result = match (&case.error, consumed) {
            (None, result) => result?,
            (Some(expected), Err(AuthError::Internal(message))) if case.rollback.is_some() => {
                assert_eq!(expected.name, "Error");
                assert_eq!(message, expected.message);
                None
            }
            (Some(expected), Err(AuthError::Internal(message)))
                if case.condition.get(1).is_some_and(|query| {
                    query.get("operator").and_then(Value::as_str) == Some("in")
                        && query.get("value").is_some_and(|value| !value.is_array())
                }) =>
            {
                assert_eq!(expected.name, "BetterAuthError");
                assert_eq!(message, "Value must be an array");
                assert_eq!(message, expected.message);
                None
            }
            (Some(expected), Err(AuthError::Internal(message)))
                if backend == "memory" && message == "Value must be an array" =>
            {
                assert_eq!(expected.name, "Error");
                assert_eq!(message, expected.message);
                None
            }
            (Some(expected), Err(AuthError::Internal(message))) if backend == "memory" => {
                assert_eq!(expected.name, "TypeError");
                assert_eq!(
                    message, expected.message,
                    "{backend}/{} diagnostic",
                    case.name
                );
                None
            }
            (Some(expected), Err(AuthError::Internal(message))) if backend == "sqlite" => {
                let name = match message.as_str() {
                    "Binding expected string, TypedArray, boolean, number, bigint or null" => {
                        "TypeError"
                    }
                    "Invalid Date" => "RangeError",
                    _ => {
                        return Err(AuthError::internal(format!(
                            "{backend}/{} unexpected binding error: {message}",
                            case.name
                        )));
                    }
                };
                assert_eq!(expected.name, name);
                assert_eq!(
                    message, expected.message,
                    "{backend}/{} diagnostic",
                    case.name
                );
                None
            }
            (Some(expected), Err(AuthError::Database(DatabaseError::Query(message))))
                if backend == "postgres" =>
            {
                assert_eq!(expected.name, "error");
                // Rust retains the SeaORM and SQLx wrappers. JavaScript error identity remains unpaired.
                assert_eq!(
                    message,
                    format!(
                        "Query Error: error returned from database: {}",
                        expected.message
                    ),
                    "{backend}/{} diagnostic",
                    case.name
                );
                None
            }
            (Some(expected), Err(AuthError::Database(DatabaseError::Query(message))))
                if backend == "sqlite" =>
            {
                assert_eq!(expected.name, "SQLiteError");
                assert_eq!(expected.message, "row value misused");
                assert_eq!(
                    message,
                    format!(
                        "Query Error: error returned from database: (code: 1) {}",
                        expected.message
                    ),
                    "{backend}/{} diagnostic",
                    case.name
                );
                None
            }
            (Some(expected), Err(AuthError::Database(DatabaseError::Query(message))))
                if backend == "mysql" =>
            {
                assert_eq!(expected.name, "Error");
                if expected
                    .message
                    .starts_with(reference_sets::MYSQL_SYNTAX_PREFIX)
                {
                    reference_sets::compare_mysql_syntax_error(
                        &case.name,
                        &expected.message,
                        &message,
                    )?;
                    None
                } else {
                    let code = match expected.message.as_str() {
                        "Unknown column 'NaN' in 'where clause'"
                        | "Unknown column 'Infinity' in 'where clause'" => "1054 (42S22)",
                        "Operand should contain 1 column(s)" => "1241 (21000)",
                        other => {
                            return Err(AuthError::internal(format!(
                                "{backend}/{} unexpected fixture diagnostic: {other}",
                                case.name
                            )));
                        }
                    };
                    assert_eq!(
                        message,
                        format!(
                            "Query Error: error returned from database: {code}: {}",
                            expected.message
                        ),
                        "{backend}/{} diagnostic",
                        case.name
                    );
                    None
                }
            }
            (expected, actual) => {
                return Err(AuthError::internal(format!(
                    "{backend}/{} expected {expected:?}, received {actual:?}",
                    case.name
                )));
            }
        };
        let mut events = json!(take(&trace));
        canonical_numbers(&mut events)?;
        assert_eq!(
            events,
            json!(case.events),
            "{backend}/{} callbacks",
            case.name
        );
        assert_eq!(
            result
                .as_ref()
                .map(|row| visible(row, &seeded))
                .transpose()?
                .unwrap_or(Value::Null),
            case.result,
            "{backend}/{} result",
            case.name
        );
        let after = stored(reader.store().as_ref(), &storage_trace, &seeded).await?;
        assert_eq!(
            after,
            stored_semantics(&case.after, backend)?,
            "{backend}/{} after",
            case.name
        );
        if case.error.is_some() || case.result.is_null() {
            assert_eq!(
                after, before,
                "failed consumption must retain the complete row"
            );
        } else {
            assert!(
                after.is_empty(),
                "successful consumption must delete the row"
            );
        }
        if case.storage.is_some() {
            assert_eq!(
                auth.store().get_user_by_id(owner.id.typed()?).await?,
                Some(owner_before.clone()),
                "{backend}/{} must retain the complete owner view",
                case.name
            );
        }
        auth.store().delete_device_code(&seeded.id).await?;
    }
    Ok(())
}

pub(crate) fn load(backend: &str) -> Result<Fixture, Box<dyn std::error::Error + Send + Sync>> {
    load_fixture(backend, "device-where")
}

pub(crate) fn load_transactions(
    backend: &str,
) -> Result<Fixture, Box<dyn std::error::Error + Send + Sync>> {
    load_fixture(backend, "device-where-transactions")
}

fn load_fixture(
    backend: &str,
    name: &str,
) -> Result<Fixture, Box<dyn std::error::Error + Send + Sync>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/fixtures/{name}-{backend}-1.7.6.json"));
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
