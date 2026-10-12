#![expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]

//! Replay captured bare-adapter operations through the production shared record boundary.

use super::{ReplayFailures, assert_replay, auth_core as core};
use core::{
    AuthConfig, AuthError, AuthResult, FieldMap, FieldValue,
    plugin_runtime::ModelFields,
    store::schema::EntityRole,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

mod values {
    use super::core as better_auth;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/support/device_where_values.rs"
    ));
}

#[derive(Default)]
pub(super) struct State {
    events: Vec<Value>,
    discard: bool,
    reject: bool,
    original_error: Option<AuthError>,
    original_allocation: usize,
}

pub(super) type Trace = Arc<Mutex<State>>;

fn lock(trace: &Trace) -> AuthResult<std::sync::MutexGuard<'_, State>> {
    trace
        .lock()
        .map_err(|_| AuthError::internal("Shared-column trace lock is poisoned"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Declaration {
    #[serde(rename = "type")]
    kind: String,
    required: bool,
    field_name: String,
}

pub(super) fn role(model: &str) -> AuthResult<EntityRole> {
    Ok(match model {
        "user" => EntityRole::User,
        "session" => EntityRole::Session,
        "account" => EntityRole::Account,
        "verification" => EntityRole::Verification,
        "organization" => EntityRole::Organization,
        "member" => EntityRole::Member,
        "invitation" => EntityRole::Invitation,
        "team" => EntityRole::Team,
        "teamMember" => EntityRole::TeamMember,
        "organizationRole" => EntityRole::OrganizationRole,
        _ => return Err(AuthError::internal("Unknown captured shared-column model")),
    })
}

pub(super) fn cases(backend: &str) -> AuthResult<Vec<Value>> {
    let source = match backend {
        "memory" | "sqlite" => include_str!("../fixtures/shared-column-1.7.6.json"),
        "postgres" | "mysql" => include_str!("../fixtures/shared-column-server-1.7.6.json"),
        _ => return Err(AuthError::internal("Unknown shared-column backend")),
    };
    let fixture: Value = serde_json::from_str(source)?;
    let observation = fixture
        .as_array()
        .and_then(|items| items.iter().find(|item| item["backend"] == backend))
        .ok_or_else(|| AuthError::internal("Missing shared-column backend observation"))?;
    assert_eq!(observation["version"], "1.7.6");
    let cases = observation["cases"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Missing shared-column cases"))?;
    assert_eq!(cases.len(), 30);
    Ok(cases.clone())
}

pub(super) fn runtime(case: &Value) -> AuthResult<(ModelFields, EntityRole, Trace)> {
    let name = case["model"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing shared-column model"))?;
    let role = role(name)?;
    let config = AuthConfig::default();
    let mut schema = match role {
        EntityRole::User => config.user.user_field_schema(),
        EntityRole::Session => {
            let mut plugins = ModelFields::default();
            plugins.register_native_session_fields("organization.enabled")?;
            plugins.register_native_session_fields("organization.teams_enabled")?;
            let mut session = config.session.clone();
            session.additional_fields = plugins.fields(role).additional_fields.clone();
            core::store::session_field_schema(&session, &FieldMap::new())
        }
        EntityRole::Account => config.account.field_schema(),
        EntityRole::Verification => config.verification.field_schema(),
        _ => ModelFields::plugin_native_fields(role),
    };
    let second = case["second"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing second shared-column declaration"))?
        .to_owned();
    let error = String::from("shared column output rejected");
    let trace = Arc::new(Mutex::new(State {
        original_allocation: error.as_ptr() as usize,
        original_error: Some(AuthError::Internal(error)),
        ..Default::default()
    }));
    let declarations = case["configuration"][name]["additionalFields"]
        .as_object()
        .ok_or_else(|| AuthError::internal("Missing shared-column declarations"))?;
    for (name, declaration) in declarations {
        let declaration: Declaration = serde_json::from_value(declaration.clone())?;
        let field_type = match declaration.kind.as_str() {
            "string" => UserFieldType::String,
            "number" => UserFieldType::Number,
            _ => return Err(AuthError::internal("Unexpected captured declaration type")),
        };
        let input_name = name.clone();
        let output_name = name.clone();
        let input_trace = trace.clone();
        let output_trace = trace.clone();
        let input_second = second.clone();
        let output_second = second.clone();
        let declaration = UserFieldConfig {
            field_type,
            required: Some(declaration.required),
            field_name: Some(declaration.field_name),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    let mut state = lock(&input_trace)?;
                    state.events.push(json!({
                        "phase": "input", "field": input_name, "value": values::observe(&value)?,
                    }));
                    Ok(if state.discard && input_name == input_second {
                        FieldValue::Undefined
                    } else {
                        value
                    })
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    let mut state = lock(&output_trace)?;
                    state.events.push(json!({
                        "phase": "output", "field": output_name, "value": values::observe(&value)?,
                    }));
                    if state.reject && output_name == output_second {
                        return Err(state.original_error.take().ok_or_else(|| {
                            AuthError::internal("The captured callback must reject once")
                        })?);
                    }
                    Ok(value)
                })),
            }),
            ..Default::default()
        };
        let _ = schema.fields_mut().insert(name.clone(), declaration);
    }
    assert_eq!(
        json!(schema.fields().keys().collect::<Vec<_>>()),
        case["fields"],
        "Complete declaration order for {name} {}",
        case["mode"]
    );
    let mut runtime = ModelFields::default();
    runtime.register_model_fields(role, schema)?;
    Ok((runtime, role, trace))
}

#[core::__private_async_trait::async_trait]
pub(super) trait Adapter: Sync {
    async fn execute(&self, method: &str, input: FieldValue) -> AuthResult<FieldValue>;
    async fn stored(&self) -> AuthResult<Vec<FieldMap>>;
}

pub(super) fn identifier(input: &FieldValue) -> AuthResult<FieldValue> {
    let selectors = input.model_property("where")?;
    let selectors = selectors
        .as_array()
        .ok_or_else(|| AuthError::internal("Missing shared-column selector"))?;
    assert_eq!(selectors.len()?, 1);
    let selector = selectors
        .get(0)?
        .ok_or_else(|| AuthError::internal("Missing shared-column selector"))?;
    assert_eq!(selector.model_property("field")?, FieldValue::from("id"));
    selector
        .as_object()
        .ok_or_else(|| AuthError::internal("A captured record must be an object"))?
        .get("value")?
        .ok_or_else(|| AuthError::internal("Missing shared-column selector value"))
}

pub(super) async fn run(adapter: &impl Adapter, case: &Value, trace: &Trace) -> AuthResult<()> {
    let operations = case["operations"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Missing shared-column operations"))?;
    assert_eq!(operations.len(), 8);
    let mut failures = ReplayFailures::default();
    for operation in operations {
        let method = operation["method"]
            .as_str()
            .ok_or_else(|| AuthError::internal("Missing shared-column method"))?;
        {
            let mut state = lock(trace)?;
            state.discard = operation["name"] == "update-undefined";
            state.reject = operation["name"] == "update-output-error";
        }
        let input = values::revive(&operation["input"])?;
        let input_observation = values::observe(&input)?;
        let result = adapter.execute(method, input).await;
        let mut actual = json!({
            "name": operation["name"], "method": method, "input": input_observation,
        });
        match result {
            Ok(value) => {
                actual["returned"] = true.into();
                actual["keys"] = json!(match value.as_object() {
                    Some(object) => object.enumerable_keys()?,
                    None => Vec::new(),
                });
                actual["value"] = values::observe(&value)?;
            }
            Err(AuthError::Internal(message)) => {
                actual["returned"] = false.into();
                actual["error"] = json!({
                    "name": "Error", "message": message,
                    "sameCallbackError": message.as_ptr() as usize == lock(trace)?.original_allocation,
                    "properties": {},
                });
            }
            Err(error) => {
                let value = error.into_thrown_value()?;
                actual["returned"] = false.into();
                actual["error"] = json!({
                    "name": values::observe(&value.model_property("name")?)?,
                    "message": values::observe(&value.model_property("message")?)?,
                    "sameCallbackError": false,
                    "properties": values::observe(&value.enumerable_fields()?.into())?,
                });
            }
        }
        actual["events"] = json!(std::mem::take(&mut lock(trace)?.events));
        actual["stored"] = Value::Array(
            adapter
                .stored()
                .await?
                .into_iter()
                .map(|row| {
                    Ok(json!({
                        "keys": row.keys().collect::<Vec<_>>(),
                        "value": values::observe(&row.clone().into())?,
                    }))
                })
                .collect::<AuthResult<_>>()?,
        );
        let label = format!(
            "shared-column/{}/{}/{}",
            case["model"], case["mode"], operation["name"]
        );
        let actual_fields = actual
            .as_object()
            .ok_or_else(|| AuthError::internal("The operation observation must be an object"))?;
        let expected_fields = operation
            .as_object()
            .ok_or_else(|| AuthError::internal("The captured operation must be an object"))?;
        failures.record(&label, || {
            assert_eq!(
                actual_fields.keys().collect::<Vec<_>>(),
                expected_fields.keys().collect::<Vec<_>>(),
                "{label}: own key order"
            );
        });
        // A driver error difference must not prevent callback and persisted-state comparisons.
        for (field, expected) in expected_fields {
            let path = format!("{label}/{field}");
            failures.record(&path, || assert_replay(&actual[field], expected, &path));
        }
    }
    failures.finish();
    Ok(())
}
