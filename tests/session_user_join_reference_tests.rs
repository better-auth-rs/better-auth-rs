#![cfg(feature = "seaorm2")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions compare captured operations; Result propagates setup and observation errors."
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthRequest, AuthResult, AuthSchema, AuthStore, CreateSession,
    CreateUser, FieldDate, FieldMap, FieldValue, HttpMethod, ListUsersParams, UserView,
    session::{NativeSessionData, SessionData, SessionManager, SessionRead},
    store::{EphemeralStore, JoinValue},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform},
    wire::SessionView,
};
use better_auth_seaorm::{SeaOrmStore, sea_orm::DatabaseConnection};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

#[path = "account_user_auth_boundary_reference_tests/models.rs"]
mod core_models;
#[path = "session_user_join_reference_tests/recorder.rs"]
mod recorder;
#[path = "session_user_join_reference_tests/storage.rs"]
mod storage;
#[path = "support/device_where_values.rs"]
mod values;

use recorder::Events;

const TOKEN: &str = "session-user-join-existing-token";
const SECRET: &str = "session-user-join-reference-contract-at-least-thirty-two-characters";
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn config(scenario: &str, joins: bool, events: Option<&Events>) -> AuthConfig {
    let mut config = AuthConfig::new(SECRET);
    config.base_url = "http://session-user-join-reference.test".into();
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.advanced.database.joins = Some(joins);
    config.session.cookie_cache = None;
    config.session.disable_session_refresh = Some(true);
    config.advanced.database.default_find_many_limit =
        (scenario == "reverse-user-reference-many-limit").then_some(1.0);
    let generated = AtomicUsize::new(0);
    config.advanced.database.generate_id = Some(better_auth_core::id::IdGeneration::Custom(
        better_auth_core::id::IdGenerator::new(move |_| {
            ["session-a", "session-b"]
                .get(generated.fetch_add(1, Ordering::SeqCst))
                .map(|id| Some((*id).into()))
                .ok_or_else(|| AuthError::internal("Session seed generated an unexpected ID"))
        }),
    ));
    let replace_owner = scenario == "session-output-selects-fallback-owner";
    let field = |model: &'static str, name: &'static str, required| {
        let events = events.cloned();
        UserFieldConfig {
            required: Some(required),
            transform: events.map(|events| FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    events.push(json!([
                        "output",
                        format!("{model}.{name}"),
                        values::observe(&value)?
                    ]))?;
                    Ok(
                        if replace_owner
                            && model == "session"
                            && name == "ownerRef"
                            && value.as_str() == Some("user-b")
                        {
                            "user-c".into()
                        } else {
                            value
                        },
                    )
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    };
    config.user.fields_mut().extend([
        ("name".into(), field("user", "name", true)),
        (
            "image".into(),
            UserFieldConfig {
                references: scenario
                    .starts_with("reverse-")
                    .then(|| UserFieldReference {
                        model: "session".into(),
                        field: "id".into(),
                        ..Default::default()
                    }),
                unique: scenario
                    .starts_with("reverse-user-reference-unique")
                    .then_some(true),
                ..field("user", "image", false)
            },
        ),
    ]);
    let reference = UserFieldReference {
        model: "user".into(),
        field: "id".into(),
        ..Default::default()
    };
    config.session.fields_mut().extend([
        (
            "token".into(),
            UserFieldConfig {
                unique: Some(true),
                ..field("session", "token", true)
            },
        ),
        (
            "userId".into(),
            UserFieldConfig {
                references: (!matches!(
                    scenario,
                    "removed-reference"
                        | "alternate-session-reference"
                        | "session-output-selects-fallback-owner"
                ))
                .then(|| reference.clone()),
                ..field("session", "userId", true)
            },
        ),
        (
            "ownerRef".into(),
            UserFieldConfig {
                references: matches!(
                    scenario,
                    "second-optional-user-reference"
                        | "alternate-session-reference"
                        | "session-output-selects-fallback-owner"
                )
                .then_some(reference),
                ..field("session", "ownerRef", false)
            },
        ),
    ]);
    config
}

async fn user_fields(user: &UserView, config: &AuthConfig) -> AuthResult<FieldValue> {
    Ok(FieldMap::from(
        UserView::with_internal_fields(user, &config.user, &Default::default()).await?,
    )
    .into())
}

fn snapshot_fields(
    (session, joined): (SessionView, Option<SessionData<JoinValue<UserView>>>),
    config: &AuthConfig,
    internal: bool,
) -> AuthResult<FieldValue> {
    let mut data = NativeSessionData::from(
        joined
            .ok_or_else(|| AuthError::internal("Requested Session relationship was not loaded"))?,
    );
    if internal {
        if data.user.is_null() {
            return Ok(FieldValue::Null);
        }
        data.session.filter_returned_fields(&config.session)?;
        return Ok(FieldMap::from(data).into());
    }
    let mut fields = FieldMap::from(session);
    let _ = fields.insert("user".into(), data.user);
    Ok(fields.into())
}

async fn operation<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    config: Arc<AuthConfig>,
    input: &Value,
) -> AuthResult<FieldValue> {
    let name = input["name"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing operation name"))?;
    if name == "user-control" {
        return match store.get_user_by_id("user-a").await? {
            Some(user) => user_fields(&user, &config).await,
            None => Ok(FieldValue::Null),
        };
    }
    let internal = input["surface"] == "internal";
    if input["batch"] == true {
        let tokens = input
            .get("tokens")
            .or_else(|| {
                input
                    .get("input")?
                    .get("where")?
                    .as_array()?
                    .first()?
                    .get("value")
            })
            .and_then(Value::as_array)
            .ok_or_else(|| AuthError::internal("Missing batch Session tokens"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| AuthError::internal("Batch Session token is not a string"))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let values = store
            .get_session_snapshots(&tokens, false)
            .await?
            .into_iter()
            .map(|snapshot| snapshot_fields(snapshot, &config, internal))
            .collect::<AuthResult<Vec<_>>>()?;
        return Ok(if internal && values.iter().any(FieldValue::is_null) {
            Vec::<FieldValue>::new().into()
        } else {
            values.into()
        });
    }
    let token = input
        .get("token")
        .and_then(Value::as_str)
        .or_else(|| {
            input
                .get("input")?
                .get("where")?
                .as_array()?
                .first()?
                .get("value")?
                .as_str()
        })
        .ok_or_else(|| {
            AuthError::internal("Missing Session token at token or input.where[0].value")
        })?;
    if name == "session-control" {
        return Ok(store
            .get_session(token)
            .await?
            .map_or(FieldValue::Null, |session| FieldMap::from(session).into()));
    }
    if internal {
        let mut request = AuthRequest::new(HttpMethod::Get, "/get-session");
        request.query = Some(json!({"disableRefresh": true}));
        let _ = request.headers.insert(
            "cookie".into(),
            format!(
                "{}={}",
                config.auth_cookie("session_token", Default::default()).name,
                better_auth_core::utils::cookie_utils::sign_cookie_value(
                    token,
                    config.signing_secret()
                ),
            ),
        );
        let resolved = SessionManager::new(config, store)
            .resolve_native(&request, SessionRead::Authoritative)
            .await?;
        return Ok(resolved
            .data
            .map_or(FieldValue::Null, |data| FieldMap::from(data).into()));
    }
    let Some(snapshot) = store.get_session_snapshot(token).await? else {
        return Ok(FieldValue::Null);
    };
    snapshot_fields(snapshot, &config, false)
}

fn key_order(value: &FieldValue, path: &[String]) -> Vec<Value> {
    let entries: Vec<_> = match value {
        FieldValue::Object(fields) => fields
            .iter()
            .map(|(name, value)| (name.clone(), value))
            .collect(),
        FieldValue::Array(values) => values
            .iter()
            .enumerate()
            .map(|(index, value)| (index.to_string(), value))
            .collect(),
        _ => return Vec::new(),
    };
    let mut result = vec![json!({
        "path": path,
        "keys": entries.iter().map(|(name, _)| name).collect::<Vec<_>>(),
    })];
    for (name, value) in entries {
        let mut child = path.to_vec();
        child.push(name);
        result.extend(key_order(value, &child));
    }
    result
}

fn assert_outcome(result: AuthResult<FieldValue>, expected: &Value) -> TestResult {
    match result {
        Ok(value) => {
            assert_eq!(expected["returned"], true, "{expected}");
            assert_eq!(value, values::revive(&expected["result"])?, "{expected}");
            assert_eq!(value.json()?, Some(expected["json"].clone()), "{expected}");
            assert_eq!(
                Value::Array(key_order(&value, &[])),
                expected["keyOrder"],
                "{expected}"
            );
        }
        Err(error) => {
            assert_eq!(expected["returned"], false, "{expected}: {error:?}");
            assert!(matches!(error, AuthError::Config(_)), "{error:?}");
            let expected_error = expected.get("error").ok_or("Missing captured error")?;
            assert_eq!(
                error.instrumentation_message(),
                expected_error
                    .get("message")
                    .and_then(Value::as_str)
                    .ok_or("Missing captured error message")?
            );
            assert_eq!(
                expected_error
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or("Missing captured error name")?,
                "BetterAuthError"
            );
            assert_eq!(
                expected_error
                    .get("properties")
                    .ok_or("Missing captured error properties")?,
                &json!({"name":"BetterAuthError"})
            );
            assert_eq!(
                expected_error
                    .get("keys")
                    .ok_or("Missing captured error keys")?,
                &json!(["name"])
            );
        }
    }
    Ok(())
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    database: Option<&DatabaseConnection>,
    case: &Value,
) -> TestResult {
    let scenario = case["scenario"].as_str().ok_or("Missing scenario")?;
    storage::seed(raw.as_ref(), scenario).await?;
    let before = storage::snapshot(raw.as_ref(), database).await?;
    storage::assert_snapshot(&before, &case["before"], database.is_some());
    let joins = case["joins"].as_bool().ok_or("Missing joins option")?;
    let operations = case["operations"].as_array().ok_or("Missing operations")?;
    let controls = matches!(
        scenario,
        "default" | "removed-reference" | "second-optional-user-reference"
    );
    assert_eq!(operations.len(), if controls { 6 } else { 4 });
    for expected in operations {
        let events = Events::default();
        let config = Arc::new(config(scenario, joins, Some(&events)));
        let store = raw.with_runtime(config.clone(), Vec::new(), Default::default())?;
        let result = operation(store, config, expected)
            .with_subscriber(tracing_subscriber::registry().with(events.clone()))
            .await;
        assert_eq!(events.take()?, expected["events"], "{case}");
        assert_outcome(result, expected)?;
        assert_eq!(expected["storageUnchanged"], true);
        assert_eq!(
            storage::snapshot(raw.as_ref(), database).await?,
            before,
            "{case}"
        );
    }
    storage::assert_snapshot(
        &storage::snapshot(raw.as_ref(), database).await?,
        &case["after"],
        database.is_some(),
    );
    Ok(())
}

#[tokio::test]
async fn session_user_join_references_match_upstream_before_queries() -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/session-user-join-reference-1.7.6.json"
    ))?;
    assert_eq!(
        fixture
            .get("version")
            .and_then(Value::as_str)
            .ok_or("Missing fixture version")?,
        "1.7.6"
    );
    let scenarios = fixture
        .get("scenarios")
        .and_then(Value::as_array)
        .ok_or("Missing scenarios")?;
    assert_eq!(scenarios.len(), 10);
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Missing cases")?;
    assert_eq!(cases.len(), 40);
    assert_eq!(
        cases
            .iter()
            .map(|case| case["operations"].as_array().map_or(0, Vec::len))
            .sum::<usize>(),
        184
    );
    for case in cases {
        let baseline = config("default", false, None);
        match case["backend"].as_str() {
            Some("memory") => {
                contract(
                    Arc::new(EphemeralStore::new(Arc::new(baseline))),
                    None,
                    case,
                )
                .await?
            }
            Some("sqlite") => {
                let database = storage::sqlite().await?;
                contract(
                    Arc::new(SeaOrmStore::<storage::Core>::new(
                        baseline,
                        database.clone(),
                    )),
                    Some(&database),
                    case,
                )
                .await?;
            }
            value => return Err(format!("Unknown backend: {value:?}").into()),
        }
    }
    Ok(())
}
