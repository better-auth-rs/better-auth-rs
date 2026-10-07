#![cfg(feature = "seaorm2")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions compare captured operations; Result propagates setup and observation errors."
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthRequest, AuthResult, AuthSchema, AuthStore, CreateSession,
    CreateUser, FieldDate, FieldMap, FieldValue, HttpMethod, ListUsersParams, UserView,
    session::{SessionManager, SessionRead},
    store::EphemeralStore,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform},
    utils::cookie_utils::sign_cookie_value,
};
use better_auth_seaorm::{SeaOrmStore, sea_orm::DatabaseConnection};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
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
    config.advanced.database.generate_id = Some(better_auth_core::id::IdGeneration::Custom(
        better_auth_core::id::IdGenerator::new(|_| Ok(Some("session-a".into()))),
    ));
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
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    };
    config.user.fields_mut().extend([
        ("name".into(), field("user", "name", true)),
        ("image".into(), field("user", "image", false)),
    ]);
    let reference = UserFieldReference {
        model: "user".into(),
        field: "id".into(),
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
                references: (scenario != "removed-reference").then(|| reference.clone()),
                ..field("session", "userId", true)
            },
        ),
        (
            "ownerRef".into(),
            UserFieldConfig {
                references: (scenario == "second-optional-user-reference").then_some(reference),
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
    let token = input["token"]
        .as_str()
        .or_else(|| input["input"]["where"][0]["value"].as_str())
        .ok_or_else(|| AuthError::internal("Missing Session token"))?;
    if input["surface"] == "internal" {
        let mut request = AuthRequest::new(HttpMethod::Get, "/get-session");
        let _ = request.headers.insert(
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                sign_cookie_value(token, SECRET)
            ),
        );
        let result = SessionManager::new(config, store)
            .resolve(&request, SessionRead::Authoritative)
            .await?;
        return Ok(result
            .data
            .map_or(FieldValue::Null, |data| FieldMap::from(data).into()));
    }
    if name == "session-control" {
        return Ok(store
            .get_session(token)
            .await?
            .map_or(FieldValue::Null, |session| FieldMap::from(session).into()));
    }
    let Some((session, joined)) = store.get_session_snapshot(token).await? else {
        return Ok(FieldValue::Null);
    };
    let user = match joined {
        Some(data) => Some(data.user),
        None => store.get_user_by_id(session.user_id.typed()?).await?,
    };
    let mut result = FieldMap::from(session);
    let _ = result.insert(
        "user".into(),
        match user {
            Some(user) => user_fields(&user, &config).await?,
            None => FieldValue::Null,
        },
    );
    Ok(result.into())
}

fn assert_outcome(result: AuthResult<FieldValue>, expected: &Value) -> TestResult {
    match result {
        Ok(value) => {
            assert_eq!(expected["returned"], true, "{expected}");
            assert_eq!(value, values::revive(&expected["result"])?, "{expected}");
            assert_eq!(value.json()?, Some(expected["json"].clone()), "{expected}");
            if value.is_null() {
                assert_eq!(expected["keyOrder"], json!([]));
            } else {
                println!(
                    "Unpaired observation boundary: {} object keyOrder {:?}; Rust typed Session/User views retain their wire order.",
                    expected["name"], expected["keyOrder"]
                );
            }
        }
        Err(error) => {
            assert_eq!(expected["returned"], false, "{expected}: {error:?}");
            assert!(matches!(error, AuthError::Config(_)), "{error:?}");
            assert_eq!(
                error.instrumentation_message(),
                expected["error"]["message"]
            );
            assert_eq!(expected["error"]["name"], "BetterAuthError");
            assert_eq!(
                expected["error"]["properties"],
                json!({"name":"BetterAuthError"})
            );
            assert_eq!(expected["error"]["keys"], json!(["name"]));
        }
    }
    Ok(())
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    database: Option<&DatabaseConnection>,
    case: &Value,
) -> TestResult {
    storage::seed(raw.as_ref()).await?;
    let before = storage::snapshot(raw.as_ref(), database).await?;
    storage::assert_snapshot(&before, &case["before"], database.is_some());
    let scenario = case["scenario"].as_str().ok_or("Missing scenario")?;
    let joins = case["joins"].as_bool().ok_or("Missing joins option")?;
    let operations = case["operations"].as_array().ok_or("Missing operations")?;
    assert_eq!(operations.len(), 6);
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
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["scenarios"].as_array().map(Vec::len), Some(3));
    let cases = fixture["cases"].as_array().ok_or("Missing cases")?;
    assert_eq!(cases.len(), 12);
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
