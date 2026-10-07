#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "The paired contract must fail on missing observations and retain complete fixture values"
)]

use better_auth::{
    __private_core::{
        __private_async_trait::async_trait,
        AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
        AuthRoute, AuthSchema, AuthStore, CreateUser,
        api_error::{ApiErrorHandler, ApiErrorTask},
        entity::AuthUser,
        id::{IdGeneration, IdGenerator},
        middleware::RateLimitConfig,
        store::schema::EntityRole,
        user_fields::{
            FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
        },
        utils::cookie_utils::{sign_cookie_value, verify_cookie_value},
    },
    AuthConfig, BetterAuth,
    plugins::api_key::{ApiKeyConfig, ApiKeyGenerator, ApiKeyPlugin},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex},
};

#[path = "api_key_number_name_observation.rs"]
mod observation;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(crate) const OWNER: &str = "number-name-user-1";
const SECRET: &str = "ordinary-api-key-number-name-secret-at-least-32-characters";
const ORIGIN: &str = "http://api-key-number-name.test";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scenario {
    Defaults,
    Ordering,
}

#[derive(Deserialize)]
struct Fixture {
    version: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Case {
    backend: String,
    required: bool,
    declaration: Value,
    owner_id: String,
    pub(crate) catalog: Value,
    operations: Vec<Operation>,
}

#[derive(Deserialize)]
struct Operation {
    name: String,
    request: Request,
    before: Value,
    events: Vec<Value>,
    response: Response,
    thrown: Value,
    after: Value,
}

#[derive(Deserialize)]
struct Request {
    url: String,
    method: String,
    headers: Vec<[String; 2]>,
    body: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Response {
    status: u16,
    status_text: String,
    headers: Vec<[String; 2]>,
    cookies: Vec<String>,
    body: String,
}

pub(crate) fn fixture(backend: &str, required: bool, scenario: Scenario) -> TestResult<Case> {
    let source = match scenario {
        Scenario::Defaults => include_str!("../fixtures/api-key-number-name-1.7.6.json"),
        Scenario::Ordering => include_str!("../fixtures/api-key-number-name-order-1.7.6.json"),
    };
    let fixture: Fixture = serde_json::from_str(source)?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(
        fixture
            .cases
            .iter()
            .map(|case| (case.backend.as_str(), case.required))
            .collect::<Vec<_>>(),
        [
            ("memory", true),
            ("memory", false),
            ("sqlite", true),
            ("sqlite", false)
        ]
    );
    fixture
        .cases
        .into_iter()
        .find(|case| case.backend == backend && case.required == required)
        .ok_or_else(|| "Missing Number name case".into())
}

#[derive(Default)]
struct State {
    events: Vec<Value>,
    ids: BTreeMap<String, usize>,
    keys: usize,
}
type Shared = Arc<Mutex<State>>;

pub(crate) fn config() -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.telemetry.enabled = false;
    config
}

struct Callbacks(Shared);

#[async_trait]
impl ApiKeyGenerator for Callbacks {
    async fn generate(&self, length: usize, prefix: Option<&str>) -> AuthResult<String> {
        let mut state = self.0.lock().expect("API Key generator trace");
        state.keys += 1;
        let value = format!(
            "ordinary-number-name-key-{}-abcdefghijklmnopqrstuvwxyz",
            state.keys
        );
        state.events.push(json!({
            "kind": "generate-key", "input": {"length": length, "prefix": prefix.map_or(json!({"type":"undefined"}), Value::from)}, "value": value,
        }));
        Ok(value)
    }
}

impl<S: AuthSchema> ApiErrorHandler<S> for Callbacks {
    fn on_error(&self, error: &AuthError, _: &AuthContext<S>) -> AuthResult<Option<ApiErrorTask>> {
        self.0
            .lock()
            .expect("API Key error trace")
            .events
            .push(json!({
                "kind": "api-error", "message": error.to_string(),
            }));
        Ok(None)
    }
}

struct Fields {
    required: bool,
    scenario: Scenario,
    state: Shared,
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "ordinary-api-key-number-name"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        let scenario = self.scenario;
        let transform = |kind| {
            let state = self.state.clone();
            UserFieldTransform::new(move |value| {
                state.lock().expect("API Key field trace").events.push(json!({
                    "kind": kind, "field": "name", "value": value.json()?.unwrap_or(json!({"type":"undefined"})),
                }));
                Ok(if scenario == Scenario::Ordering && kind == "input" {
                    match value.as_str() {
                        Some("Key 10") => 10.0.into(),
                        Some("Key 2") => 2.0.into(),
                        _ => value,
                    }
                } else {
                    value
                })
            })
        };
        context.register_model_fields(
            EntityRole::ApiKey,
            UserConfig {
                additional_fields: Some(
                    [(
                        "name".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Number,
                            required: Some(self.required),
                            default_value: Some(7.into()),
                            transform: Some(FieldTransforms {
                                input: Some(transform("input")),
                                output: Some(transform("output")),
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        )
    }
}

pub(crate) async fn contract<S, F, Fut>(
    raw: Arc<dyn AuthStore<S>>,
    case: Case,
    scenario: Scenario,
    observe_raw: F,
) -> TestResult
where
    S: AuthSchema,
    F: Fn() -> Fut,
    Fut: Future<Output = TestResult<Value>>,
{
    assert_eq!(
        case.declaration,
        json!({"type":"number", "required":case.required, "defaultValue":7})
    );
    assert_eq!(case.owner_id, OWNER);
    assert_eq!(case.catalog.is_null(), case.backend == "memory");
    let operations: &[&str] = match scenario {
        Scenario::Defaults => &[
            "create-first",
            "create-second",
            "get",
            "list",
            "list-name-ascending",
            "reject-number-input",
        ],
        Scenario::Ordering => &[
            "create-ten",
            "create-two",
            "create-default",
            "get",
            "list",
            "list-name-asc",
            "list-name-desc",
            "reject-number-input",
        ],
    };
    assert_eq!(
        case.operations
            .iter()
            .map(|operation| operation.name.as_str())
            .collect::<Vec<_>>(),
        operations
    );
    let state = Shared::default();
    let ids = state.clone();
    let mut config = config();
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            let mut state = ids.lock().expect("API Key ID trace");
            let sequence = state.ids.entry(request.model.to_owned()).or_default();
            *sequence += 1;
            let value = format!("number-name-{}-{sequence}", request.model);
            state
                .events
                .push(json!({"kind":"generate-id", "model":request.model, "value":value}));
            Ok(Some(value))
        })));
    let callbacks = Arc::new(Callbacks(state.clone()));
    let auth = Arc::new(
        BetterAuth::new(config)
            .store_arc(raw)
            .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
                custom_key_generator: Some(callbacks.clone()),
                ..Default::default()
            }))
            .plugin(Fields {
                required: case.required,
                scenario,
                state: state.clone(),
            })
            .on_api_error(callbacks)
            .rate_limit(RateLimitConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .build()
            .await?,
    );
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Number name owner")
                .with_email("owner@api-key-number-name.test")
                .with_email_verified(false),
        )
        .await?;
    assert_eq!(owner.id().typed()?, OWNER);
    let session = auth
        .session_manager()
        .create_session(&owner, None, None)
        .await?;
    let signed = sign_cookie_value(&session.token, SECRET);
    assert_eq!(
        verify_cookie_value(&signed, SECRET).as_deref(),
        Some(session.token.as_str())
    );
    let cookie = format!("better-auth.session_token={signed}");
    state.lock().expect("API Key setup trace").events.clear();
    let mut dates = observation::Dates::default();
    for operation in &case.operations {
        let before = observe_raw().await?;
        assert_eq!(
            dates.normalize(&before)?,
            operation.before,
            "{} {} before",
            case.backend,
            operation.name
        );
        assert!(
            state
                .lock()
                .expect("API Key trace before request")
                .events
                .is_empty()
        );
        let start = observation::now();
        let response = observation::request(auth.clone(), &operation.request, &cookie).await?;
        let end = observation::now();
        let events = std::mem::take(&mut state.lock().expect("API Key operation trace").events);
        assert_eq!(
            events, operation.events,
            "{} {} callbacks",
            case.backend, operation.name
        );
        assert!(
            operation.thrown.is_null(),
            "The HTTP request must return a Response"
        );
        let after = observe_raw().await?;
        if operation.request.method == "GET" || operation.name == "reject-number-input" {
            assert_eq!(
                after, before,
                "Reads and rejected numeric input must preserve all stored fields"
            );
        }
        dates.insert(&after, start..=end)?;
        assert_eq!(
            dates.normalize(&after)?,
            operation.after,
            "{} {} after",
            case.backend,
            operation.name
        );
        observation::assert_response(response, &operation.response, &dates)?;
    }
    eprintln!(
        "API Key Number name boundaries: finite number and null ordering is paired; object coercion timing and locale string ordering remain unpaired; HTTP statusText and JSON key order remain unpaired; Axum framing is checked separately; Memory adapter projection maps absent permissions to None; SQLite catalog compares semantics rather than DDL spelling; backend={}",
        case.backend
    );
    Ok(())
}
