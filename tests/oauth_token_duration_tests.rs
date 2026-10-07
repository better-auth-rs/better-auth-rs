#![cfg(all(feature = "seaorm2", feature = "axum"))]
#![expect(
    clippy::indexing_slicing,
    reason = "Contract fixtures require the captured request, response, and storage fields."
)]

use async_trait::async_trait;
use axum::{Router, body::Body, extract::State, http, routing::post};
use better_auth::{
    AuthConfig, BetterAuth,
    plugins::oauth::{
        GenericOAuthConfig, OAuthPlugin, OAuthRefreshParameters, RefreshTokenParameters,
    },
};
use better_auth_core::{
    AuthError, AuthRequest, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateSession,
    CreateUser, FieldDate, FieldMap, FieldValue, HttpMethod, store::EphemeralStore,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement},
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[path = "oauth_token_duration_tests/hooks.rs"]
mod hooks;
#[path = "account_user_auth_boundary_reference_tests/models.rs"]
mod models;
#[path = "oauth_token_duration_tests/storage.rs"]
mod storage;
#[path = "support/device_where_values.rs"]
mod values;

use hooks::Hooks;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const ORIGIN: &str = "http://oauth-token-duration.test";
const SECRET: &str = "oauth-token-duration-contract-secret-at-least-32-characters";

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<Value>>>);

impl Events {
    fn push(&self, event: Value) -> AuthResult<()> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("OAuth event lock poisoned"))?
            .push(event);
        Ok(())
    }

    fn take(&self) -> AuthResult<Vec<Value>> {
        Ok(std::mem::take(&mut *self.0.lock().map_err(|_| {
            AuthError::internal("OAuth event lock poisoned")
        })?))
    }
}

struct Parameters {
    events: Events,
    scenario: String,
}

fn headers(headers: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut values: Vec<_> = headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    values.sort();
    values
}

#[async_trait]
impl OAuthRefreshParameters for Parameters {
    async fn parameters(&self, request: &AuthRequest) -> AuthResult<HashMap<String, String>> {
        let original = request
            .original_request()
            .ok_or_else(|| AuthError::internal("Missing original refresh Request"))?;
        self.events.push(json!({
            "kind": "refresh.params", "hasContext": true,
            "headers": headers(request.endpoint_headers().ok_or_else(|| AuthError::internal("Missing refresh headers"))?),
            "request": {"url": original.url().map(|url| url.as_str()), "method": format!("{:?}", original.method()).to_ascii_uppercase(), "headers": headers(&original.headers)},
        }))?;
        Ok(HashMap::from([(
            "duration_case".into(),
            self.scenario.clone(),
        )]))
    }
}

#[derive(Clone)]
struct TokenState {
    events: Events,
    response: Value,
}

async fn token(
    State(state): State<TokenState>,
    method: http::Method,
    uri: http::Uri,
    headers: http::HeaderMap,
    body: String,
) -> Result<http::Response<Body>, http::StatusCode> {
    if uri.path() != "/token" {
        return Err(http::StatusCode::NOT_FOUND);
    }
    // The upstream fetch interceptor observes configured headers before transport headers are added.
    let observed_headers = ["accept", "content-type"]
        .into_iter()
        .map(|name| {
            let value = headers
                .get(name)
                .ok_or(http::StatusCode::BAD_REQUEST)?
                .to_str()
                .map_err(|_| http::StatusCode::BAD_REQUEST)?;
            Ok((name, value))
        })
        .collect::<Result<Vec<_>, http::StatusCode>>()?;
    state.events.push(json!({"kind": "token.http", "request": {"method": method.as_str(), "headers": observed_headers, "body": body}, "response": state.response})).map_err(|_| http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let response_body = state.response["body"]
        .as_str()
        .ok_or(http::StatusCode::INTERNAL_SERVER_ERROR)?;
    http::Response::builder()
        .status(200)
        .header("content-type", "application/json;charset=utf-8")
        .body(Body::from(response_body.to_owned()))
        .map_err(|_| http::StatusCode::INTERNAL_SERVER_ERROR)
}

struct Server(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn config() -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.session.expires_in = Some(Duration::seconds(3600));
    config.session.update_age = Some(Duration::seconds(600));
    config.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
        enabled: Some(false),
        ..Default::default()
    });
    config
}

fn comparable_events(mut events: Vec<Value>) -> Vec<Value> {
    // Rust has no consumed Request stream flag; the token server uses a local ephemeral origin.
    for event in &mut events {
        if let Some(request) = event.get_mut("request").and_then(Value::as_object_mut) {
            let _ = request.remove("bodyUsed");
        }
        if event["kind"] == "token.http"
            && let Some(request) = event.get_mut("request").and_then(Value::as_object_mut)
        {
            let _ = request.remove("url");
        }
    }
    events
}

fn date_millis(value: &Value) -> TestResult<i64> {
    let text = value
        .as_str()
        .or_else(|| value.get("value").and_then(Value::as_str))
        .ok_or("Missing Date observation")?;
    Ok(text.parse::<DateTime<Utc>>()?.timestamp_millis())
}

fn normalize_expiries(value: &mut Value, anchors: &HashMap<&str, (i64, Value)>) -> TestResult {
    match value {
        Value::Array(values) => {
            for value in values {
                normalize_expiries(value, anchors)?;
            }
        }
        Value::Object(fields) => {
            for (name, value) in fields {
                if let Some((actual, expected)) = anchors.get(name.as_str()) {
                    if (value.is_string() || value.get("type") == Some(&json!("date")))
                        && date_millis(value)? == *actual
                    {
                        *value = if value.is_string() {
                            expected["value"].clone()
                        } else {
                            expected.clone()
                        };
                    }
                } else {
                    normalize_expiries(value, anchors)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    database: Option<&DatabaseConnection>,
    case: &Value,
) -> TestResult {
    let events = Events::default();
    let recording = Arc::new(AtomicBool::new(false));
    let options = config();
    let raw = raw.with_runtime(
        Arc::new(options.clone()),
        vec![Arc::new(Hooks {
            events: events.clone(),
            recording: recording.clone(),
        })],
        Default::default(),
    )?;
    storage::seed(
        raw.as_ref(),
        case["now"].as_i64().ok_or("Missing captured clock")?,
    )
    .await?;
    let before = storage::snapshot(raw.as_ref(), database).await?;
    storage::assert_snapshot(&before, &case["before"], database.is_some());
    assert!(events.take()?.is_empty());
    let scenario = case["scenario"]["name"]
        .as_str()
        .ok_or("Missing scenario")?;
    let fallback = match values::revive(&case["scenario"]["fallbackDuration"])? {
        FieldValue::Null => None,
        FieldValue::Number(value) => Some(value),
        _ => return Err("Unknown OAuth fallback duration".into()),
    };
    let expected_events: Vec<Value> = serde_json::from_value(case["refresh"]["events"].clone())?;
    let token_event = expected_events
        .iter()
        .find(|event| event["kind"] == "token.http")
        .ok_or("Missing token exchange")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/token", listener.local_addr()?);
    let router = Router::new()
        .route("/token", post(token))
        .with_state(TokenState {
            events: events.clone(),
            response: token_event["response"].clone(),
        });
    let _server = Server(tokio::spawn(
        async move { axum::serve(listener, router).await },
    ));
    let auth = BetterAuth::new(options)
        .store_arc(raw.clone())
        .rate_limit(better_auth_core::middleware::RateLimitConfig::new().enabled(false))
        .plugin(OAuthPlugin::new().add_generic_provider(
            "duration",
            GenericOAuthConfig {
                client_id: "duration-client".into(),
                client_secret: Some("duration-client-secret".into()),
                authorization_url: Some("https://duration-provider.test/authorize".into()),
                token_url: Some(endpoint),
                access_token_expires_in: fallback,
                refresh_token_params: Some(RefreshTokenParameters::Dynamic(Arc::new(Parameters {
                    events: events.clone(),
                    scenario: scenario.into(),
                }))),
                ..Default::default()
            },
        ))
        .build()
        .await?;
    recording.store(true, Ordering::SeqCst);
    let request = &case["refresh"]["request"];
    let request_headers: HashMap<String, String> =
        serde_json::from_value::<Vec<(String, String)>>(request["headers"].clone())?
            .into_iter()
            .collect();
    let request = AuthRequest::from_parts(
        HttpMethod::Post,
        "/api/auth/refresh-token".into(),
        request_headers,
        Some(
            request["body"]
                .as_str()
                .ok_or("Missing refresh body")?
                .as_bytes()
                .to_vec(),
        ),
        None,
    )
    .with_url(
        request["url"]
            .as_str()
            .ok_or("Missing refresh URL")?
            .parse()?,
    );
    let start = Utc::now().timestamp_millis();
    let response = auth.handle_request(request).await?;
    let end = Utc::now().timestamp_millis();
    let mut response_body: Value = serde_json::from_slice(&response.body.bytes()?)?;
    let mut after = storage::snapshot(raw.as_ref(), database).await?;
    let mut observed_events = events.take()?;
    let account = raw
        .get_account("duration", "duration-subject")
        .await?
        .ok_or("Missing refreshed Account")?;
    let mut observed_account = values::observe(&account.internal_fields()?.into())?;
    let mut anchors = HashMap::new();
    if scenario == "negative-submillisecond" {
        for field in ["accessTokenExpiresAt", "refreshTokenExpiresAt"] {
            let actual = date_millis(&observed_account[field])?;
            assert!(
                (start - 1..=end - 1).contains(&actual),
                "{field} must expire within the observed refresh interval minus one millisecond"
            );
            let _ = anchors.insert(field, (actual, case["refresh"]["account"][field].clone()));
        }
    }
    normalize_expiries(&mut response_body, &anchors)?;
    normalize_expiries(&mut after, &anchors)?;
    normalize_expiries(&mut observed_account, &anchors)?;
    for event in &mut observed_events {
        normalize_expiries(event, &anchors)?;
    }
    let mut response_headers: Vec<_> = response
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    response_headers.sort_by(|left, right| left.0.cmp(&right.0));
    let expected = &case["refresh"]["outcome"]["response"];
    assert_eq!(u64::from(response.status), expected["status"]);
    assert_eq!(json!(response_headers), expected["headers"]);
    assert_eq!(
        json!(
            response
                .headers
                .get_all("set-cookie")
                .cloned()
                .collect::<Vec<_>>()
        ),
        expected["cookies"]
    );
    assert_eq!(
        response_body,
        serde_json::from_str::<Value>(
            expected["body"]
                .as_str()
                .ok_or("Missing captured response body")?
        )?
    );
    assert_eq!(
        comparable_events(observed_events),
        comparable_events(expected_events)
    );
    assert_eq!(observed_account, case["refresh"]["account"]);
    storage::assert_snapshot(&after, &case["after"], database.is_some());
    Ok(())
}

#[tokio::test]
async fn oauth_duration_refresh_matches_captured_http_callbacks_and_storage() -> TestResult {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/oauth-token-duration-1.7.6.json"))?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"].as_array().ok_or("Missing OAuth cases")?;
    assert_eq!(cases.len(), 4);
    for case in cases {
        match case["backend"].as_str() {
            Some("memory") => {
                contract(
                    Arc::new(EphemeralStore::new(Arc::new(config()))),
                    None,
                    case,
                )
                .await?
            }
            Some("sqlite") => {
                let database = storage::sqlite().await?;
                contract(
                    Arc::new(SeaOrmStore::<models::Core>::new(config(), database.clone())),
                    Some(&database),
                    case,
                )
                .await?;
                database.close().await?;
            }
            _ => return Err("Unknown OAuth backend".into()),
        }
    }
    Ok(())
}
