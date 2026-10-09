#![cfg(feature = "seaorm2")]
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "The paired contract fails immediately on incomplete observations; Result preserves setup and decoding errors."
)]

use better_auth::{
    BetterAuth,
    plugins::{
        EmailVerificationPlugin, email_verification::EmailVerificationCallbacks,
        endpoint_context::EndpointContext,
    },
};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema,
    AuthStore, CreateAccount, CreateSession, CreateUser, FieldMap, FieldValue, HttpMethod,
    ListUsersParams, store::EphemeralStore,
};
use better_auth_seaorm::{SeaOrmStore, sea_orm::DatabaseConnection};
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

#[path = "account_user_auth_boundary_reference_tests/hooks.rs"]
mod hooks;
#[path = "account_user_auth_boundary_reference_tests/models.rs"]
mod models;
#[path = "email_verification_claims_tests/normalize.rs"]
mod normalize;
#[path = "email_verification_payload_tests/recorder.rs"]
mod recorder;
#[path = "email_verification_claims_tests/storage.rs"]
mod storage;
#[path = "email_verification_claims_tests/values.rs"]
mod values;

use recorder::Events;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const ORIGIN: &str = "http://email-verification-claims.test";
const SECRET: &str = "email-verification-claims-contract-secret-at-least-32-characters";
const EMAIL: &str = "owner@verify-claims.test";
const ISSUED_AT: i64 = 2_000_000_000_123;

#[derive(Deserialize)]
struct Fixture {
    version: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    backend: String,
    scenario: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    issued_at: i64,
    observations: Vec<Box<RawValue>>,
    follow_up_tokens: Vec<CapturedToken>,
    jwt: Box<RawValue>,
}

#[derive(Deserialize)]
struct CapturedToken {
    token: String,
    payload: String,
    claims: Box<RawValue>,
}

fn required<'a>(value: &'a Value, pointer: &str) -> &'a Value {
    value.pointer(pointer).expect("Required captured field")
}

fn config(events: Option<&Events>) -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.session.expires_in = Some(chrono::Duration::seconds(3600));
    config.session.update_age = Some(chrono::Duration::seconds(600));
    config.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
        enabled: Some(false),
        ..Default::default()
    });
    let events = events.cloned();
    let counter = AtomicUsize::new(0);
    config.advanced.database.generate_id = Some(better_auth_core::id::IdGeneration::Custom(
        better_auth_core::id::IdGenerator::new(move |input| {
            let id = format!(
                "{}-{}",
                input.model,
                counter.fetch_add(1, Ordering::SeqCst) + 1
            );
            if let Some(events) = &events {
                let mut input_value = json!({"model":input.model});
                if let Some(size) = input.size {
                    input_value["size"] = json!(size);
                }
                events.push(json!({"kind":"generate-id", "input":input_value, "id":id}))?;
            }
            Ok(Some(id))
        }),
    ));
    config
}

fn describe_request(request: Option<&AuthRequest>) -> AuthResult<Value> {
    let Some(request) = request else {
        return Ok(json!({"type":"undefined"}));
    };
    let mut headers = request
        .headers
        .iter()
        .map(|(key, value)| [key.to_ascii_lowercase(), value.clone()])
        .collect::<Vec<_>>();
    headers.sort();
    Ok(json!({
        "method": match request.method { HttpMethod::Get => "GET", HttpMethod::Post => "POST", HttpMethod::Put => "PUT", HttpMethod::Delete => "DELETE", HttpMethod::Patch => "PATCH", HttpMethod::Options => "OPTIONS", HttpMethod::Head => "HEAD" },
        "url": request.url().ok_or_else(|| AuthError::internal("The callback Request must retain its URL"))?.as_str(),
        "headers": headers,
        "body": std::str::from_utf8(request.body.as_deref().unwrap_or_default()).map_err(|error| AuthError::internal(error.to_string()))?,
    }))
}

fn request(input: &Value, tokens: &[(String, String)]) -> TestResult<AuthRequest> {
    assert_eq!(input["method"], "GET");
    assert_eq!(input["body"], "");
    let mut url = input["url"]
        .as_str()
        .ok_or("Missing request URL")?
        .to_owned();
    for (actual, captured) in tokens {
        url = url.replace(captured, actual);
    }
    let url: url::Url = url.parse()?;
    assert_eq!(url.origin().ascii_serialization(), ORIGIN);
    assert_eq!(url.path(), "/api/auth/verify-email");
    let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/verify-email").with_url(url);
    for header in input["headers"]
        .as_array()
        .ok_or("Missing request headers")?
    {
        let _ = request.headers.insert(
            header[0].as_str().ok_or("Header name")?.into(),
            header[1].as_str().ok_or("Header value")?.into(),
        );
    }
    Ok(request)
}

fn response(response: &AuthResponse) -> TestResult<Value> {
    let mut headers = response
        .headers
        .iter()
        .map(|(key, value)| [key.to_ascii_lowercase(), value.clone()])
        .collect::<Vec<_>>();
    headers.sort();
    Ok(json!({
        "status":response.status,
        "headers":headers,
        "cookies":response.headers.get_all("set-cookie").collect::<Vec<_>>(),
        "body":String::from_utf8(response.body.bytes()?.to_vec())?,
    }))
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    database: Option<&DatabaseConnection>,
    case: &Case,
) -> TestResult {
    assert_eq!(case.issued_at, ISSUED_AT);
    storage::seed(
        raw.as_ref(),
        case.scenario == "uppercase-change-own-session",
    )
    .await?;
    let events = Events::default();
    let options = config(Some(&events));
    let store = raw.with_runtime(
        Arc::new(options.clone()),
        vec![Arc::new(hooks::Hooks(events.clone()))],
        Default::default(),
    )?;
    let before = events.clone();
    let after = events.clone();
    let sender = events.clone();
    let callbacks = EmailVerificationCallbacks::send(move |message, endpoint: &EndpointContext<'_, S>| {
        sender.push(json!({"kind":"sender", "data":{"user":values::observe(&message.user)?,"url":message.url,"token":message.token}, "request":describe_request(endpoint.request)?}))?;
        Ok(None)
    }).before(move |user, endpoint| {
        before.push(json!({"kind":"verification.before", "user":values::observe(user)?, "request":describe_request(endpoint.request)?}))?;
        Ok(None)
    }).after(move |user, endpoint| {
        after.push(json!({"kind":"verification.after", "user":values::observe(user)?, "request":describe_request(endpoint.request)?}))?;
        Ok(None)
    });
    let legacy = Arc::new(|_: &FieldValue| -> std::pin::Pin<Box<dyn std::future::Future<Output=AuthResult<()>> + Send>> {
        Box::pin(async { Err(AuthError::internal("Typed callbacks must replace the legacy callback")) })
    });
    let auth = BetterAuth::new(options)
        .store_arc(store)
        .plugin(
            EmailVerificationPlugin::new()
                .before_email_verification(legacy.clone())
                .after_email_verification(legacy)
                .callbacks(callbacks),
        )
        .rate_limit(better_auth_core::middleware::RateLimitConfig {
            enabled: Some(false),
            ..Default::default()
        })
        .on_api_error(Arc::new(events.clone()))
        .build()
        .await?;
    let _ = events.take()?;
    let mut anchors = normalize::Anchors::default();
    for captured in &case.observations {
        let mut expected = values::capture(captured.get())?;
        let request = request(&expected["request"], &anchors.tokens)?;
        let request_observation = describe_request(Some(&request))?;
        let before = storage::snapshot(raw.as_ref(), database).await?;
        let start = chrono::Utc::now().timestamp_millis();
        let result = auth
            .handle_request(request)
            .with_subscriber(tracing_subscriber::registry().with(events.clone()))
            .await?;
        let end = chrono::Utc::now().timestamp_millis();
        let observed = events.take()?;
        let after = storage::snapshot(raw.as_ref(), database).await?;
        let mut actual = json!({"phase":expected["phase"], "request":request_observation, "before":before,"events":observed,"response":response(&result)?,"after":after});
        anchors.validate(&actual, case, start, end)?;
        anchors.apply(&mut actual);
        normalize::paired(&mut actual, &mut expected, database.is_some())?;
        recorder::assert_events(
            actual["events"].as_array().ok_or("Missing events")?,
            &json!({"backend":case.backend,"scenario":case.scenario,"events":expected["events"]}),
        )?;
        normalize::remove_native_errors(&mut actual)?;
        normalize::remove_native_errors(&mut expected)?;
        assert_eq!(
            actual, expected,
            "{} / {} / {:?}",
            case.backend, case.scenario, case.callback_url
        );
    }
    assert_eq!(anchors.tokens.len(), case.follow_up_tokens.len());
    // The JWT unit contract separately compares the complete signed payload, including unknown UTF-16 keys.
    let input: CapturedToken = serde_json::from_str(case.jwt.get())?;
    assert!(!input.token.is_empty());
    eprintln!(
        "{} / {}: complete endpoint values and lifecycle order paired; runtime-native error diagnostics and HTTP statusText retain their language-specific observations",
        case.backend, case.scenario
    );
    Ok(())
}

fn fixture() -> TestResult<Fixture> {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "fixtures/email-verification-claims-1.7.6.json"
    ))?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.cases.len(), 60);
    Ok(fixture)
}

#[tokio::test]
async fn memory_claims_match_captured_http_callbacks_and_storage() -> TestResult {
    for case in fixture()?
        .cases
        .iter()
        .filter(|case| case.backend == "memory")
    {
        contract(
            Arc::new(EphemeralStore::new(Arc::new(config(None)))),
            None,
            case,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_claims_match_captured_http_callbacks_and_storage() -> TestResult {
    for case in fixture()?
        .cases
        .iter()
        .filter(|case| case.backend == "sqlite")
    {
        let database = storage::sqlite().await?;
        let store = Arc::new(SeaOrmStore::<models::Core>::new(
            config(None),
            database.clone(),
        ));
        contract(store, Some(&database), case).await?;
        database.close().await?;
    }
    Ok(())
}
