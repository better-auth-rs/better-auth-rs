#![cfg(feature = "seaorm2")]
#![expect(
    clippy::expect_used,
    reason = "The contract fails immediately when a captured fixture field is missing"
)]

use async_trait::async_trait;
use better_auth::{AuthConfig, BetterAuth, plugins::EmailVerificationPlugin};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, AuthStore, CreateUser, HttpMethod, ListUsersParams,
    store::EphemeralStore, wire::UserView,
};
use better_auth_seaorm::{
    Database, SeaOrmStore,
    sea_orm::DatabaseConnection,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

#[path = "email_verification_payload_tests/hooks.rs"]
mod hooks;
#[path = "email_verification_payload_tests/recorder.rs"]
mod recorder;
#[path = "email_verification_payload_tests/storage.rs"]
mod storage;

use hooks::DatabaseObserver;
use recorder::Events;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const ORIGIN: &str = "http://email-verification-payload.test";
const SECRET: &str = "email-verification-payload-contract-secret-at-least-32-characters";
const EMAIL: &str = "owner@verify-payload.test";

fn config() -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.telemetry.enabled = false;
    config.logger.disabled = Some(true);
    config.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
        enabled: Some(false),
        ..Default::default()
    });
    config
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Fixture assertions panic while request URL parsing propagates errors"
)]
fn request(case: &Value) -> TestResult<AuthRequest> {
    let input = &case["request"];
    assert_eq!(input["method"], "GET");
    let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/verify-email").with_url(
        input["url"]
            .as_str()
            .expect("Captured request URL")
            .parse()?,
    );
    let url = request.url().expect("Captured request URL");
    assert_eq!(url.origin().ascii_serialization(), ORIGIN);
    assert_eq!(url.path(), "/api/auth/verify-email");
    assert_eq!(
        url.query_pairs()
            .find(|(name, _)| name == "token")
            .map(|(_, value)| value.into_owned()),
        case["token"].as_str().map(str::to_owned)
    );
    for header in input["headers"]
        .as_array()
        .expect("Captured request headers")
    {
        let _ = request.headers.insert(
            header[0].as_str().expect("Header name").into(),
            header[1].as_str().expect("Header value").into(),
        );
    }
    Ok(request)
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions panic while response decoding propagates errors"
)]
fn assert_response(response: &AuthResponse, case: &Value) -> TestResult {
    let expected = &case["response"];
    assert_eq!(u64::from(response.status), expected["status"], "{case}");
    let mut headers = response
        .headers
        .iter()
        .map(|(name, value)| [name.to_ascii_lowercase(), value.clone()])
        .collect::<Vec<_>>();
    // Web Headers iterates by lowercase name; preserve every header value.
    headers.sort();
    assert_eq!(json!(headers), expected["headers"], "{case}");
    assert_eq!(
        json!(response.headers.get_all("set-cookie").collect::<Vec<_>>()),
        expected["cookies"],
        "{case}"
    );
    let body = response.body.bytes()?;
    let expected_body = expected["body"].as_str().expect("Captured response body");
    if expected_body.is_empty() {
        assert!(body.is_empty(), "{case}");
    } else {
        assert_eq!(
            serde_json::from_slice::<Value>(&body)?,
            serde_json::from_str::<Value>(expected_body)?,
            "{case}"
        );
    }
    Ok(())
}

async fn pairing<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    database: Option<&DatabaseConnection>,
    backend: &str,
) -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/email-verification-payload-1.7.6.json"
    ))?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"].as_array().expect("Captured payload cases");
    assert_eq!(cases.len(), 20);
    let cases = cases
        .iter()
        .filter(|case| case["backend"] == backend)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 10);
    let events = Events::default();
    let before = events.clone();
    let after = events.clone();
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .rate_limit(better_auth_core::middleware::RateLimitConfig {
            enabled: Some(false),
            ..Default::default()
        })
        .plugin(DatabaseObserver(events.clone()))
        .plugin(
            EmailVerificationPlugin::new()
                .before_email_verification(Arc::new(move |user| {
                    let result = before.push(json!({"kind": "verification.before", "user": user}));
                    Box::pin(async move { result })
                }))
                .after_email_verification(Arc::new(move |user| {
                    let result = after.push(json!({"kind": "verification.after", "user": user}));
                    Box::pin(async move { result })
                })),
        )
        .on_api_error(Arc::new(events.clone()))
        .build()
        .await?;
    let date = "2030-01-02T03:04:05Z".parse::<chrono::DateTime<chrono::Utc>>()?;
    let _ = auth
        .store()
        .create_user(CreateUser {
            id: Some("payload-owner".into()),
            name: Some("Payload Owner".into()).into(),
            email: Some(EMAIL.into()),
            email_verified: Some(false),
            image: None.into(),
            created_at: Some(date.into()),
            updated_at: Some(date.into()),
            ..Default::default()
        })
        .with_subscriber(tracing_subscriber::registry().with(events.clone()))
        .await?;
    let setup_events = events.take()?;
    assert!(
        setup_events
            .iter()
            .any(|event| event["kind"] == "query" && event["operation"] == "create")
    );
    assert_eq!(
        setup_events
            .iter()
            .filter(|event| event["kind"] == "hook")
            .cloned()
            .collect::<Vec<_>>(),
        vec![
            json!({"kind": "hook", "model": "user", "operation": "create", "phase": "before"}),
            json!({"kind": "hook", "model": "user", "operation": "create", "phase": "after"}),
        ],
        "The real setup must activate both database callback phases"
    );
    let initial = storage::projected(raw.as_ref()).await?;
    let initial_sql = if let Some(database) = database {
        Some(storage::sqlite(database).await?)
    } else {
        None
    };
    let _ = events.take()?;
    for case in cases {
        storage::assert_projected(&initial, &case["before"]);
        let response = auth
            .handle_request(request(case)?)
            .with_subscriber(tracing_subscriber::registry().with(events.clone()))
            .await?;
        let observed = events.take()?;
        assert_response(&response, case)?;
        recorder::assert_events(&observed, case)?;
        let after = storage::projected(raw.as_ref()).await?;
        assert_eq!(
            after, initial,
            "{}: projected stored values",
            case["scenario"]
        );
        storage::assert_projected(&after, &case["after"]);
        if let Some(database) = database {
            assert_eq!(
                Some(storage::sqlite(database).await?),
                initial_sql,
                "{}: all stored SQLite columns",
                case["scenario"]
            );
        }
    }
    eprintln!(
        "{backend}: paired status, all headers/cookies, complete JSON response, callback/log order, zero database operations, and stored User/owner Session/Account projections. JavaScript ZodError details, statusText, JSON key order, and raw Memory table enumeration remain upstream-only; SQLite preserves all four complete local tables."
    );
    Ok(())
}

#[tokio::test]
async fn memory_malformed_verification_payload_matches_pinned_http_contract() -> TestResult {
    pairing(
        Arc::new(EphemeralStore::new(Arc::new(config()))),
        None,
        "memory",
    )
    .await
}

#[tokio::test]
async fn sqlite_malformed_verification_payload_matches_pinned_http_contract() -> TestResult {
    let database = Database::connect("sqlite::memory:").await?;
    migrator::run_migrations(&database).await?;
    pairing(
        Arc::new(SeaOrmStore::<BundledSchema>::new(
            config(),
            database.clone(),
        )),
        Some(&database),
        "sqlite",
    )
    .await?;
    database.close().await?;
    Ok(())
}
