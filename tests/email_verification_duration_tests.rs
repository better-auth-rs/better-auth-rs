#![cfg(feature = "seaorm2")]
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "The endpoint contract fails immediately on missing captured tokens or fixture fields"
)]

use async_trait::async_trait;
use better_auth::{AuthConfig, BetterAuth, plugins::EmailVerificationPlugin};
use better_auth_core::{
    AuthRequest, AuthResult, AuthSchema, AuthStore, CreateUser, HttpMethod,
    email::SendVerificationEmail, store::EphemeralStore, wire::UserView,
};
use better_auth_seaorm::{
    Database, SeaOrmStore,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::Duration;
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
const ORIGIN: &str = "http://email-verification-duration.test";
const EMAIL: &str = "owner@email-verification-duration.test";

#[derive(Default)]
struct Sender(Mutex<Vec<String>>);

#[async_trait]
impl SendVerificationEmail for Sender {
    async fn send(&self, _: &UserView, _: &str, token: &str) -> AuthResult<()> {
        self.0
            .lock()
            .expect("Delivered email tokens")
            .push(token.to_owned());
        Ok(())
    }
}

fn config() -> AuthConfig {
    let mut config =
        AuthConfig::new("email-verification-duration-contract-secret-at-least-32-characters")
            .base_url(ORIGIN);
    config.telemetry.enabled = false;
    config.logger.disabled = Some(true);
    config.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
        enabled: Some(false),
        ..Default::default()
    });
    config
}

fn request(method: HttpMethod, path: &str) -> AuthRequest {
    let mut request = AuthRequest::new(method, path);
    let _ = request.headers.insert("origin".into(), ORIGIN.into());
    request
}

async fn zero_duration<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, backend: &str) -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/email-verification-duration-1.7.6.json"
    ))?;
    let case = fixture["cases"]
        .as_array()
        .expect("Captured duration cases")
        .iter()
        .find(|case| case["backend"] == backend && case["scenario"]["name"] == "zero-immediate")
        .expect("Captured zero-duration backend");
    let sender = Arc::new(Sender::default());
    let hooks = Arc::new(AtomicUsize::new(0));
    let before = hooks.clone();
    let after = hooks.clone();
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .rate_limit(better_auth_core::middleware::RateLimitConfig {
            enabled: Some(false),
            ..Default::default()
        })
        .plugin(
            EmailVerificationPlugin::new()
                .verification_token_expiry(Duration::zero())
                .auto_sign_in_after_verification(true)
                .custom_send_verification_email(sender.clone())
                .before_email_verification(Arc::new(move |_| {
                    before.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async { Ok(()) })
                }))
                .after_email_verification(Arc::new(move |_| {
                    after.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async { Ok(()) })
                })),
        )
        .build()
        .await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email(EMAIL)
                .with_name("Email Duration"),
        )
        .await?;
    let stored = serde_json::to_value(raw.get_user_by_email(EMAIL).await?)?;
    let mut send = request(HttpMethod::Post, "/api/auth/send-verification-email");
    let _ = send
        .headers
        .insert("content-type".into(), "application/json".into());
    send.body = Some(serde_json::to_vec(&json!({"email": EMAIL}))?);
    let sent = auth.handle_request(send).await?;
    assert_eq!(u64::from(sent.status), case["send"]["response"]["status"]);
    assert_eq!(
        serde_json::from_slice::<Value>(&sent.body.bytes()?)?,
        json!({"status": true})
    );
    assert!(sent.headers.get_all("set-cookie").next().is_none());
    let token = {
        let tokens = sender.0.lock().expect("Delivered email tokens");
        assert_eq!(tokens.len(), 1);
        tokens[0].clone()
    };
    let mut verify = request(HttpMethod::Get, "/api/auth/verify-email");
    verify.query = Some(json!({"token": token}));
    let response = auth.handle_request(verify).await?;
    assert_eq!(
        u64::from(response.status),
        case["verify"]["response"]["status"]
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body.bytes()?)?,
        serde_json::from_str::<Value>(
            case["verify"]["response"]["body"]
                .as_str()
                .expect("Captured error body")
        )?,
    );
    assert!(response.headers.get_all("set-cookie").next().is_none());
    assert_eq!(
        serde_json::to_value(raw.get_user_by_email(EMAIL).await?)?,
        stored
    );
    assert!(raw.get_user_sessions(owner.id.typed()?).await?.is_empty());
    assert!(raw.get_user_accounts(owner.id.typed()?).await?.is_empty());
    assert_eq!(hooks.load(Ordering::SeqCst), 0);
    assert_eq!(sender.0.lock().expect("Delivered email tokens").len(), 1);
    eprintln!(
        "{backend}: zero-duration HTTP rejection, cookies, unchanged user, and absent sessions are paired; fixed-clock successful HTTP flows remain unpaired"
    );
    Ok(())
}

#[tokio::test]
async fn memory_zero_duration_email_verification_matches_pinned_http_rejection() -> TestResult {
    zero_duration(Arc::new(EphemeralStore::new(Arc::new(config()))), "memory").await
}

#[tokio::test]
async fn sqlite_zero_duration_email_verification_matches_pinned_http_rejection() -> TestResult {
    let database = Database::connect("sqlite::memory:").await?;
    migrator::run_migrations(&database).await?;
    zero_duration(
        Arc::new(SeaOrmStore::<BundledSchema>::new(
            config(),
            database.clone(),
        )),
        "sqlite",
    )
    .await?;
    database.close().await?;
    Ok(())
}
