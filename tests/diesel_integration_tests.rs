//! End-to-end requests through `BetterAuth` backed by `DieselStore`.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "integration tests fail fast on fixture setup and index into response JSON"
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth::plugins::{
    ApiKeyPlugin, EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin,
};
use better_auth::prelude::{AuthRequest, CreateUser, HttpMethod};
use better_auth::{AuthConfig, AuthResult, BetterAuth};
use better_auth_diesel::diesel_async::AsyncMigrationHarness;
use better_auth_diesel::diesel_migrations::MigrationHarness;
use better_auth_diesel::{
    DieselAuthSchema, DieselHookContext, DieselHooks, DieselPool, DieselStore, HookControl,
};
use serde_json::Value;

type TestAuth = BetterAuth<DieselAuthSchema>;

fn test_config() -> AuthConfig {
    let mut config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000");
    config.session.bearer = Some(Default::default());
    config
}

async fn test_pool() -> DieselPool {
    let pool = DieselPool::sqlite(":memory:").expect("sqlite pool should build");
    let sqlite = pool
        .as_sqlite()
        .expect("DieselPool::sqlite builds a SQLite pool");
    let mut harness = AsyncMigrationHarness::new(sqlite.get().await.expect("connection"));
    let _ = harness
        .run_pending_migrations(better_auth_diesel::migrations::SQLITE)
        .expect("sqlite migrations should run");
    pool
}

/// Records the request path seen by `before_create_user`.
#[derive(Clone, Default)]
struct RequestPathHook {
    paths: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl DieselHooks for RequestPathHook {
    async fn before_create_user(
        &self,
        _user: &mut CreateUser,
        ctx: &DieselHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let path = ctx
            .request
            .as_ref()
            .map(|request| request.path.clone())
            .unwrap_or_default();
        self.paths.lock().expect("hook mutex").push(path);
        Ok(HookControl::Continue)
    }
}

async fn build_auth(hook: RequestPathHook) -> TestAuth {
    let config = test_config();
    let store = DieselStore::new(config.clone(), test_pool().await).hook(hook);
    BetterAuth::<DieselAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(OrganizationPlugin::new())
        .plugin(ApiKeyPlugin::builder().build())
        .build()
        .await
        .expect("auth should build")
}

fn request(
    method: HttpMethod,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> AuthRequest {
    let mut request = AuthRequest::new(method, path);
    let _ = request
        .headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    if let Some(token) = token {
        let _ = request
            .headers
            .insert("authorization".to_string(), format!("Bearer {token}"));
    }
    if let Some(body) = body {
        request.body = Some(body.to_string().into_bytes());
        let _ = request
            .headers
            .insert("content-type".to_string(), "application/json".to_string());
    }
    request
}

async fn send(auth: &TestAuth, request: AuthRequest) -> (u16, Value) {
    let response = auth
        .handle_request(request)
        .await
        .expect("request should produce a response");
    let body = if response.body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&response.body).expect("response body should be JSON")
    };
    (response.status, body)
}

async fn sign_up(auth: &TestAuth, email: &str) -> String {
    let (status, body) = send(
        auth,
        request(
            HttpMethod::Post,
            "/sign-up/email",
            None,
            Some(serde_json::json!({
                "name": "Test User",
                "email": email,
                "password": "Password123!",
            })),
        ),
    )
    .await;
    assert_eq!(status, 200, "sign-up failed: {body}");
    body["token"].as_str().expect("sign-up token").to_owned()
}

// Rust-specific surface: `DieselStore` is a Rust persistence integration; the
// session flow it serves is the one exercised against the TS reference server.
#[tokio::test(flavor = "multi_thread")]
async fn diesel_store_serves_the_email_password_session_lifecycle() {
    let hook = RequestPathHook::default();
    let auth = build_auth(hook.clone()).await;

    let sign_up_token = sign_up(&auth, "Ada@Example.com").await;
    assert_eq!(
        hook.paths.lock().expect("hook mutex").as_slice(),
        ["/sign-up/email"]
    );

    let (status, session) = send(
        &auth,
        request(HttpMethod::Get, "/get-session", Some(&sign_up_token), None),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(session["user"]["email"], "ada@example.com");

    let (status, body) = send(
        &auth,
        request(
            HttpMethod::Post,
            "/sign-in/email",
            None,
            Some(serde_json::json!({
                "email": "ada@example.com",
                "password": "Password123!",
            })),
        ),
    )
    .await;
    assert_eq!(status, 200, "sign-in failed: {body}");
    let sign_in_token = body["token"].as_str().expect("sign-in token").to_owned();

    let (status, sessions) = send(
        &auth,
        request(
            HttpMethod::Get,
            "/list-sessions",
            Some(&sign_in_token),
            None,
        ),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(sessions.as_array().map(Vec::len), Some(2));

    let (status, _) = send(
        &auth,
        request(
            HttpMethod::Post,
            "/sign-out",
            Some(&sign_in_token),
            Some(serde_json::json!({})),
        ),
    )
    .await;
    assert_eq!(status, 200);

    let (status, session) = send(
        &auth,
        request(HttpMethod::Get, "/get-session", Some(&sign_in_token), None),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        session.is_null(),
        "signed-out session should be gone: {session}"
    );
}

// Rust-specific surface: `DieselStore` persistence for the organization and
// API-key plugin tables.
#[tokio::test(flavor = "multi_thread")]
async fn diesel_store_serves_organization_and_api_key_plugins() {
    let auth = build_auth(RequestPathHook::default()).await;
    let token = sign_up(&auth, "owner@example.com").await;

    let (status, organization) = send(
        &auth,
        request(
            HttpMethod::Post,
            "/organization/create",
            Some(&token),
            Some(serde_json::json!({ "name": "Acme", "slug": "acme" })),
        ),
    )
    .await;
    assert_eq!(status, 200, "create organization failed: {organization}");
    assert_eq!(organization["slug"], "acme");

    let (status, organizations) = send(
        &auth,
        request(HttpMethod::Get, "/organization/list", Some(&token), None),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(organizations[0]["id"], organization["id"]);

    let (status, key) = send(
        &auth,
        request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&token),
            Some(serde_json::json!({ "name": "ci", "prefix": "sk_" })),
        ),
    )
    .await;
    assert_eq!(status, 200, "create api key failed: {key}");
    assert!(
        key["key"]
            .as_str()
            .is_some_and(|key| key.starts_with("sk_"))
    );

    let (status, keys) = send(
        &auth,
        request(HttpMethod::Get, "/api-key/list", Some(&token), None),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        keys.to_string()
            .contains(key["id"].as_str().expect("key id")),
        "listed keys should include the new key: {keys}"
    );
}
