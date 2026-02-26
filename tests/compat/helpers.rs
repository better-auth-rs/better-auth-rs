//! Auth setup, HTTP request builders, and signup/signin helpers.
//!
//! This is the **canonical** location for all shared test utilities.
//! All integration test files should use `use compat::helpers::*;`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use better_auth::{
    AuthBuilder, AuthConfig, BetterAuth, MemoryDatabaseAdapter,
    plugins::{
        AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, EmailPasswordPlugin,
        EmailVerificationPlugin, OAuthPlugin, OrganizationPlugin, PasskeyPlugin,
        PasswordManagementPlugin, SessionManagementPlugin, TwoFactorPlugin,
    },
    types::{AuthRequest, HttpMethod},
};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Unique email generator
// ---------------------------------------------------------------------------

static EMAIL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique email address for testing, avoiding hard-coded collisions.
pub fn unique_email(prefix: &str) -> String {
    let n = EMAIL_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{n}_{}@test.com", std::process::id())
}

// ---------------------------------------------------------------------------
// Auth setup
// ---------------------------------------------------------------------------

/// Generate a deterministic test-only key (not a real secret).
pub fn test_secret() -> String {
    "t]e]s]t]-]o]n]l]y]-]k]e]y]-]n]o]t]-]a]-]r]e]a]l]-]s]e]c]r]e]t]-]3]2]c]h".replace(']', "")
}

pub fn test_config() -> AuthConfig {
    AuthConfig::new(&test_secret())
        .base_url("http://localhost:3000")
        .password_min_length(8)
}

pub async fn create_test_auth() -> BetterAuth<MemoryDatabaseAdapter> {
    AuthBuilder::new(test_config())
        .database(MemoryDatabaseAdapter::new())
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(PasswordManagementPlugin::new().require_current_password(true))
        .plugin(AccountManagementPlugin::new())
        .plugin(EmailVerificationPlugin::new())
        .plugin(ApiKeyPlugin::new())
        .plugin(OAuthPlugin::new())
        .plugin(TwoFactorPlugin::new())
        .plugin(OrganizationPlugin::new())
        .plugin(
            PasskeyPlugin::new()
                .rp_id("localhost")
                .rp_name("Better Auth Test")
                .origin("http://localhost:3000")
                .allow_insecure_unverified_assertion(true),
        )
        .plugin(AdminPlugin::new())
        .build()
        .await
        .expect("Failed to create test auth instance")
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

pub fn post_json(path: &str, body: Value) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Post, path);
    req.body = Some(body.to_string().into_bytes());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

pub fn get_request(path: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, path);
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

pub fn get_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, path);
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

pub fn get_with_auth_and_query(path: &str, token: &str, query: Vec<(&str, &str)>) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, path);
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    for (k, v) in query {
        req.query.insert(k.to_string(), v.to_string());
    }
    req
}

pub fn post_json_with_auth(path: &str, body: Value, token: &str) -> AuthRequest {
    let mut req = post_json(path, body);
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req
}

pub fn delete_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Delete, path);
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

/// Build an authenticated POST request with an empty `{}` body (no content-type).
///
/// Matches the pattern used by many integration tests for action endpoints
/// like `/sign-out`, `/revoke-sessions`, `/delete-user`, etc.
pub fn post_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Post, path);
    req.body = Some(b"{}".to_vec());
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

// ---------------------------------------------------------------------------
// Send / signup / signin
// ---------------------------------------------------------------------------

pub async fn send_request(
    auth: &BetterAuth<MemoryDatabaseAdapter>,
    req: AuthRequest,
) -> (u16, Value) {
    let resp = auth
        .handle_request(req)
        .await
        .expect("Request should not panic");
    let status = resp.status;
    let json: Value = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&resp.body).to_string()));
    (status, json)
}

pub async fn signup_user(
    auth: &BetterAuth<MemoryDatabaseAdapter>,
    email: &str,
    password: &str,
    name: &str,
) -> (String, Value) {
    let req = post_json(
        "/sign-up/email",
        serde_json::json!({
            "name": name,
            "email": email,
            "password": password,
        }),
    );
    let (status, json) = send_request(auth, req).await;
    assert_eq!(
        status, 200,
        "signup should succeed, got status {}: {}",
        status, json
    );
    let token = json["token"]
        .as_str()
        .expect("signup response missing token")
        .to_string();
    (token, json)
}

pub async fn signin_user(
    auth: &BetterAuth<MemoryDatabaseAdapter>,
    email: &str,
    password: &str,
) -> (String, Value) {
    let req = post_json(
        "/sign-in/email",
        serde_json::json!({
            "email": email,
            "password": password,
        }),
    );
    let (status, json) = send_request(auth, req).await;
    assert_eq!(
        status, 200,
        "signin should succeed, got status {}: {}",
        status, json
    );
    let token = json["token"]
        .as_str()
        .expect("signin response missing token")
        .to_string();
    (token, json)
}

// ---------------------------------------------------------------------------
// TestHarness
// ---------------------------------------------------------------------------

/// Unified test harness wrapping `BetterAuth` with ergonomic helpers.
///
/// # Examples
///
/// ```rust,ignore
/// let h = TestHarness::new().await;
/// let (token, _) = h.signup("alice@test.com", "password123", "Alice").await;
/// let (status, body) = h.send(h.authed_get("/get-session", &token)).await;
/// assert_eq!(status, 200);
/// ```
pub struct TestHarness {
    auth: Arc<BetterAuth<MemoryDatabaseAdapter>>,
}

impl TestHarness {
    /// Create a harness with **all** plugins enabled (suitable for compat and
    /// comprehensive integration tests).
    pub async fn new() -> Self {
        let auth = create_test_auth().await;
        Self {
            auth: Arc::new(auth),
        }
    }

    /// Create a harness with a **minimal** plugin set matching
    /// `integration_tests.rs` conventions (EmailPassword, SessionManagement,
    /// PasswordManagement, AccountManagement, ApiKey).
    pub async fn minimal() -> Self {
        let config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
            .base_url("http://localhost:3000")
            .password_min_length(6);
        let auth = AuthBuilder::new(config)
            .database(MemoryDatabaseAdapter::new())
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(PasswordManagementPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .plugin(ApiKeyPlugin::new())
            .build()
            .await
            .expect("Failed to create test auth instance");
        Self {
            auth: Arc::new(auth),
        }
    }

    /// Wrap an existing `Arc<BetterAuth>` in a harness.
    pub fn from_arc(auth: Arc<BetterAuth<MemoryDatabaseAdapter>>) -> Self {
        Self { auth }
    }

    /// Access the inner `BetterAuth` reference.
    pub fn auth(&self) -> &BetterAuth<MemoryDatabaseAdapter> {
        &self.auth
    }

    /// Consume the harness and return the inner `Arc`.
    pub fn into_arc(self) -> Arc<BetterAuth<MemoryDatabaseAdapter>> {
        self.auth
    }

    // -------------------------------------------------------------------
    // Request builders (instance methods delegate to helpers that include
    // `origin` header for CSRF by default)
    // -------------------------------------------------------------------

    /// Build a GET request (with `origin` header).
    pub fn get(&self, path: &str) -> AuthRequest {
        get_request(path)
    }

    /// Build an authenticated GET request (with `origin` header).
    pub fn authed_get(&self, path: &str, token: &str) -> AuthRequest {
        get_with_auth(path, token)
    }

    /// Build a POST request with a JSON body (with `origin` header).
    pub fn post(&self, path: &str, body: Value) -> AuthRequest {
        post_json(path, body)
    }

    /// Build an authenticated POST request with a JSON body (with `origin`
    /// header).
    pub fn authed_post(&self, path: &str, body: Value, token: &str) -> AuthRequest {
        post_json_with_auth(path, body, token)
    }

    // -------------------------------------------------------------------
    // Send
    // -------------------------------------------------------------------

    /// Send a request and return `(status_code, parsed_json_body)`.
    pub async fn send(&self, req: AuthRequest) -> (u16, Value) {
        send_request(&self.auth, req).await
    }

    // -------------------------------------------------------------------
    // User lifecycle
    // -------------------------------------------------------------------

    /// Sign up a new user. Returns `(token, response_json)`.
    pub async fn signup(&self, email: &str, password: &str, name: &str) -> (String, Value) {
        let req = self.post(
            "/sign-up/email",
            serde_json::json!({ "name": name, "email": email, "password": password }),
        );
        let (status, json) = self.send(req).await;
        assert_eq!(
            status, 200,
            "signup should succeed, got status {}: {}",
            status, json
        );
        let token = json["token"]
            .as_str()
            .expect("signup response missing token")
            .to_string();
        (token, json)
    }

    /// Sign in an existing user. Returns `(token, response_json)`.
    pub async fn signin(&self, email: &str, password: &str) -> (String, Value) {
        let req = self.post(
            "/sign-in/email",
            serde_json::json!({ "email": email, "password": password }),
        );
        let (status, json) = self.send(req).await;
        assert_eq!(
            status, 200,
            "signin should succeed, got status {}: {}",
            status, json
        );
        let token = json["token"]
            .as_str()
            .expect("signin response missing token")
            .to_string();
        (token, json)
    }

    /// Create a test user with a unique email and return `(user_id, session_token)`.
    pub async fn create_user_with_session(&self) -> (String, String) {
        let email = unique_email("harness");
        let (token, json) = self.signup(&email, "password123", "Test User").await;
        let user_id = json["user"]["id"]
            .as_str()
            .expect("missing user id")
            .to_string();
        (user_id, token)
    }
}
