//! Unified test harness for `better-auth-rs`.
//!
//! Provides:
//! - [`TestHarness`]: ergonomic wrapper around `BetterAuth` with request
//!   builders, response parsing, and user lifecycle helpers.
//! - Standalone request builder functions for use in existing tests.
//! - [`unique_email`]: atomic counter-based email generator to avoid
//!   hard-coded test emails.

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
#[allow(dead_code)]
pub fn unique_email(prefix: &str) -> String {
    let n = EMAIL_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{n}@test.com")
}

// ---------------------------------------------------------------------------
// Standalone request builders
// ---------------------------------------------------------------------------

/// Build a POST request with a JSON body and `content-type` header.
#[allow(dead_code)]
pub fn post_json(path: &str, body: Value) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Post, path);
    req.body = Some(body.to_string().into_bytes());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    req
}

/// Build a bare GET request (no auth, no origin).
#[allow(dead_code)]
pub fn get_request(path: &str) -> AuthRequest {
    AuthRequest::new(HttpMethod::Get, path)
}

/// Build an authenticated GET request.
#[allow(dead_code)]
pub fn get_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = get_request(path);
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req
}

/// Build an authenticated POST request with a JSON body.
#[allow(dead_code)]
pub fn post_json_with_auth(path: &str, body: Value, token: &str) -> AuthRequest {
    let mut req = post_json(path, body);
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req
}

/// Build an authenticated POST request with an empty `{}` body (no content-type).
///
/// Matches the pattern used by many integration tests for action endpoints
/// like `/sign-out`, `/revoke-sessions`, `/delete-user`, etc.
#[allow(dead_code)]
pub fn post_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Post, path);
    req.body = Some(b"{}".to_vec());
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req
}

/// Build a DELETE request with auth.
#[allow(dead_code)]
pub fn delete_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Delete, path);
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req
}

/// Send a request through a `BetterAuth` instance and return
/// `(status_code, parsed_json_body)`.
#[allow(dead_code)]
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
#[allow(dead_code)]
pub struct TestHarness {
    auth: Arc<BetterAuth<MemoryDatabaseAdapter>>,
}

#[allow(dead_code)]
impl TestHarness {
    /// Create a harness with **all** plugins enabled (suitable for compat and
    /// comprehensive integration tests).
    pub async fn new() -> Self {
        let config = AuthConfig::new("test-only-key-not-a-real-secret-32ch")
            .base_url("http://localhost:3000")
            .password_min_length(8);
        let auth = AuthBuilder::new(config)
            .database(MemoryDatabaseAdapter::new())
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(PasswordManagementPlugin::new().require_current_password(true))
            .plugin(AccountManagementPlugin::new())
            .plugin(EmailVerificationPlugin::new())
            .plugin(ApiKeyPlugin::builder().build())
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
            .expect("Failed to create test auth instance");
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
            .plugin(ApiKeyPlugin::builder().build())
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
    // Request builders (instance methods add `origin` header for CSRF)
    // -------------------------------------------------------------------

    /// Build a GET request (with `origin` header).
    pub fn get(&self, path: &str) -> AuthRequest {
        let mut req = get_request(path);
        req.headers
            .insert("origin".to_string(), "http://localhost:3000".to_string());
        req
    }

    /// Build an authenticated GET request (with `origin` header).
    pub fn authed_get(&self, path: &str, token: &str) -> AuthRequest {
        let mut req = get_with_auth(path, token);
        req.headers
            .insert("origin".to_string(), "http://localhost:3000".to_string());
        req
    }

    /// Build a POST request with a JSON body (with `origin` header).
    pub fn post(&self, path: &str, body: Value) -> AuthRequest {
        let mut req = post_json(path, body);
        req.headers
            .insert("origin".to_string(), "http://localhost:3000".to_string());
        req
    }

    /// Build an authenticated POST request with a JSON body (with `origin`
    /// header).
    pub fn authed_post(&self, path: &str, body: Value, token: &str) -> AuthRequest {
        let mut req = post_json_with_auth(path, body, token);
        req.headers
            .insert("origin".to_string(), "http://localhost:3000".to_string());
        req
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
