//! Auth setup, HTTP request builders, and signup/signin helpers.

use better_auth::{
    AuthBuilder, AuthConfig, BetterAuth, MemoryDatabaseAdapter,
    plugins::{
        AccountManagementPlugin, ApiKeyPlugin, EmailPasswordPlugin, EmailVerificationPlugin,
        OAuthPlugin, PasswordManagementPlugin, SessionManagementPlugin, TwoFactorPlugin,
    },
    types::{AuthRequest, HttpMethod},
};
use serde_json::Value;

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
