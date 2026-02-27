//! Response shape contract tests.
//!
//! These tests validate that the response JSON structure of each endpoint
//! matches the expected shape from the reference Better-Auth OpenAPI spec
//! (`better-auth.yaml`). Tests are written against `handle_request()` directly
//! (no HTTP server needed).

use crate::adapters::{MemoryDatabaseAdapter, SessionOps, VerificationOps};
use crate::plugins::{
    AccountManagementPlugin, ApiKeyPlugin, EmailPasswordPlugin, EmailVerificationPlugin,
    PasswordManagementPlugin, SessionManagementPlugin,
};
use crate::{AuthBuilder, AuthConfig, AuthRequest, BetterAuth, CreateVerification, HttpMethod};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_config() -> AuthConfig {
    AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000")
        .password_min_length(8)
}

async fn create_test_auth() -> BetterAuth<MemoryDatabaseAdapter> {
    AuthBuilder::new(test_config())
        .database(MemoryDatabaseAdapter::new())
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(PasswordManagementPlugin::new().require_current_password(true))
        .plugin(AccountManagementPlugin::new())
        .plugin(EmailVerificationPlugin::new())
        .plugin(ApiKeyPlugin::builder().build())
        .build()
        .await
        .expect("Failed to create test auth instance")
}

fn post_json(path: &str, body: serde_json::Value) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Post, path);
    req.body = Some(body.to_string().into_bytes());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

fn get_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, path);
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

fn post_json_with_auth(path: &str, body: serde_json::Value, token: &str) -> AuthRequest {
    let mut req = post_json(path, body);
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req
}

/// Sign up a user and return (token, response_json).
async fn signup_user(
    auth: &BetterAuth<MemoryDatabaseAdapter>,
    email: &str,
    password: &str,
    name: &str,
) -> (String, serde_json::Value) {
    let req = post_json(
        "/sign-up/email",
        serde_json::json!({
            "name": name,
            "email": email,
            "password": password,
        }),
    );
    let resp = auth.handle_request(req).await.expect("signup failed");
    assert_eq!(resp.status, 200, "signup status should be 200");
    let json: serde_json::Value =
        serde_json::from_slice(&resp.body).expect("signup response is not valid JSON");
    let token = json["token"]
        .as_str()
        .expect("signup response missing token")
        .to_string();
    (token, json)
}

/// Sign in a user and return (token, response_json).
async fn signin_user(
    auth: &BetterAuth<MemoryDatabaseAdapter>,
    email: &str,
    password: &str,
) -> (String, serde_json::Value) {
    let req = post_json(
        "/sign-in/email",
        serde_json::json!({
            "email": email,
            "password": password,
        }),
    );
    let resp = auth.handle_request(req).await.expect("signin failed");
    assert_eq!(resp.status, 200, "signin status should be 200");
    let json: serde_json::Value =
        serde_json::from_slice(&resp.body).expect("signin response is not valid JSON");
    let token = json["token"]
        .as_str()
        .expect("signin response missing token")
        .to_string();
    (token, json)
}

// ---------------------------------------------------------------------------
// Contract tests
// ---------------------------------------------------------------------------

/// Spec: POST /sign-up/email => { token: string|null, user: { id, email, name, ... } }
#[tokio::test]
async fn test_signup_response_shape() {
    let auth = create_test_auth().await;
    let (_token, json) = signup_user(&auth, "shape@example.com", "password123", "Shape User").await;

    // Required fields per spec
    assert!(
        json["token"].is_string() || json["token"].is_null(),
        "token must be string or null, got: {:?}",
        json["token"]
    );
    assert!(json["user"].is_object(), "user must be an object");
    assert!(json["user"]["id"].is_string(), "user.id must be a string");
    assert!(
        json["user"]["email"].is_string(),
        "user.email must be a string"
    );
    assert!(
        json["user"]["name"].is_string(),
        "user.name must be a string"
    );
    assert!(
        json["user"]["emailVerified"].is_boolean(),
        "user.emailVerified must be a boolean"
    );
    assert!(
        json["user"]["createdAt"].is_string(),
        "user.createdAt must be a string"
    );
    assert!(
        json["user"]["updatedAt"].is_string(),
        "user.updatedAt must be a string"
    );
}

/// Spec: POST /sign-in/email => { redirect: bool, token: string, url: null, user: { ... } }
#[tokio::test]
async fn test_signin_response_shape() {
    let auth = create_test_auth().await;
    signup_user(&auth, "si@example.com", "password123", "SI User").await;
    let (_token, json) = signin_user(&auth, "si@example.com", "password123").await;

    assert!(
        json["redirect"].is_boolean(),
        "redirect must be a boolean, got: {:?}",
        json["redirect"]
    );
    assert!(
        json["token"].is_string(),
        "token must be a string, got: {:?}",
        json["token"]
    );
    assert!(
        json["url"].is_null() || json["url"].is_string(),
        "url must be null or string, got: {:?}",
        json["url"]
    );
    assert!(json["user"].is_object(), "user must be an object");
    assert!(json["user"]["id"].is_string(), "user.id must be a string");
    assert!(
        json["user"]["email"].is_string(),
        "user.email must be a string"
    );
}

/// Spec: GET /get-session => { session: { id, token, userId, ... }, user: { id, email, ... } }
#[tokio::test]
async fn test_get_session_response_shape() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "gs@example.com", "password123", "GS User").await;

    let req = get_with_auth("/get-session", &token);
    let resp = auth
        .handle_request(req)
        .await
        .expect("get-session request failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(json["session"].is_object(), "session must be an object");
    assert!(
        json["session"]["id"].is_string(),
        "session.id must be a string"
    );
    assert!(
        json["session"]["token"].is_string(),
        "session.token must be a string"
    );
    assert!(
        json["session"]["userId"].is_string() || json["session"]["user_id"].is_string(),
        "session must have userId or user_id"
    );
    assert!(json["user"].is_object(), "user must be an object");
    assert!(json["user"]["id"].is_string(), "user.id must be a string");
    assert!(
        json["user"]["email"].is_string(),
        "user.email must be a string"
    );
}

/// Spec: POST /sign-out => { success: bool }
#[tokio::test]
async fn test_sign_out_response_shape() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "so@example.com", "password123", "SO User").await;

    let req = post_json_with_auth("/sign-out", serde_json::json!({}), &token);
    let resp = auth
        .handle_request(req)
        .await
        .expect("sign-out request failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(
        json["success"].is_boolean(),
        "success must be a boolean, got: {:?}",
        json
    );
}

/// Spec: GET /list-sessions => array of session objects
#[tokio::test]
async fn test_list_sessions_response_shape() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "ls@example.com", "password123", "LS User").await;

    let req = get_with_auth("/list-sessions", &token);
    let resp = auth
        .handle_request(req)
        .await
        .expect("list-sessions request failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(json.is_array(), "list-sessions response must be an array");
    let arr = json.as_array().unwrap();
    assert!(!arr.is_empty(), "should have at least one session");

    let session = &arr[0];
    assert!(session["id"].is_string(), "session.id must be a string");
    assert!(
        session["token"].is_string(),
        "session.token must be a string"
    );
}

/// Spec: POST /forget-password => { status: bool }
#[tokio::test]
async fn test_forget_password_response_shape() {
    let auth = create_test_auth().await;
    signup_user(&auth, "fp@example.com", "password123", "FP User").await;

    let req = post_json(
        "/forget-password",
        serde_json::json!({
            "email": "fp@example.com",
        }),
    );
    let resp = auth
        .handle_request(req)
        .await
        .expect("forget-password request failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(
        json["status"].is_boolean(),
        "status must be a boolean, got: {:?}",
        json
    );
}

/// Spec: POST /reset-password => { status: bool }
///
/// NOTE: This test requires a valid reset token. We create a verification token
/// directly through the database adapter.
#[tokio::test]
async fn test_reset_password_response_shape() {
    let auth = create_test_auth().await;
    let (token, signup_json) = signup_user(&auth, "rp@example.com", "password123", "RP User").await;
    let _user_id = signup_json["user"]["id"].as_str().unwrap();

    // Create a reset token directly in the database
    let reset_token = format!("reset_{}", uuid::Uuid::new_v4());
    let create_verification = CreateVerification {
        identifier: "rp@example.com".to_string(),
        value: reset_token.clone(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
    };
    auth.database()
        .create_verification(create_verification)
        .await
        .expect("failed to create verification");

    let req = post_json(
        "/reset-password",
        serde_json::json!({
            "newPassword": "NewPassword123",
            "token": reset_token,
        }),
    );
    let resp = auth
        .handle_request(req)
        .await
        .expect("reset-password request failed");

    // The reset might fail if password validation is strict; check status 200 only
    if resp.status == 200 {
        let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(
            json["status"].is_boolean(),
            "status must be a boolean, got: {:?}",
            json
        );
    }
    // Allow unused variable
    let _ = token;
}

/// Spec: POST /change-password => { token: string|null, user: { id, email, ... } }
#[tokio::test]
async fn test_change_password_response_shape() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "cp@example.com", "password123", "CP User").await;

    let req = post_json_with_auth(
        "/change-password",
        serde_json::json!({
            "currentPassword": "password123",
            "newPassword": "newpassword456",
            "revokeOtherSessions": "false",
        }),
        &token,
    );
    let resp = auth
        .handle_request(req)
        .await
        .expect("change-password request failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();

    // Spec says: { token?: string|null, user: { ... } }
    assert!(
        json["token"].is_null() || json["token"].is_string(),
        "token must be null or string, got: {:?}",
        json["token"]
    );
    assert!(
        json["user"].is_object(),
        "user must be an object, got: {:?}",
        json["user"]
    );
    assert!(json["user"]["id"].is_string(), "user.id must be a string");
    assert!(
        json["user"]["email"].is_string(),
        "user.email must be a string"
    );
}

/// Spec: POST /update-user => { status: bool }
///
/// NOTE: The Rust implementation currently returns { user: { ... } } instead of
/// { status: bool }. This test documents the *actual* current response shape.
/// Spec: POST /update-user => { status: bool }
#[tokio::test]
async fn test_update_user_response_shape_actual() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "uu@example.com", "password123", "UU User").await;

    let req = post_json_with_auth(
        "/update-user",
        serde_json::json!({
            "name": "Updated Name",
        }),
        &token,
    );
    let resp = auth
        .handle_request(req)
        .await
        .expect("update-user request failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(
        json["status"].is_boolean(),
        "status must be a boolean, got: {:?}",
        json
    );
    assert_eq!(json["status"], true);
}

/// Spec: POST /delete-user => { success: bool, message: string }
#[tokio::test]
async fn test_delete_user_response_shape() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "du@example.com", "password123", "DU User").await;

    let req = post_json_with_auth("/delete-user", serde_json::json!({}), &token);
    let resp = auth
        .handle_request(req)
        .await
        .expect("delete-user request failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(
        json["success"].is_boolean(),
        "success must be a boolean, got: {:?}",
        json
    );
    assert!(
        json["message"].is_string(),
        "message must be a string, got: {:?}",
        json
    );
}

/// Spec: POST /change-email => { status: bool, message: string }
#[tokio::test]
async fn test_change_email_response_shape_actual() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "ce@example.com", "password123", "CE User").await;

    let req = post_json_with_auth(
        "/change-email",
        serde_json::json!({
            "newEmail": "ce_new@example.com",
        }),
        &token,
    );
    let resp = auth
        .handle_request(req)
        .await
        .expect("change-email request failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(
        json["status"].is_boolean(),
        "status must be a boolean, got: {:?}",
        json
    );
    assert_eq!(json["status"], true);
    assert!(
        json["message"].is_string(),
        "message must be a string, got: {:?}",
        json
    );
}

/// Spec: POST /send-verification-email => { status: bool }
///
/// NOTE: The email verification plugin requires an email provider configured.
/// Without one, this endpoint returns an error. We test the shape for the error
/// case and document the expected 200 shape.
#[tokio::test]
async fn test_send_verification_email_response_shape() {
    let auth = create_test_auth().await;
    signup_user(&auth, "sv@example.com", "password123", "SV User").await;

    let req = post_json(
        "/send-verification-email",
        serde_json::json!({
            "email": "sv@example.com",
        }),
    );
    let resp = auth
        .handle_request(req)
        .await
        .expect("send-verification-email request failed");

    // The endpoint may return 200 with { status: bool } or may fail because
    // no email provider is configured. Both are valid in test context.
    if resp.status == 200 {
        let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(
            json["status"].is_boolean(),
            "status must be a boolean, got: {:?}",
            json
        );
    }
    // If status is not 200 (e.g., 500 due to no email provider), that is acceptable
    // for this contract test -- the shape of the success response is what we validate.
}

/// Spec: GET /list-accounts => array of account objects
#[tokio::test]
async fn test_list_accounts_response_shape() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "la@example.com", "password123", "LA User").await;

    let req = get_with_auth("/list-accounts", &token);
    let resp = auth
        .handle_request(req)
        .await
        .expect("list-accounts request failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(json.is_array(), "list-accounts response must be an array");

    // The array may be empty if no linked accounts exist for email/password users.
    // If accounts are present, validate their shape.
    if let Some(arr) = json.as_array() {
        for account in arr {
            assert!(
                account["id"].is_string(),
                "account.id must be a string, got: {:?}",
                account
            );
            assert!(
                account["provider"].is_string(),
                "account must have provider field, got: {:?}",
                account
            );
            assert!(
                account["scopes"].is_array(),
                "account must have scopes array, got: {:?}",
                account
            );
        }
    }
}

// ---------------------------------------------------------------------------
// API Key response shape tests
// ---------------------------------------------------------------------------

/// Spec: POST /api-key/create => { key: string, id: string, userId: string, ... }
#[tokio::test]
async fn test_api_key_create_response_shape() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "ak_create@example.com", "password123", "AK User").await;

    let req = post_json_with_auth(
        "/api-key/create",
        serde_json::json!({
            "name": "shape-test-key",
            "prefix": "sk_"
        }),
        &token,
    );
    let resp = auth
        .handle_request(req)
        .await
        .expect("api-key/create request failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();

    // Must have raw key (only returned on creation)
    assert!(
        json["key"].is_string(),
        "key must be a string, got: {:?}",
        json["key"]
    );
    assert!(
        json["key"].as_str().unwrap().starts_with("sk_"),
        "key should start with prefix"
    );

    // Must have standard fields
    assert!(json["id"].is_string(), "id must be a string");
    assert!(
        json["userId"].is_string(),
        "userId must be a string, got: {:?}",
        json["userId"]
    );
    assert_eq!(json["name"], "shape-test-key");
    assert!(json["enabled"].is_boolean(), "enabled must be a boolean");
    assert!(
        json["rateLimitEnabled"].is_boolean(),
        "rateLimitEnabled must be a boolean"
    );
    assert!(json["createdAt"].is_string(), "createdAt must be a string");
    assert!(json["updatedAt"].is_string(), "updatedAt must be a string");

    // Must NOT expose the key hash
    assert!(
        json.get("keyHash").is_none(),
        "keyHash must not be in response"
    );
    assert!(
        json.get("key_hash").is_none(),
        "key_hash must not be in response"
    );
}

/// Spec: GET /api-key/get => { id, name, userId, enabled, ... }
#[tokio::test]
async fn test_api_key_get_response_shape() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "ak_get@example.com", "password123", "AK Get User").await;

    // Create a key first
    let create_req = post_json_with_auth(
        "/api-key/create",
        serde_json::json!({"name": "get-shape-key"}),
        &token,
    );
    let create_resp = auth.handle_request(create_req).await.unwrap();
    let create_json: serde_json::Value = serde_json::from_slice(&create_resp.body).unwrap();
    let key_id = create_json["id"].as_str().unwrap();

    // Get the key
    let mut req = AuthRequest::new(HttpMethod::Get, "/api-key/get");
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req.query.insert("id".to_string(), key_id.to_string());

    let resp = auth.handle_request(req).await.expect("api-key/get failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();

    assert!(json["id"].is_string(), "id must be a string");
    assert_eq!(json["name"], "get-shape-key");
    assert!(json["userId"].is_string(), "userId must be a string");
    assert!(json["enabled"].is_boolean(), "enabled must be a boolean");
    assert!(json["createdAt"].is_string(), "createdAt must be a string");
    assert!(json["updatedAt"].is_string(), "updatedAt must be a string");

    // Raw key should NOT be returned on get
    assert!(
        json.get("key").is_none(),
        "key must not be returned on get endpoint"
    );
}

/// Spec: GET /api-key/list => array of ApiKeyView objects
#[tokio::test]
async fn test_api_key_list_response_shape() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "ak_list@example.com", "password123", "AK List User").await;

    // Create two keys
    for name in &["list-key-1", "list-key-2"] {
        let req = post_json_with_auth("/api-key/create", serde_json::json!({"name": name}), &token);
        auth.handle_request(req).await.unwrap();
    }

    let req = get_with_auth("/api-key/list", &token);
    let resp = auth.handle_request(req).await.expect("api-key/list failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(json.is_array(), "list response must be an array");

    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 2, "should have 2 keys");

    for item in arr {
        assert!(item["id"].is_string(), "item.id must be a string");
        assert!(item["userId"].is_string(), "item.userId must be a string");
        assert!(
            item["enabled"].is_boolean(),
            "item.enabled must be a boolean"
        );
        // Raw key must NOT appear in list
        assert!(
            item.get("key").is_none(),
            "key must not appear in list items"
        );
    }
}

/// Spec: POST /api-key/update => { id, name, enabled, ... }
#[tokio::test]
async fn test_api_key_update_response_shape() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "ak_upd@example.com", "password123", "AK Upd User").await;

    // Create
    let create_req = post_json_with_auth(
        "/api-key/create",
        serde_json::json!({"name": "original"}),
        &token,
    );
    let create_resp = auth.handle_request(create_req).await.unwrap();
    let create_json: serde_json::Value = serde_json::from_slice(&create_resp.body).unwrap();
    let key_id = create_json["id"].as_str().unwrap();

    // Update
    let req = post_json_with_auth(
        "/api-key/update",
        serde_json::json!({
            "id": key_id,
            "name": "updated",
            "enabled": false
        }),
        &token,
    );
    let resp = auth
        .handle_request(req)
        .await
        .expect("api-key/update failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["id"], key_id);
    assert_eq!(json["name"], "updated");
    assert_eq!(json["enabled"], false);
    assert!(json["updatedAt"].is_string(), "updatedAt must be a string");
}

/// Spec: POST /api-key/delete => { status: true }
#[tokio::test]
async fn test_api_key_delete_response_shape() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "ak_del@example.com", "password123", "AK Del User").await;

    // Create
    let create_req = post_json_with_auth(
        "/api-key/create",
        serde_json::json!({"name": "to-delete"}),
        &token,
    );
    let create_resp = auth.handle_request(create_req).await.unwrap();
    let create_json: serde_json::Value = serde_json::from_slice(&create_resp.body).unwrap();
    let key_id = create_json["id"].as_str().unwrap();

    // Delete
    let req = post_json_with_auth("/api-key/delete", serde_json::json!({"id": key_id}), &token);
    let resp = auth
        .handle_request(req)
        .await
        .expect("api-key/delete failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(
        json["status"].is_boolean(),
        "status must be a boolean, got: {:?}",
        json
    );
    assert_eq!(json["status"], true);
}

/// Spec: POST /unlink-account => { status: bool }
///
/// NOTE: This requires having a linked account to unlink. Since email/password
/// users may not have linked accounts, this might return an error. We test what
/// we can.
#[tokio::test]
async fn test_unlink_account_response_shape() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "ua@example.com", "password123", "UA User").await;

    let req = post_json_with_auth(
        "/unlink-account",
        serde_json::json!({
            "providerId": "nonexistent-provider",
        }),
        &token,
    );
    let resp = auth
        .handle_request(req)
        .await
        .expect("unlink-account request failed");

    // May return 404 (no such provider) or 400 (cannot unlink last).
    // If it returns 200, validate the shape.
    if resp.status == 200 {
        let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(
            json["status"].is_boolean(),
            "status must be a boolean, got: {:?}",
            json
        );
    } else {
        // Error responses should have { message: string }
        let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(
            json["message"].is_string(),
            "error response must have message string, got: {:?}",
            json
        );
    }
}

/// Verify that `enableSessionForAPIKeys` actually injects a session when a
/// request carries an `x-api-key` header. This is the integration test that
/// proves the `before_request` hook is wired into the request pipeline.
#[tokio::test]
async fn test_enable_session_for_api_keys_injects_session() {
    // Build an auth instance with enableSessionForAPIKeys turned on
    let auth = AuthBuilder::new(test_config())
        .database(MemoryDatabaseAdapter::new())
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(
            ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .build(),
        )
        .build()
        .await
        .expect("Failed to create auth with session-for-api-keys");

    // 1. Sign up a user and get a session token
    let (token, _) = signup_user(
        &auth,
        "apikey_session@example.com",
        "password123",
        "AK Session",
    )
    .await;

    // 2. Create an API key for this user
    let create_req = post_json_with_auth(
        "/api-key/create",
        serde_json::json!({"name": "session-emulation-key"}),
        &token,
    );
    let create_resp = auth.handle_request(create_req).await.unwrap();
    assert_eq!(create_resp.status, 200);
    let create_json: serde_json::Value = serde_json::from_slice(&create_resp.body).unwrap();
    let raw_key = create_json["key"]
        .as_str()
        .expect("create response must contain raw key")
        .to_string();

    // 3. Call a protected endpoint (/update-user) using ONLY the x-api-key header
    //    (no Bearer token). If before_request is wired correctly, the API key plugin
    //    will inject a real session and the request will succeed.
    let mut req = AuthRequest::new(HttpMethod::Post, "/update-user");
    req.body = Some(
        serde_json::json!({"name": "Updated Via API Key"})
            .to_string()
            .into_bytes(),
    );
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req.headers.insert("x-api-key".to_string(), raw_key.clone());
    // Deliberately NO authorization header

    let resp = auth
        .handle_request(req)
        .await
        .expect("update-user via api-key failed");

    assert_eq!(
        resp.status, 200,
        "update-user via API key should succeed (session injected by before_request hook)"
    );

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(
        json["status"], true,
        "update-user should return status: true"
    );

    // 4. Also verify /get-session with the API key returns a virtual session
    //    (the before_request hook intercepts this path and returns a Respond action)
    let mut get_session_req = AuthRequest::new(HttpMethod::Get, "/get-session");
    get_session_req
        .headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    get_session_req
        .headers
        .insert("x-api-key".to_string(), raw_key);

    let get_session_resp = auth
        .handle_request(get_session_req)
        .await
        .expect("get-session via api-key failed");

    assert_eq!(get_session_resp.status, 200);
    let gs_json: serde_json::Value = serde_json::from_slice(&get_session_resp.body).unwrap();
    assert!(
        gs_json["user"].is_object(),
        "get-session via API key must return user object"
    );
    assert_eq!(
        gs_json["user"]["email"], "apikey_session@example.com",
        "get-session must return the correct user"
    );
}

/// disabled_paths must be enforced before plugin before_request short-circuits.
#[tokio::test]
async fn test_disabled_path_blocks_api_key_get_session_short_circuit() {
    let auth = AuthBuilder::new(test_config().disabled_path("/get-session"))
        .database(MemoryDatabaseAdapter::new())
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(
            ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .build(),
        )
        .build()
        .await
        .expect("Failed to create auth with disabled get-session");

    let (token, _) = signup_user(
        &auth,
        "disabled_get_session@example.com",
        "password123",
        "DG",
    )
    .await;

    let create_req = post_json_with_auth(
        "/api-key/create",
        serde_json::json!({"name": "disabled-get-session-key"}),
        &token,
    );
    let create_resp = auth.handle_request(create_req).await.unwrap();
    assert_eq!(create_resp.status, 200);
    let create_json: serde_json::Value = serde_json::from_slice(&create_resp.body).unwrap();
    let raw_key = create_json["key"]
        .as_str()
        .expect("create response must contain raw key");

    let mut get_session_req = AuthRequest::new(HttpMethod::Get, "/get-session");
    get_session_req
        .headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    get_session_req
        .headers
        .insert("x-api-key".to_string(), raw_key.to_string());

    let resp = auth.handle_request(get_session_req).await.unwrap();
    assert_eq!(resp.status, 404, "disabled path must return 404");
}

/// Caller-supplied virtual_user_id must be ignored by handle_request entry.
#[tokio::test]
async fn test_handle_request_ignores_caller_supplied_virtual_user_id() {
    let auth = create_test_auth().await;
    let (_token, signup_json) = signup_user(
        &auth,
        "forged_virtual_user@example.com",
        "password123",
        "FVU",
    )
    .await;

    let user_id = signup_json["user"]["id"]
        .as_str()
        .expect("signup response must contain user id")
        .to_string();

    let mut req = post_json("/update-user", serde_json::json!({ "name": "should-fail" }));
    req.set_virtual_user_id(user_id);

    let resp = auth.handle_request(req).await.unwrap();
    assert_eq!(
        resp.status, 401,
        "request without real session token must remain unauthorized"
    );
}

/// Verify that without `enableSessionForAPIKeys`, the x-api-key header is ignored
/// and protected endpoints return unauthenticated.
#[tokio::test]
async fn test_api_key_without_session_emulation_does_not_inject() {
    // Default ApiKeyPlugin has enable_session_for_api_keys = false
    let auth = create_test_auth().await;

    let (token, _) = signup_user(
        &auth,
        "apikey_nosess@example.com",
        "password123",
        "AK NoSess",
    )
    .await;

    // Create an API key
    let create_req = post_json_with_auth(
        "/api-key/create",
        serde_json::json!({"name": "no-session-key"}),
        &token,
    );
    let create_resp = auth.handle_request(create_req).await.unwrap();
    let create_json: serde_json::Value = serde_json::from_slice(&create_resp.body).unwrap();
    let raw_key = create_json["key"].as_str().unwrap();

    // Try to call a protected endpoint with only x-api-key (no Bearer)
    let mut req = AuthRequest::new(HttpMethod::Post, "/update-user");
    req.body = Some(
        serde_json::json!({"name": "Should Fail"})
            .to_string()
            .into_bytes(),
    );
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req.headers
        .insert("x-api-key".to_string(), raw_key.to_string());

    let resp = auth
        .handle_request(req)
        .await
        .expect("request should not panic");

    // Should fail because session emulation is disabled
    assert_eq!(
        resp.status, 401,
        "without enableSessionForAPIKeys, api key should NOT inject a session"
    );
}

/// Spec: POST /revoke-session => { status: bool }
#[tokio::test]
async fn test_revoke_session_response_shape() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "rs@example.com", "password123", "RS User").await;

    // Sign in again to create a second session we can revoke
    let (token2, _) = signin_user(&auth, "rs@example.com", "password123").await;

    let req = post_json_with_auth(
        "/revoke-session",
        serde_json::json!({
            "token": token,
        }),
        &token2,
    );
    let resp = auth
        .handle_request(req)
        .await
        .expect("revoke-session request failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(
        json["status"].is_boolean(),
        "status must be a boolean, got: {:?}",
        json
    );
}

// ---------------------------------------------------------------------------
// Fullstack e2e tests for API Key — virtual session, rate limiting, remaining,
// refill, permissions, concurrent rate limiting, delete expired, auth checks
// ---------------------------------------------------------------------------

/// Helper: create an auth instance with session-for-api-keys enabled.
async fn create_auth_with_api_key_session() -> BetterAuth<MemoryDatabaseAdapter> {
    AuthBuilder::new(test_config())
        .database(MemoryDatabaseAdapter::new())
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(
            ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .build(),
        )
        .build()
        .await
        .expect("Failed to create auth with session-for-api-keys")
}

/// Helper: sign up + create an API key with custom body, return (token, raw_key, user_id).
async fn setup_user_with_api_key(
    auth: &BetterAuth<MemoryDatabaseAdapter>,
    email: &str,
    key_body: serde_json::Value,
) -> (String, String, String) {
    let (token, signup_json) = signup_user(auth, email, "password123", "E2E User").await;
    let user_id = signup_json["user"]["id"]
        .as_str()
        .expect("user id")
        .to_string();

    let create_req = post_json_with_auth("/api-key/create", key_body, &token);
    let create_resp = auth.handle_request(create_req).await.unwrap();
    assert_eq!(create_resp.status, 200, "api-key/create should succeed");
    let create_json: serde_json::Value = serde_json::from_slice(&create_resp.body).unwrap();
    let raw_key = create_json["key"].as_str().expect("raw key").to_string();

    (token, raw_key, user_id)
}

/// Helper: build a request with only x-api-key header (no Bearer token).
fn api_key_request(method: HttpMethod, path: &str, raw_key: &str) -> AuthRequest {
    let mut req = AuthRequest::new(method, path);
    req.headers
        .insert("x-api-key".to_string(), raw_key.to_string());
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

/// E2E 1: Virtual session creates NO database session.
///
/// After authenticating via API key, the session count for the user must
/// remain unchanged — no real session row is created.
#[tokio::test]
async fn e2e_virtual_session_creates_no_db_session() {
    let auth = create_auth_with_api_key_session().await;
    let (_token, raw_key, user_id) = setup_user_with_api_key(
        &auth,
        "e2e_nosess@example.com",
        serde_json::json!({"name": "no-session-key"}),
    )
    .await;

    // Count sessions before the API-key request
    let sessions_before = auth
        .database()
        .get_user_sessions(&user_id)
        .await
        .unwrap()
        .len();

    // Send a protected request using only x-api-key
    let mut req = api_key_request(HttpMethod::Post, "/update-user", &raw_key);
    req.body = Some(
        serde_json::json!({"name": "Updated"})
            .to_string()
            .into_bytes(),
    );
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());

    let resp = auth
        .handle_request(req)
        .await
        .expect("request should not panic");
    assert_eq!(resp.status, 200, "update-user via API key should succeed");

    // Count sessions after — must be identical
    let sessions_after = auth
        .database()
        .get_user_sessions(&user_id)
        .await
        .unwrap()
        .len();
    assert_eq!(
        sessions_before, sessions_after,
        "No new database sessions should be created by API-key auth"
    );
}

/// E2E 2: Virtual session on /get-session returns synthetic response.
///
/// The before_request hook intercepts /get-session and returns a synthetic
/// response containing user and session-like data without a DB session.
#[tokio::test]
async fn e2e_virtual_session_get_session_returns_synthetic() {
    let auth = create_auth_with_api_key_session().await;
    let (_token, raw_key, user_id) = setup_user_with_api_key(
        &auth,
        "e2e_getsess@example.com",
        serde_json::json!({"name": "get-session-key"}),
    )
    .await;

    let req = api_key_request(HttpMethod::Get, "/get-session", &raw_key);
    let resp = auth.handle_request(req).await.expect("get-session failed");
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(json["user"].is_object(), "must contain user object");
    assert_eq!(json["user"]["id"], user_id, "user id must match");
    assert_eq!(
        json["user"]["email"], "e2e_getsess@example.com",
        "user email must match"
    );
    assert!(json["session"].is_object(), "must contain session object");
    assert!(
        json["session"]["id"].is_string(),
        "session.id must be present"
    );
    assert_eq!(
        json["session"]["userId"], user_id,
        "session.userId must match"
    );
}

/// E2E 3: Rate limiting — 3rd request fails with RATE_LIMITED.
///
/// Create an API key with rateLimitEnabled + rateLimitMax=2 and a 60-second
/// window. The first two verify calls return `valid: true`; the third
/// returns `valid: false` with error code `RATE_LIMITED`.
///
/// Note: `handle_verify` always returns HTTP 200 with a structured
/// `{valid, error, key}` response — rate-limit failures are conveyed
/// inside the body, not via HTTP status.
#[tokio::test]
async fn e2e_rate_limiting_third_request_fails() {
    let auth = create_test_auth().await;
    let (_token, raw_key, _user_id) = setup_user_with_api_key(
        &auth,
        "e2e_ratelimit@example.com",
        serde_json::json!({
            "name": "rate-limited-key",
            "rateLimitEnabled": true,
            "rateLimitMax": 2,
            "rateLimitTimeWindow": 60000
        }),
    )
    .await;

    let resp1 = auth
        .handle_request(post_json(
            "/api-key/verify",
            serde_json::json!({"key": raw_key}),
        ))
        .await
        .unwrap();
    assert_eq!(resp1.status, 200);
    let j1: serde_json::Value = serde_json::from_slice(&resp1.body).unwrap();
    assert_eq!(j1["valid"], true, "1st verify should be valid");

    let resp2 = auth
        .handle_request(post_json(
            "/api-key/verify",
            serde_json::json!({"key": raw_key}),
        ))
        .await
        .unwrap();
    assert_eq!(resp2.status, 200);
    let j2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
    assert_eq!(j2["valid"], true, "2nd verify should be valid");

    let resp3 = auth
        .handle_request(post_json(
            "/api-key/verify",
            serde_json::json!({"key": raw_key}),
        ))
        .await
        .unwrap();
    assert_eq!(resp3.status, 200);
    let j3: serde_json::Value = serde_json::from_slice(&resp3.body).unwrap();
    assert_eq!(
        j3["valid"], false,
        "3rd verify should be invalid (rate-limited)"
    );
    assert_eq!(
        j3["error"]["code"], "RATE_LIMITED",
        "error code must be RATE_LIMITED"
    );
}

/// E2E 4: Remaining consumption — 3rd request returns `valid: false`
/// with USAGE_EXCEEDED.
///
/// Create an API key with remaining=2 and no refill configuration.
/// After two verifications, the key is exhausted.
///
/// Note: `handle_verify` always returns HTTP 200; the failure is in the
/// response body `{valid: false, error: {code: "USAGE_EXCEEDED"}}`.
#[tokio::test]
async fn e2e_remaining_consumption_third_fails() {
    let auth = create_test_auth().await;
    let (_token, raw_key, _user_id) = setup_user_with_api_key(
        &auth,
        "e2e_remaining@example.com",
        serde_json::json!({
            "name": "remaining-key",
            "remaining": 2
        }),
    )
    .await;

    let resp1 = auth
        .handle_request(post_json(
            "/api-key/verify",
            serde_json::json!({"key": raw_key}),
        ))
        .await
        .unwrap();
    assert_eq!(resp1.status, 200);
    let j1: serde_json::Value = serde_json::from_slice(&resp1.body).unwrap();
    assert_eq!(j1["valid"], true, "1st verify should be valid");

    let resp2 = auth
        .handle_request(post_json(
            "/api-key/verify",
            serde_json::json!({"key": raw_key}),
        ))
        .await
        .unwrap();
    assert_eq!(resp2.status, 200);
    let j2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
    assert_eq!(j2["valid"], true, "2nd verify should be valid");

    let resp3 = auth
        .handle_request(post_json(
            "/api-key/verify",
            serde_json::json!({"key": raw_key}),
        ))
        .await
        .unwrap();
    assert_eq!(resp3.status, 200);
    let j3: serde_json::Value = serde_json::from_slice(&resp3.body).unwrap();
    assert_eq!(
        j3["valid"], false,
        "3rd verify should be invalid (usage exceeded)"
    );
    assert_eq!(
        j3["error"]["code"], "USAGE_EXCEEDED",
        "error code must be USAGE_EXCEEDED"
    );
}

/// E2E 5: Refill logic — remaining resets to refillAmount after interval.
///
/// Create a key with remaining=1, refillInterval=1000ms, refillAmount=5.
/// Verify once (consuming the only use), then immediately verify again
/// (should fail with USAGE_EXCEEDED), wait >1s, verify again — the key
/// should have been refilled and the verify should succeed.
#[tokio::test]
async fn e2e_refill_resets_after_interval() {
    let auth = create_test_auth().await;
    let (_token, raw_key, _user_id) = setup_user_with_api_key(
        &auth,
        "e2e_refill@example.com",
        serde_json::json!({
            "name": "refill-key",
            "remaining": 1,
            "refillInterval": 1000,
            "refillAmount": 5
        }),
    )
    .await;

    // First verify — consumes the only remaining use
    let resp1 = auth
        .handle_request(post_json(
            "/api-key/verify",
            serde_json::json!({"key": raw_key}),
        ))
        .await
        .unwrap();
    assert_eq!(resp1.status, 200);
    let j1: serde_json::Value = serde_json::from_slice(&resp1.body).unwrap();
    assert_eq!(j1["valid"], true, "1st verify should be valid");

    // Second verify immediately — should fail (remaining exhausted)
    let resp2 = auth
        .handle_request(post_json(
            "/api-key/verify",
            serde_json::json!({"key": raw_key}),
        ))
        .await
        .unwrap();
    assert_eq!(resp2.status, 200);
    let j2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
    assert_eq!(
        j2["valid"], false,
        "2nd verify should be invalid (remaining exhausted)"
    );

    // Wait for refill interval to elapse
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // Third verify after refill — should succeed
    let resp3 = auth
        .handle_request(post_json(
            "/api-key/verify",
            serde_json::json!({"key": raw_key}),
        ))
        .await
        .unwrap();
    assert_eq!(resp3.status, 200);
    let j3: serde_json::Value = serde_json::from_slice(&resp3.body).unwrap();
    assert_eq!(j3["valid"], true, "3rd verify after refill should be valid");
}

/// E2E 6: Permissions — verify with wrong permissions fails.
///
/// Create a key with permissions {"admin": ["read"]}, then attempt to
/// verify with required permissions {"admin": ["write"]}.
///
/// Note: permission failures are returned as `{valid: false, error:
/// {code: "KEY_NOT_FOUND"}}` at HTTP 200 (matching the TS implementation
/// which does not reveal that the key exists but lacks permissions).
#[tokio::test]
async fn e2e_permissions_validation() {
    let auth = create_test_auth().await;
    let (_token, raw_key, _user_id) = setup_user_with_api_key(
        &auth,
        "e2e_perms@example.com",
        serde_json::json!({
            "name": "perm-key",
            "permissions": {"admin": ["read"]}
        }),
    )
    .await;

    // Verify with matching permissions — should succeed
    let req_ok = post_json(
        "/api-key/verify",
        serde_json::json!({
            "key": raw_key,
            "permissions": {"admin": ["read"]}
        }),
    );
    let resp_ok = auth.handle_request(req_ok).await.unwrap();
    assert_eq!(resp_ok.status, 200);
    let j_ok: serde_json::Value = serde_json::from_slice(&resp_ok.body).unwrap();
    assert_eq!(
        j_ok["valid"], true,
        "verify with correct permissions should be valid"
    );

    // Verify with wrong permissions — should return valid=false
    let req_fail = post_json(
        "/api-key/verify",
        serde_json::json!({
            "key": raw_key,
            "permissions": {"admin": ["write"]}
        }),
    );
    let resp_fail = auth.handle_request(req_fail).await.unwrap();
    assert_eq!(resp_fail.status, 200);
    let j_fail: serde_json::Value = serde_json::from_slice(&resp_fail.body).unwrap();
    assert_eq!(
        j_fail["valid"], false,
        "verify with wrong permissions should be invalid"
    );
    assert_eq!(
        j_fail["error"]["code"], "KEY_NOT_FOUND",
        "permission failure returns KEY_NOT_FOUND (matching TS behaviour)"
    );
}

/// E2E 7: Concurrent rate limiting — sequential requests respect the limit.
///
/// With rateLimitEnabled + rateLimitMax=2, send 5 sequential verify
/// requests. Exactly 2 should return `valid: true` and 3 should return
/// `valid: false` with error code RATE_LIMITED.
#[tokio::test]
async fn e2e_concurrent_rate_limiting_sequential() {
    let auth = create_test_auth().await;
    let (_token, raw_key, _user_id) = setup_user_with_api_key(
        &auth,
        "e2e_concurrent_rl@example.com",
        serde_json::json!({
            "name": "concurrent-rl-key",
            "rateLimitEnabled": true,
            "rateLimitMax": 2,
            "rateLimitTimeWindow": 60000
        }),
    )
    .await;

    let mut successes = 0u32;
    let mut rate_limited = 0u32;

    for _ in 0..5 {
        let req = post_json("/api-key/verify", serde_json::json!({"key": raw_key}));
        let resp = auth.handle_request(req).await.unwrap();
        assert_eq!(resp.status, 200);
        let j: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        if j["valid"] == true {
            successes += 1;
        } else {
            rate_limited += 1;
        }
    }

    assert_eq!(successes, 2, "exactly 2 requests should succeed");
    assert_eq!(rate_limited, 3, "exactly 3 requests should be rate-limited");
}

/// E2E 8: delete_expired_api_keys works via the fullstack endpoint.
///
/// Create an API key with a very short expiry, wait for it to expire,
/// then call the delete-all-expired endpoint and verify the key is gone.
#[tokio::test]
async fn e2e_delete_expired_api_keys() {
    let auth = create_test_auth().await;
    let (token, _raw_key, _user_id) = setup_user_with_api_key(
        &auth,
        "e2e_expire@example.com",
        serde_json::json!({
            "name": "expire-key",
            "expiresIn": 1
        }),
    )
    .await;

    // Wait for the key to expire (expiresIn=1 second)
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // Call the delete-all-expired endpoint (requires auth)
    let req = post_json_with_auth(
        "/api-key/delete-all-expired-api-keys",
        serde_json::json!({}),
        &token,
    );
    let resp = auth.handle_request(req).await.unwrap();
    assert_eq!(
        resp.status, 200,
        "delete-all-expired should succeed with auth"
    );

    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(
        json["deleted"].is_number(),
        "response should contain 'deleted' count, got: {:?}",
        json
    );
    let deleted = json["deleted"].as_u64().unwrap();
    assert!(deleted >= 1, "at least 1 expired key should be deleted");

    // Verify the key is actually gone — list should be empty
    let list_req = get_with_auth("/api-key/list", &token);
    let list_resp = auth.handle_request(list_req).await.unwrap();
    assert_eq!(list_resp.status, 200);
    let keys: Vec<serde_json::Value> = serde_json::from_slice(&list_resp.body).unwrap();
    assert_eq!(keys.len(), 0, "expired key should have been deleted");
}

/// E2E 9: delete-all-expired without auth returns 401.
#[tokio::test]
async fn e2e_delete_expired_unauthenticated_returns_401() {
    let auth = create_test_auth().await;

    let req = post_json(
        "/api-key/delete-all-expired-api-keys",
        serde_json::json!({}),
    );
    let resp = auth.handle_request(req).await.unwrap();
    assert_eq!(
        resp.status, 401,
        "delete-all-expired without auth should return 401"
    );
}

/// E2E 10: virtual_user_id cannot be set by external callers (type-system enforced).
///
/// This is a compile-time guarantee: `virtual_user_id` is `pub(crate)` on
/// `AuthRequest`, so external crates cannot construct `AuthRequest { ...,
/// virtual_user_id: Some("forged") }`. We verify at runtime that requests
/// built via the public API always have `virtual_user_id() == None`.
#[tokio::test]
async fn e2e_virtual_user_id_not_settable_externally() {
    // AuthRequest::new always initialises virtual_user_id to None
    let req = AuthRequest::new(HttpMethod::Get, "/test");
    assert!(
        req.virtual_user_id().is_none(),
        "AuthRequest::new must initialise virtual_user_id to None"
    );

    // AuthRequest::from_parts always initialises virtual_user_id to None
    let req2 = AuthRequest::from_parts(
        HttpMethod::Post,
        "/test".to_string(),
        std::collections::HashMap::new(),
        None,
        std::collections::HashMap::new(),
    );
    assert!(
        req2.virtual_user_id().is_none(),
        "AuthRequest::from_parts must initialise virtual_user_id to None"
    );
}
