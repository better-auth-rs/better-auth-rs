use super::*;
use crate::plugins::test_helpers;
use better_auth_core::AuthContext;
use better_auth_core::config::{Argon2Config, AuthConfig, PasswordConfig};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{CreateAccount, CreateUser, CreateVerification};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

const PASSWORD_RESET_SUCCESS_MESSAGE: &str =
    "If this email exists in our system, check your email for the reset link";

struct NoopResetSender;

#[async_trait::async_trait]
impl SendResetPassword for NoopResetSender {
    async fn send(&self, _user: &serde_json::Value, _url: &str, _token: &str) -> AuthResult<()> {
        Ok(())
    }
}

fn plugin_with_reset_sender() -> PasswordManagementPlugin {
    PasswordManagementPlugin::new().send_reset_password(Arc::new(NoopResetSender))
}

async fn create_test_context_with_user() -> (AuthContext<TestSchema>, UserView, SessionView) {
    let mut config =
        AuthConfig::new("test-secret-key-at-least-32-chars-long").base_url("http://localhost:3000");
    config.session.bearer = Some(Default::default());
    config.password = PasswordConfig {
        min_length: 8,
        max_length: 128,
        require_uppercase: true,
        require_lowercase: true,
        require_numbers: true,
        require_special: true,
        argon2_config: Argon2Config::default(),
    };

    let ctx = test_helpers::create_test_context_with_config(config).await;

    // Create test user with hashed password
    let plugin = PasswordManagementPlugin::new();
    let password_hash = plugin.hash_password("Password123!").await.unwrap();

    let create_user = CreateUser::new()
        .with_email("test@example.com")
        .with_name("Test User");
    let user = test_helpers::create_user(&ctx, create_user).await;
    let _ = ctx
        .database
        .create_account(CreateAccount {
            user_id: (user.id.clone()).into(),
            account_id: (user.id.clone()).into(),
            provider_id: ("credential".to_string()).into(),
            access_token: Default::default(),
            refresh_token: Default::default(),
            id_token: Default::default(),
            access_token_expires_at: Default::default(),
            refresh_token_expires_at: Default::default(),
            scope: Default::default(),
            password: (Some(password_hash))
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            ..Default::default()
        })
        .await
        .unwrap();
    let session =
        test_helpers::create_session(&ctx, user.id.typed().unwrap().clone(), Duration::hours(24))
            .await;

    (ctx, user, session)
}

async fn create_test_context_with_oauth_only_user()
-> (AuthContext<TestSchema>, UserView, SessionView) {
    let (ctx, user, session) = create_test_context_with_user().await;

    let existing_accounts = ctx
        .database
        .get_user_accounts(user.id.typed().unwrap())
        .await
        .unwrap();
    for account in existing_accounts {
        ctx.database
            .delete_account(account.id.typed().unwrap())
            .await
            .unwrap();
    }

    let _ = ctx
        .database
        .create_account(CreateAccount {
            user_id: (user.id.clone()).into(),
            account_id: ("google-account-id".to_string()).into(),
            provider_id: ("google".to_string()).into(),
            access_token: (Some("oauth-access-token".to_string()))
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            refresh_token: (Some("oauth-refresh-token".to_string()))
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            id_token: Default::default(),
            access_token_expires_at: Default::default(),
            refresh_token_expires_at: Default::default(),
            scope: (Some("email profile".to_string()))
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            password: Default::default(),
            ..Default::default()
        })
        .await
        .unwrap();

    (ctx, user, session)
}

/// Helper: create a reset-password verification token for the given user
/// and store it in the database. Returns the token string.
async fn create_reset_token(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user_id: &str,
) -> String {
    let reset_token = uuid::Uuid::new_v4().simple().to_string();
    let create_verification = CreateVerification {
        identifier: (format!("reset-password:{}", reset_token)).into(),
        value: (user_id.to_string()).into(),
        expires_at: (Utc::now() + Duration::hours(24)).into(),
        ..Default::default()
    };
    ctx.database
        .create_verification(create_verification)
        .await
        .unwrap();
    reset_token
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_request_password_reset_success() {
    let plugin = plugin_with_reset_sender();
    let (ctx, _user, _session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "email": "test@example.com",
        "redirectTo": "http://localhost:3000/reset"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/request-password-reset",
        None,
        Some(body.to_string().into_bytes()),
    );

    let response = plugin
        .handle_request_password_reset(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body.into_bytes().unwrap()).unwrap();
    let response_data: RequestPasswordResetResponse = serde_json::from_str(&body_str).unwrap();
    assert!(response_data.status);
    assert_eq!(response_data.message, PASSWORD_RESET_SUCCESS_MESSAGE);
}

struct ResetTokenCapture(std::sync::Mutex<Option<String>>);
#[async_trait::async_trait]
impl SendResetPassword for ResetTokenCapture {
    async fn send(&self, _: &serde_json::Value, _: &str, token: &str) -> AuthResult<()> {
        *self
            .0
            .lock()
            .map_err(|_| AuthError::internal("reset token capture poisoned"))? =
            Some(token.to_owned());
        Ok(())
    }
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "the test propagates setup failures and asserts persisted token expiry"
)]
async fn request_reset_persists_omitted_zero_and_explicit_lifetimes() -> AuthResult<()> {
    let (ctx, _, _) = create_test_context_with_user().await;
    for configured in [None, Some(0.0), Some(3600.0), Some(90.0)] {
        let sender = Arc::new(ResetTokenCapture(std::sync::Mutex::new(None)));
        let plugin = PasswordManagementPlugin::with_config(PasswordManagementConfig {
            reset_password_token_expires_in: configured,
            send_reset_password: Some(sender.clone()),
            ..Default::default()
        });
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/request-password-reset",
            None,
            Some(
                serde_json::json!({"email": "test@example.com"})
                    .to_string()
                    .into_bytes(),
            ),
        );
        let before = Utc::now();
        assert_eq!(
            plugin
                .handle_request_password_reset(&req, &ctx)
                .await?
                .status,
            200
        );
        let after = Utc::now();
        let token = sender
            .0
            .lock()
            .map_err(|_| AuthError::internal("reset token capture poisoned"))?
            .clone()
            .ok_or_else(|| AuthError::internal("reset sender did not receive a token"))?;
        let stored = ctx
            .database
            .get_verification_by_identifier(&format!("reset-password:{token}"))
            .await?
            .ok_or_else(|| AuthError::internal("reset token was not persisted"))?;
        let expected = Duration::seconds(if configured == Some(90.0) { 90 } else { 3600 });
        let expires_at = stored.expires_at.typed()?;
        // Adapter dates retain the upstream millisecond precision.
        assert!(expires_at.milliseconds() >= (before + expected).timestamp_millis() as f64);
        assert!(expires_at.milliseconds() <= (after + expected).timestamp_millis() as f64);
    }
    Ok(())
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_request_password_reset_unknown_email() {
    let plugin = plugin_with_reset_sender();
    let (ctx, _user, _session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "email": "unknown@example.com"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/request-password-reset",
        None,
        Some(body.to_string().into_bytes()),
    );

    let response = plugin
        .handle_request_password_reset(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body.into_bytes().unwrap()).unwrap();
    let response_data: RequestPasswordResetResponse = serde_json::from_str(&body_str).unwrap();
    assert!(response_data.status);
    assert_eq!(response_data.message, PASSWORD_RESET_SUCCESS_MESSAGE);
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_reset_password_success() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, user, _session) = create_test_context_with_user().await;

    let reset_token = create_reset_token(&ctx, user.id.typed().unwrap()).await;

    let body = serde_json::json!({
        "newPassword": "NewPassword123!",
        "token": reset_token
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/reset-password",
        None,
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body.into_bytes().unwrap()).unwrap();
    let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
    assert!(response_data.status);

    // Verify password was updated
    let accounts = ctx
        .database
        .get_user_accounts(user.id.typed().unwrap())
        .await
        .unwrap();
    let stored_hash = accounts
        .iter()
        .find(|account| account.provider_id == "credential")
        .and_then(|account| account.password.typed().unwrap().as_deref())
        .unwrap();
    assert!(
        plugin
            .verify_password("NewPassword123!", stored_hash)
            .await
            .is_ok()
    );

    let verification_check = ctx
        .database
        .get_verification_by_identifier(&format!("reset-password:{}", reset_token))
        .await
        .unwrap();
    assert!(verification_check.is_none());
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_reset_password_invalid_token() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, _session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "newPassword": "NewPassword123!",
        "token": "invalid_token"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/reset-password",
        None,
        Some(body.to_string().into_bytes()),
    );

    let err = plugin.handle_reset_password(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_reset_password_weak_password() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, user, _session) = create_test_context_with_user().await;

    let reset_token = create_reset_token(&ctx, user.id.typed().unwrap()).await;

    let body = serde_json::json!({
        "newPassword": "weak",
        "token": reset_token
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/reset-password",
        None,
        Some(body.to_string().into_bytes()),
    );

    let err = plugin.handle_reset_password(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_change_password_success() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "currentPassword": "Password123!",
        "newPassword": "NewPassword123!",
        "revokeOtherSessions": false
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/change-password",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body.into_bytes().unwrap()).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert!(response_data["token"].is_null()); // No new token when not revoking sessions

    // Verify password was updated by checking the database directly
    let user_id = response_data["user"]["id"].as_str().unwrap();
    let accounts = ctx.database.get_user_accounts(user_id).await.unwrap();
    let stored_hash = accounts
        .iter()
        .find(|account| account.provider_id == "credential")
        .and_then(|account| account.password.typed().unwrap().as_deref())
        .unwrap();
    assert!(
        plugin
            .verify_password("NewPassword123!", stored_hash)
            .await
            .is_ok()
    );
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_change_password_with_session_revocation() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "currentPassword": "Password123!",
        "newPassword": "NewPassword123!",
        "revokeOtherSessions": true
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/change-password",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body.into_bytes().unwrap()).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert!(response_data["token"].is_string()); // New token when revoking sessions
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_change_password_sets_cookie_on_session_revocation() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "currentPassword": "Password123!",
        "newPassword": "NewPassword123!",
        "revokeOtherSessions": true
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/change-password",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
    let response = test_helpers::finalize_response(&ctx, &req, response);
    assert_eq!(response.status, 200);

    // Verify Set-Cookie header is present
    let set_cookie = response.headers.get("Set-Cookie");
    assert!(
        set_cookie.is_some(),
        "Set-Cookie header must be set when revokeOtherSessions is true"
    );

    let cookie_value = set_cookie.unwrap();
    assert!(
        cookie_value.contains(
            &ctx.config
                .auth_cookie("session_token", Default::default())
                .name
        ),
        "Cookie must contain the session cookie name"
    );
    assert!(
        cookie_value.contains("Path=/"),
        "Cookie must contain Path=/"
    );
    assert!(
        !cookie_value.contains("Expires="),
        "Cookie must omit Expires without an explicit date"
    );
    assert_eq!(
        cookie_value
            .split(';')
            .find_map(|part| part.trim().strip_prefix("Max-Age=")),
        Some("604800"),
        "Cookie must contain the upstream default session lifetime"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_change_password_no_cookie_without_revocation() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "currentPassword": "Password123!",
        "newPassword": "NewPassword123!"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/change-password",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    // Verify Set-Cookie header is NOT present when not revoking sessions
    let set_cookie = response.headers.get("Set-Cookie");
    assert!(
        set_cookie.is_none(),
        "Set-Cookie header must not be set when revokeOtherSessions is not true"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_change_password_revoke_with_boolean() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, session) = create_test_context_with_user().await;

    // Send revokeOtherSessions as a boolean (as better-auth TS SDK does)
    let body = serde_json::json!({
        "currentPassword": "Password123!",
        "newPassword": "NewPassword123!",
        "revokeOtherSessions": true
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/change-password",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body.into_bytes().unwrap()).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert!(
        response_data["token"].is_string(),
        "New token must be returned when revokeOtherSessions is boolean true"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_change_password_wrong_current_password() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "currentPassword": "WrongPassword123!",
        "newPassword": "NewPassword123!"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/change-password",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
    );

    let err = plugin.handle_change_password(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_change_password_unauthorized() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, _session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "currentPassword": "Password123!",
        "newPassword": "NewPassword123!"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/change-password",
        None,
        Some(body.to_string().into_bytes()),
    );

    let err = plugin.handle_change_password(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 401);
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: verifyPassword with
// a valid session and the correct credential password succeeds.
#[tokio::test]
async fn test_verify_password_success() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "password": "Password123!"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/verify-password",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_verify_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body.into_bytes().unwrap()).unwrap();
    let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
    assert!(response_data.status);
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: verifyPassword with
// a bad password returns BAD_REQUEST / Invalid password.
#[tokio::test]
async fn test_verify_password_invalid_password() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "password": "wrong-password"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/verify-password",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
    );

    let err = plugin.handle_verify_password(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
    assert_eq!(err.to_string(), "Invalid password");
}

// Upstream reference: packages/better-auth/src/api/routes/password.ts :: verifyPassword returns
// Invalid password when the signed-in user does not have a credential account.
#[tokio::test]
async fn test_verify_password_oauth_only_user_returns_invalid_password() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, session) = create_test_context_with_oauth_only_user().await;

    let body = serde_json::json!({
        "password": "Password123!"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/verify-password",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
    );

    let err = plugin.handle_verify_password(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
    assert_eq!(err.to_string(), "Invalid password");
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: verifyPassword
// requires an authenticated session.
#[tokio::test]
async fn test_verify_password_requires_session() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, _session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "password": "Password123!"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/verify-password",
        None,
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_verify_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 401);
    // Upstream returns better-call's default 401 body rather than an empty one.
    let body: serde_json::Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
    assert_eq!(body["code"], "UNAUTHORIZED");
    assert_eq!(body["message"], "Unauthorized");
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_reset_password_token_endpoint_redirects_with_callback_token() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, user, _session) = create_test_context_with_user().await;

    let reset_token = create_reset_token(&ctx, user.id.typed().unwrap()).await;

    let mut query = HashMap::new();
    query.insert(
        "callbackURL".to_string(),
        "http://localhost:3000/reset".to_string(),
    );

    let req = AuthRequest::from_parts(
        HttpMethod::Get,
        "/reset-password/token".to_string(),
        HashMap::new(),
        None,
        Some(serde_json::json!(query)),
    );

    let response = plugin
        .handle_reset_password_token(&reset_token, &req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 302);
    assert!(
        response.headers["Location"].contains("http://localhost:3000/reset"),
        "redirect must preserve the callback URL"
    );
    assert!(
        response.headers["Location"].contains(&format!("token={}", reset_token)),
        "redirect must contain the reset token"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_reset_password_token_endpoint_with_callback() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, user, _session) = create_test_context_with_user().await;

    let reset_token = create_reset_token(&ctx, user.id.typed().unwrap()).await;

    let mut query = HashMap::new();
    query.insert(
        "callbackURL".to_string(),
        "http://localhost:3000/reset".to_string(),
    );

    let req = AuthRequest::from_parts(
        HttpMethod::Get,
        "/reset-password/token".to_string(),
        HashMap::new(),
        None,
        Some(serde_json::json!(query)),
    );

    let response = plugin
        .handle_reset_password_token(&reset_token, &req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 302);

    // Check redirect URL
    let location_header = response
        .headers
        .iter()
        .find(|(key, _)| *key == "Location")
        .map(|(_, value)| value);
    assert!(location_header.is_some());
    assert!(
        location_header
            .unwrap()
            .contains("http://localhost:3000/reset")
    );
    assert!(location_header.unwrap().contains(&reset_token));
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_reset_password_token_endpoint_invalid_token() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, _session) = create_test_context_with_user().await;

    let mut query = HashMap::new();
    query.insert(
        "callbackURL".to_string(),
        "http://localhost:3000/reset".to_string(),
    );
    let req = AuthRequest::from_parts(
        HttpMethod::Get,
        "/reset-password/token".to_string(),
        HashMap::new(),
        None,
        Some(serde_json::json!(query)),
    );

    let response = plugin
        .handle_reset_password_token("invalid_token", &req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 302);
    assert!(response.headers["Location"].contains("error=INVALID_TOKEN"));
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_password_validation() {
    let plugin = PasswordManagementPlugin::new();
    let mut config = AuthConfig::new("test-secret");
    config.password = PasswordConfig {
        min_length: 8,
        max_length: 128,
        require_uppercase: true,
        require_lowercase: true,
        require_numbers: true,
        require_special: true,
        argon2_config: Argon2Config::default(),
    };
    let database = test_helpers::create_test_database().await;
    let ctx = AuthContext::new(Arc::new(config), database);

    // Test valid password
    assert!(plugin.validate_password("Password123!", &ctx).is_ok());

    // Test too short
    assert!(plugin.validate_password("Pass1!", &ctx).is_err());

    // Test missing uppercase
    assert!(plugin.validate_password("password123!", &ctx).is_err());

    // Test missing lowercase
    assert!(plugin.validate_password("PASSWORD123!", &ctx).is_err());

    // Test missing number
    assert!(plugin.validate_password("Password!", &ctx).is_err());

    // Test missing special character
    assert!(plugin.validate_password("Password123", &ctx).is_err());
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_password_hashing_and_verification() {
    let plugin = PasswordManagementPlugin::new();

    let password = "TestPassword123!";
    let hash = plugin.hash_password(password).await.unwrap();

    // Should verify correctly
    assert!(plugin.verify_password(password, &hash).await.is_ok());

    // Should fail with wrong password
    assert!(
        plugin
            .verify_password("WrongPassword123!", &hash)
            .await
            .is_err()
    );
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_plugin_routes() {
    let plugin = PasswordManagementPlugin::new();
    let routes = AuthPlugin::<
        better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema,
    >::routes(&plugin);

    assert_eq!(routes.len(), 5);
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/request-password-reset" && r.method == HttpMethod::Post)
    );
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/reset-password" && r.method == HttpMethod::Post)
    );
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/reset-password/{token}" && r.method == HttpMethod::Get)
    );
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/verify-password" && r.method == HttpMethod::Post)
    );
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/change-password" && r.method == HttpMethod::Post)
    );
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_plugin_on_request_routing() {
    let plugin = plugin_with_reset_sender();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let body = serde_json::json!({"email": "test@example.com"});
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/request-password-reset",
        None,
        Some(body.to_string().into_bytes()),
    );
    let response = plugin.on_request(&req, &ctx).await.unwrap();
    assert!(response.is_some());
    assert_eq!(response.unwrap().status, 200);

    // Test change password
    let body = serde_json::json!({
        "currentPassword": "Password123!",
        "newPassword": "NewPassword123!"
    });
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/change-password",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
    );
    let response = plugin.on_request(&req, &ctx).await.unwrap();
    assert!(response.is_some());
    assert_eq!(response.unwrap().status, 200);

    // Test invalid route
    let req =
        test_helpers::create_auth_request_no_query(HttpMethod::Get, "/invalid-route", None, None);
    let response = plugin.on_request(&req, &ctx).await.unwrap();
    assert!(response.is_none());
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_configuration() {
    let config = PasswordManagementConfig {
        reset_password_token_expires_in: Some(172800.0),
        require_current_password: false,
        send_email_notifications: false,
        ..Default::default()
    };

    let plugin = PasswordManagementPlugin::with_config(config);
    assert_eq!(plugin.config.reset_password_token_expires_in(), 172800.0);
    assert!(!plugin.config.require_current_password);
    assert!(!plugin.config.send_email_notifications);
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_send_reset_password_custom_sender() {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A test sender that records whether it was called.
    struct TestSender {
        called: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl SendResetPassword for TestSender {
        async fn send(
            &self,
            _user: &serde_json::Value,
            _url: &str,
            _token: &str,
        ) -> AuthResult<()> {
            self.called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    let called = Arc::new(AtomicBool::new(false));
    let sender: Arc<dyn SendResetPassword> = Arc::new(TestSender {
        called: called.clone(),
    });

    let plugin = PasswordManagementPlugin::new().send_reset_password(sender);
    let (ctx, _user, _session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "email": "test@example.com",
        "redirectTo": "http://localhost:3000/reset"
    });
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/request-password-reset",
        None,
        Some(body.to_string().into_bytes()),
    );

    let response = plugin
        .handle_request_password_reset(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    // The custom sender should have been called
    assert!(
        called.load(Ordering::SeqCst),
        "Custom send_reset_password should be invoked"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_on_password_reset_callback() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let callback_called = Arc::new(AtomicBool::new(false));
    let called_clone = callback_called.clone();

    let callback: Arc<OnPasswordResetCallback> = Arc::new(move |_user_value| {
        let called = called_clone.clone();
        Box::pin(async move {
            called.store(true, Ordering::SeqCst);
            Ok(())
        })
    });

    let plugin = PasswordManagementPlugin::new().on_password_reset(callback);
    let (mut ctx, user, _session) = create_test_context_with_user().await;

    let mut init = better_auth_core::AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
    plugin.on_init(&mut init).await.unwrap();
    ctx.password_policy = init.password_policy;

    let reset_token = create_reset_token(&ctx, user.id.typed().unwrap()).await;

    let body = serde_json::json!({
        "newPassword": "NewPassword123!",
        "token": reset_token
    });
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/reset-password",
        None,
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    // The on_password_reset callback should have been called
    assert!(
        callback_called.load(Ordering::SeqCst),
        "on_password_reset callback should be invoked after password reset"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_revoke_sessions_on_password_reset_false() {
    let plugin = PasswordManagementPlugin::new().revoke_sessions_on_password_reset(false);
    let (mut ctx, user, session) = create_test_context_with_user().await;

    let mut init = better_auth_core::AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
    plugin.on_init(&mut init).await.unwrap();
    ctx.password_policy = init.password_policy;

    let reset_token = create_reset_token(&ctx, user.id.typed().unwrap()).await;

    let body = serde_json::json!({
        "newPassword": "NewPassword123!",
        "token": reset_token
    });
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/reset-password",
        None,
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    // Session should still exist since revoke_sessions_on_password_reset=false
    let sessions = ctx
        .database
        .get_user_sessions(user.id.typed().unwrap())
        .await
        .unwrap();
    assert!(
        !sessions.is_empty(),
        "Sessions should remain when revoke_sessions_on_password_reset=false"
    );
    assert!(
        sessions.iter().any(|s| s.token == session.token),
        "The original session should still exist"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
#[tokio::test]
async fn test_revoke_sessions_on_password_reset_true() {
    let plugin = PasswordManagementPlugin::new().revoke_sessions_on_password_reset(true);
    let (mut ctx, user, _session) = create_test_context_with_user().await;

    let mut init = better_auth_core::AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
    plugin.on_init(&mut init).await.unwrap();
    ctx.password_policy = init.password_policy;

    let reset_token = create_reset_token(&ctx, user.id.typed().unwrap()).await;

    let body = serde_json::json!({
        "newPassword": "NewPassword123!",
        "token": reset_token
    });
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/reset-password",
        None,
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    // Sessions should be revoked since revoke_sessions_on_password_reset=true (default)
    let sessions = ctx
        .database
        .get_user_sessions(user.id.typed().unwrap())
        .await
        .unwrap();
    assert!(
        sessions.is_empty(),
        "Sessions should be revoked when revoke_sessions_on_password_reset=true"
    );
}
