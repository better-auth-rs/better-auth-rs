use super::*;
use crate::plugins::test_helpers;
use better_auth_core::adapters::{MemoryDatabaseAdapter, SessionOps, UserOps, VerificationOps};
use better_auth_core::config::{Argon2Config, AuthConfig, PasswordConfig};
use better_auth_core::{CreateUser, CreateVerification, PASSWORD_HASH_KEY, Session, User};
use chrono::{Duration, Utc};
use std::collections::HashMap;

async fn create_test_context_with_user() -> (AuthContext<MemoryDatabaseAdapter>, User, Session) {
    let mut config = AuthConfig::new("test-secret-key-at-least-32-chars-long");
    config.password = PasswordConfig {
        min_length: 8,
        require_uppercase: true,
        require_lowercase: true,
        require_numbers: true,
        require_special: true,
        argon2_config: Argon2Config::default(),
    };

    let ctx = test_helpers::create_test_context_with_config(config);

    // Create test user with hashed password
    let plugin = PasswordManagementPlugin::new();
    let password_hash = plugin.hash_password("Password123!").await.unwrap();

    let metadata = {
        let mut m = serde_json::Map::new();
        m.insert(
            PASSWORD_HASH_KEY.to_string(),
            serde_json::Value::String(password_hash),
        );
        serde_json::Value::Object(m)
    };

    let create_user = CreateUser::new()
        .with_email("test@example.com")
        .with_name("Test User")
        .with_metadata(metadata);
    let user = test_helpers::create_user(&ctx, create_user).await;
    let session = test_helpers::create_session(&ctx, user.id.clone(), Duration::hours(24)).await;

    (ctx, user, session)
}

/// Helper: create a reset-password verification token for the given user
/// email and store it in the database. Returns the token string.
async fn create_reset_token(ctx: &AuthContext<MemoryDatabaseAdapter>, email: &str) -> String {
    let reset_token = format!("reset_{}", uuid::Uuid::new_v4());
    let create_verification = CreateVerification {
        identifier: email.to_string(),
        value: reset_token.clone(),
        expires_at: Utc::now() + Duration::hours(24),
    };
    ctx.database
        .create_verification(create_verification)
        .await
        .unwrap();
    reset_token
}

#[tokio::test]
async fn test_forget_password_success() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, _session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "email": "test@example.com",
        "redirectTo": "http://localhost:3000/reset"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/forget-password",
        None,
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_forget_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
    assert!(response_data.status);
}

#[tokio::test]
async fn test_forget_password_unknown_email() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, _session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "email": "unknown@example.com"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/forget-password",
        None,
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_forget_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    // Should return success even for unknown emails (security)
    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
    assert!(response_data.status);
}

#[tokio::test]
async fn test_reset_password_success() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, user, _session) = create_test_context_with_user().await;

    let reset_token = create_reset_token(&ctx, user.email.as_deref().unwrap()).await;

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

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
    assert!(response_data.status);

    // Verify password was updated
    let updated_user = ctx
        .database
        .get_user_by_id(&user.id)
        .await
        .unwrap()
        .unwrap();
    let stored_hash = updated_user
        .metadata
        .get(PASSWORD_HASH_KEY)
        .unwrap()
        .as_str()
        .unwrap();
    assert!(
        plugin
            .verify_password("NewPassword123!", stored_hash)
            .await
            .is_ok()
    );

    // Verify token was deleted
    let verification_check = ctx
        .database
        .get_verification_by_value(&reset_token)
        .await
        .unwrap();
    assert!(verification_check.is_none());
}

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

#[tokio::test]
async fn test_reset_password_weak_password() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, user, _session) = create_test_context_with_user().await;

    let reset_token = create_reset_token(&ctx, user.email.as_deref().unwrap()).await;

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

#[tokio::test]
async fn test_change_password_success() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "currentPassword": "Password123!",
        "newPassword": "NewPassword123!",
        "revokeOtherSessions": "false"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/change-password",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert!(response_data["token"].is_null()); // No new token when not revoking sessions

    // Verify password was updated by checking the database directly
    let user_id = response_data["user"]["id"].as_str().unwrap();
    let updated_user = ctx.database.get_user_by_id(user_id).await.unwrap().unwrap();
    let stored_hash = updated_user
        .metadata
        .get(PASSWORD_HASH_KEY)
        .unwrap()
        .as_str()
        .unwrap();
    assert!(
        plugin
            .verify_password("NewPassword123!", stored_hash)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_change_password_with_session_revocation() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let body = serde_json::json!({
        "currentPassword": "Password123!",
        "newPassword": "NewPassword123!",
        "revokeOtherSessions": "true"
    });

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/change-password",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert!(response_data["token"].is_string()); // New token when revoking sessions
}

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
    assert_eq!(response.status, 200);

    // Verify Set-Cookie header is present
    let set_cookie = response.headers.get("Set-Cookie");
    assert!(
        set_cookie.is_some(),
        "Set-Cookie header must be set when revokeOtherSessions is true"
    );

    let cookie_value = set_cookie.unwrap();
    assert!(
        cookie_value.contains(&ctx.config.session.cookie_name),
        "Cookie must contain the session cookie name"
    );
    assert!(
        cookie_value.contains("Path=/"),
        "Cookie must contain Path=/"
    );
    assert!(
        cookie_value.contains("Expires="),
        "Cookie must contain an expiration"
    );
}

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

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert!(
        response_data["token"].is_string(),
        "New token must be returned when revokeOtherSessions is boolean true"
    );
}

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
    assert_eq!(err.status_code(), 401);
}

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

#[tokio::test]
async fn test_reset_password_token_endpoint_success() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, user, _session) = create_test_context_with_user().await;

    let reset_token = create_reset_token(&ctx, user.email.as_deref().unwrap()).await;

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/reset-password/token",
        None,
        None,
    );

    let response = plugin
        .handle_reset_password_token(&reset_token, &req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: types::ResetPasswordTokenResponse = serde_json::from_str(&body_str).unwrap();
    assert_eq!(response_data.token, reset_token);
}

#[tokio::test]
async fn test_reset_password_token_endpoint_with_callback() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, user, _session) = create_test_context_with_user().await;

    let reset_token = create_reset_token(&ctx, user.email.as_deref().unwrap()).await;

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
        query,
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

#[tokio::test]
async fn test_reset_password_token_endpoint_invalid_token() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, _session) = create_test_context_with_user().await;

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/reset-password/token",
        None,
        None,
    );

    let err = plugin
        .handle_reset_password_token("invalid_token", &req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 400);
}

#[tokio::test]
async fn test_password_validation() {
    let plugin = PasswordManagementPlugin::new();
    let mut config = AuthConfig::new("test-secret");
    config.password = PasswordConfig {
        min_length: 8,
        require_uppercase: true,
        require_lowercase: true,
        require_numbers: true,
        require_special: true,
        argon2_config: Argon2Config::default(),
    };
    let ctx = AuthContext::new(Arc::new(config), Arc::new(MemoryDatabaseAdapter::new()));

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

#[tokio::test]
async fn test_plugin_routes() {
    let plugin = PasswordManagementPlugin::new();
    let routes = AuthPlugin::<MemoryDatabaseAdapter>::routes(&plugin);

    assert_eq!(routes.len(), 5);
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/forget-password" && r.method == HttpMethod::Post)
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
            .any(|r| r.path == "/change-password" && r.method == HttpMethod::Post)
    );
}

#[tokio::test]
async fn test_plugin_on_request_routing() {
    let plugin = PasswordManagementPlugin::new();
    let (ctx, _user, session) = create_test_context_with_user().await;

    // Test forget password
    let body = serde_json::json!({"email": "test@example.com"});
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/forget-password",
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

#[tokio::test]
async fn test_configuration() {
    let config = PasswordManagementConfig {
        reset_token_expiry_hours: 48,
        require_current_password: false,
        send_email_notifications: false,
        ..Default::default()
    };

    let plugin = PasswordManagementPlugin::with_config(config);
    assert_eq!(plugin.config.reset_token_expiry_hours, 48);
    assert!(!plugin.config.require_current_password);
    assert!(!plugin.config.send_email_notifications);
}

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
        "/forget-password",
        None,
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_forget_password(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    // The custom sender should have been called
    assert!(
        called.load(Ordering::SeqCst),
        "Custom send_reset_password should be invoked"
    );
}

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
    let (ctx, user, _session) = create_test_context_with_user().await;

    let reset_token = create_reset_token(&ctx, user.email.as_deref().unwrap()).await;

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

#[tokio::test]
async fn test_revoke_sessions_on_password_reset_false() {
    let plugin = PasswordManagementPlugin::new().revoke_sessions_on_password_reset(false);
    let (ctx, user, session) = create_test_context_with_user().await;

    let reset_token = create_reset_token(&ctx, user.email.as_deref().unwrap()).await;

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
    let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
    assert!(
        !sessions.is_empty(),
        "Sessions should remain when revoke_sessions_on_password_reset=false"
    );
    assert!(
        sessions.iter().any(|s| s.token == session.token),
        "The original session should still exist"
    );
}

#[tokio::test]
async fn test_revoke_sessions_on_password_reset_true() {
    // Default is true
    let plugin = PasswordManagementPlugin::new();
    let (ctx, user, _session) = create_test_context_with_user().await;

    let reset_token = create_reset_token(&ctx, user.email.as_deref().unwrap()).await;

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
    let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
    assert!(
        sessions.is_empty(),
        "Sessions should be revoked when revoke_sessions_on_password_reset=true"
    );
}
