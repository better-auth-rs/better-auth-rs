use super::*;
use crate::plugins::test_helpers;
use async_trait::async_trait;
use better_auth_core::adapters::{MemoryDatabaseAdapter, UserOps, VerificationOps};
use better_auth_core::{AuthResult, CreateUser, CreateVerification, UpdateUser};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use uuid::Uuid;

use better_auth_core::{AuthPlugin, HttpMethod};

// ------------------------------------------------------------------
// Config defaults
// ------------------------------------------------------------------

#[test]
fn test_default_config() {
    let config = EmailVerificationConfig::default();
    assert_eq!(config.verification_token_expiry, Duration::hours(24));
    assert!(config.send_email_notifications);
    assert!(!config.require_verification_for_signin);
    assert!(!config.auto_verify_new_users);
    assert!(!config.send_on_sign_in);
    assert!(!config.auto_sign_in_after_verification);
    assert!(config.send_verification_email.is_none());
    assert!(config.before_email_verification.is_none());
    assert!(config.after_email_verification.is_none());
}

#[test]
fn test_expiry_hours_helper() {
    let config = EmailVerificationConfig {
        verification_token_expiry: Duration::hours(3),
        ..Default::default()
    };
    assert_eq!(config.expiry_hours(), 3);
}

#[test]
fn test_expiry_hours_truncates() {
    let config = EmailVerificationConfig {
        verification_token_expiry: Duration::minutes(90), // 1.5 hours
        ..Default::default()
    };
    assert_eq!(config.expiry_hours(), 1); // truncated
}

// ------------------------------------------------------------------
// Builder methods
// ------------------------------------------------------------------

#[test]
fn test_builder_verification_token_expiry() {
    let plugin = EmailVerificationPlugin::new().verification_token_expiry(Duration::minutes(30));
    assert_eq!(
        plugin.config.verification_token_expiry,
        Duration::minutes(30)
    );
}

#[test]
fn test_builder_verification_token_expiry_hours() {
    let plugin = EmailVerificationPlugin::new().verification_token_expiry_hours(12);
    assert_eq!(plugin.config.verification_token_expiry, Duration::hours(12));
}

#[test]
fn test_builder_send_on_sign_in() {
    let plugin = EmailVerificationPlugin::new().send_on_sign_in(true);
    assert!(plugin.config.send_on_sign_in);
}

#[test]
fn test_builder_auto_sign_in_after_verification() {
    let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(true);
    assert!(plugin.config.auto_sign_in_after_verification);
}

#[test]
fn test_builder_send_email_notifications() {
    let plugin = EmailVerificationPlugin::new().send_email_notifications(false);
    assert!(!plugin.config.send_email_notifications);
}

#[test]
fn test_builder_require_verification_for_signin() {
    let plugin = EmailVerificationPlugin::new().require_verification_for_signin(true);
    assert!(plugin.config.require_verification_for_signin);
}

#[test]
fn test_builder_auto_verify_new_users() {
    let plugin = EmailVerificationPlugin::new().auto_verify_new_users(true);
    assert!(plugin.config.auto_verify_new_users);
}

#[test]
fn test_builder_chaining() {
    let plugin = EmailVerificationPlugin::new()
        .verification_token_expiry(Duration::hours(2))
        .send_on_sign_in(true)
        .auto_sign_in_after_verification(true)
        .send_email_notifications(false)
        .require_verification_for_signin(true);
    assert_eq!(plugin.config.verification_token_expiry, Duration::hours(2));
    assert!(plugin.config.send_on_sign_in);
    assert!(plugin.config.auto_sign_in_after_verification);
    assert!(!plugin.config.send_email_notifications);
    assert!(plugin.config.require_verification_for_signin);
}

// ------------------------------------------------------------------
// Custom sender builder
// ------------------------------------------------------------------

struct DummySender;

#[async_trait]
impl SendVerificationEmail for DummySender {
    async fn send(&self, _user: &User, _url: &str, _token: &str) -> AuthResult<()> {
        Ok(())
    }
}

#[test]
fn test_builder_custom_send_verification_email() {
    let plugin =
        EmailVerificationPlugin::new().custom_send_verification_email(Arc::new(DummySender));
    assert!(plugin.config.send_verification_email.is_some());
}

// ------------------------------------------------------------------
// Hook builders
// ------------------------------------------------------------------

#[test]
fn test_builder_before_email_verification_hook() {
    let hook: EmailVerificationHook = Arc::new(|_user: &User| Box::pin(async { Ok(()) }));
    let plugin = EmailVerificationPlugin::new().before_email_verification(hook);
    assert!(plugin.config.before_email_verification.is_some());
}

#[test]
fn test_builder_after_email_verification_hook() {
    let hook: EmailVerificationHook = Arc::new(|_user: &User| Box::pin(async { Ok(()) }));
    let plugin = EmailVerificationPlugin::new().after_email_verification(hook);
    assert!(plugin.config.after_email_verification.is_some());
}

// ------------------------------------------------------------------
// Helper methods
// ------------------------------------------------------------------

#[test]
fn test_should_send_on_sign_in() {
    let plugin = EmailVerificationPlugin::new();
    assert!(!plugin.should_send_on_sign_in());

    let plugin = EmailVerificationPlugin::new().send_on_sign_in(true);
    assert!(plugin.should_send_on_sign_in());
}

#[test]
fn test_is_verification_required() {
    let plugin = EmailVerificationPlugin::new();
    assert!(!plugin.is_verification_required());

    let plugin = EmailVerificationPlugin::new().require_verification_for_signin(true);
    assert!(plugin.is_verification_required());
}

/// Helper to create a minimal User for unit tests.
fn make_test_user(email: &str, verified: bool) -> User {
    User {
        id: "test-id".into(),
        name: Some("Test".into()),
        email: Some(email.into()),
        email_verified: verified,
        image: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        username: None,
        display_username: None,
        two_factor_enabled: false,
        role: None,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        metadata: serde_json::Value::Null,
    }
}

#[tokio::test]
async fn test_is_user_verified_or_not_required() {
    let plugin = EmailVerificationPlugin::new();
    let user = make_test_user("a@b.com", false);
    // verification not required -> true even if unverified
    assert!(plugin.is_user_verified_or_not_required(&user).await);

    let plugin = EmailVerificationPlugin::new().require_verification_for_signin(true);
    // verification required + unverified -> false
    assert!(!plugin.is_user_verified_or_not_required(&user).await);

    let verified_user = make_test_user("a@b.com", true);
    // verified -> always true
    assert!(
        plugin
            .is_user_verified_or_not_required(&verified_user)
            .await
    );
}

// ------------------------------------------------------------------
// to_user conversion
// ------------------------------------------------------------------

#[test]
fn test_to_user_preserves_fields() {
    let user = User {
        id: "test-id".into(),
        name: Some("Test User".into()),
        email: Some("test@example.com".into()),
        email_verified: true,
        image: Some("https://img.example.com/a.png".into()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        username: Some("testuser".into()),
        display_username: Some("TestUser".into()),
        two_factor_enabled: true,
        role: Some("admin".into()),
        banned: true,
        ban_reason: Some("spam".into()),
        ban_expires: None,
        metadata: serde_json::Value::Null,
    };
    let converted = User::from(&user);
    assert_eq!(converted.id, "test-id");
    assert_eq!(converted.name.as_deref(), Some("Test User"));
    assert_eq!(converted.email.as_deref(), Some("test@example.com"));
    assert!(converted.email_verified);
    assert_eq!(
        converted.image.as_deref(),
        Some("https://img.example.com/a.png")
    );
    assert_eq!(converted.username.as_deref(), Some("testuser"));
    assert_eq!(converted.display_username.as_deref(), Some("TestUser"));
    assert!(converted.two_factor_enabled);
    assert_eq!(converted.role.as_deref(), Some("admin"));
    assert!(converted.banned);
    assert_eq!(converted.ban_reason.as_deref(), Some("spam"));
}

// ------------------------------------------------------------------
// Plugin trait basics
// ------------------------------------------------------------------

#[test]
fn test_plugin_name() {
    let plugin = EmailVerificationPlugin::new();
    assert_eq!(
        AuthPlugin::<MemoryDatabaseAdapter>::name(&plugin),
        "email-verification"
    );
}

#[test]
fn test_plugin_routes() {
    let plugin = EmailVerificationPlugin::new();
    let routes = AuthPlugin::<MemoryDatabaseAdapter>::routes(&plugin);
    assert_eq!(routes.len(), 2);
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/send-verification-email" && r.method == HttpMethod::Post)
    );
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/verify-email" && r.method == HttpMethod::Get)
    );
}

#[tokio::test]
async fn test_on_request_unknown_route_returns_none() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context();
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/unknown", None, None, HashMap::new());
    let result = plugin.on_request(&req, &ctx).await.unwrap();
    assert!(result.is_none());
}

// ------------------------------------------------------------------
// send_verification_on_sign_in
// ------------------------------------------------------------------

#[tokio::test]
async fn test_send_verification_on_sign_in_disabled() {
    let plugin = EmailVerificationPlugin::new().send_on_sign_in(false);
    let ctx = test_helpers::create_test_context();
    let user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("unverified@test.com")
                .with_name("Test"),
        )
        .await
        .unwrap();
    // Should return Ok(()) immediately when disabled
    plugin
        .send_verification_on_sign_in(&user, None, &ctx)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_send_verification_on_sign_in_verified_user() {
    let plugin = EmailVerificationPlugin::new().send_on_sign_in(true);
    let ctx = test_helpers::create_test_context();
    let user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("verified@test.com")
                .with_name("Test"),
        )
        .await
        .unwrap();
    // Mark user as verified
    let update = UpdateUser {
        email_verified: Some(true),
        ..Default::default()
    };
    let verified = ctx.database.update_user(&user.id, update).await.unwrap();
    // Should return Ok(()) for already-verified user
    plugin
        .send_verification_on_sign_in(&verified, None, &ctx)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_send_verification_on_sign_in_creates_token() {
    // Use a custom sender that records calls instead of needing an
    // email provider.
    let call_count = Arc::new(AtomicU32::new(0));
    let counter = call_count.clone();
    struct CountingSender(Arc<AtomicU32>);
    #[async_trait]
    impl SendVerificationEmail for CountingSender {
        async fn send(&self, _user: &User, _url: &str, _token: &str) -> AuthResult<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    let plugin = EmailVerificationPlugin::new()
        .send_on_sign_in(true)
        .send_email_notifications(false) // disable default path
        .custom_send_verification_email(Arc::new(CountingSender(counter)));

    let ctx = test_helpers::create_test_context();
    let user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("unverified@test.com")
                .with_name("Test"),
        )
        .await
        .unwrap();

    plugin
        .send_verification_on_sign_in(&user, None, &ctx)
        .await
        .unwrap();

    assert_eq!(call_count.load(Ordering::Relaxed), 1);
}

// ------------------------------------------------------------------
// on_user_created -- custom sender fires even when
// send_email_notifications is false
// ------------------------------------------------------------------

#[tokio::test]
async fn test_on_user_created_custom_sender_fires_without_notifications() {
    let call_count = Arc::new(AtomicU32::new(0));
    let counter = call_count.clone();
    struct CountingSender(Arc<AtomicU32>);
    #[async_trait]
    impl SendVerificationEmail for CountingSender {
        async fn send(&self, _user: &User, _url: &str, _token: &str) -> AuthResult<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    let plugin = EmailVerificationPlugin::new()
        .send_email_notifications(false)
        .custom_send_verification_email(Arc::new(CountingSender(counter)));

    let ctx = test_helpers::create_test_context();
    let user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("newuser@test.com")
                .with_name("New"),
        )
        .await
        .unwrap();

    plugin.on_user_created(&user, &ctx).await.unwrap();

    // Custom sender should have been called even though
    // send_email_notifications is false.
    assert_eq!(call_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn test_on_user_created_verified_user_skips_email() {
    let call_count = Arc::new(AtomicU32::new(0));
    let counter = call_count.clone();
    struct CountingSender(Arc<AtomicU32>);
    #[async_trait]
    impl SendVerificationEmail for CountingSender {
        async fn send(&self, _user: &User, _url: &str, _token: &str) -> AuthResult<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    let plugin = EmailVerificationPlugin::new()
        .custom_send_verification_email(Arc::new(CountingSender(counter)));

    let ctx = test_helpers::create_test_context();
    let user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("newuser@test.com")
                .with_name("New"),
        )
        .await
        .unwrap();
    // Mark verified
    let update = UpdateUser {
        email_verified: Some(true),
        ..Default::default()
    };
    let verified = ctx.database.update_user(&user.id, update).await.unwrap();

    plugin.on_user_created(&verified, &ctx).await.unwrap();

    // Should NOT have been called because user is already verified.
    assert_eq!(call_count.load(Ordering::Relaxed), 0);
}

// ------------------------------------------------------------------
// handle_verify_email -- basic flow
// ------------------------------------------------------------------

#[tokio::test]
async fn test_verify_email_basic_flow() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context();

    // Create an unverified user
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("verify@test.com")
                .with_name("Verify Me"),
        )
        .await
        .unwrap();

    // Create a verification token
    let token_value = format!("verify_{}", Uuid::new_v4());
    ctx.database
        .create_verification(CreateVerification {
            identifier: "verify@test.com".to_string(),
            value: token_value.clone(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();

    // Call verify-email
    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value.clone());
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["status"], true);
    assert_eq!(body["user"]["email"], "verify@test.com");

    // User should now be verified in the database
    let updated = ctx
        .database
        .get_user_by_email("verify@test.com")
        .await
        .unwrap()
        .unwrap();
    assert!(updated.email_verified);

    // Verification token should be deleted
    let v = ctx
        .database
        .get_verification_by_value(&token_value)
        .await
        .unwrap();
    assert!(v.is_none());
}

// ------------------------------------------------------------------
// handle_verify_email -- hooks are called
// ------------------------------------------------------------------

#[tokio::test]
async fn test_verify_email_calls_before_and_after_hooks() {
    let before_count = Arc::new(AtomicU32::new(0));
    let after_count = Arc::new(AtomicU32::new(0));
    let bc = before_count.clone();
    let ac = after_count.clone();

    let before_hook: EmailVerificationHook = Arc::new(move |_user: &User| {
        let c = bc.clone();
        Box::pin(async move {
            c.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    });
    let after_hook: EmailVerificationHook = Arc::new(move |_user: &User| {
        let c = ac.clone();
        Box::pin(async move {
            c.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    });

    let plugin = EmailVerificationPlugin::new()
        .before_email_verification(before_hook)
        .after_email_verification(after_hook);

    let ctx = test_helpers::create_test_context();
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("hooks@test.com")
                .with_name("Hooks"),
        )
        .await
        .unwrap();

    let token_value = format!("verify_{}", Uuid::new_v4());
    ctx.database
        .create_verification(CreateVerification {
            identifier: "hooks@test.com".to_string(),
            value: token_value.clone(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    assert_eq!(before_count.load(Ordering::Relaxed), 1);
    assert_eq!(after_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn test_verify_email_before_hook_error_aborts() {
    let before_hook: EmailVerificationHook =
        Arc::new(|_user: &User| Box::pin(async { Err(AuthError::forbidden("hook rejected")) }));

    let plugin = EmailVerificationPlugin::new().before_email_verification(before_hook);

    let ctx = test_helpers::create_test_context();
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("hook-err@test.com")
                .with_name("HookErr"),
        )
        .await
        .unwrap();

    let token_value = format!("verify_{}", Uuid::new_v4());
    ctx.database
        .create_verification(CreateVerification {
            identifier: "hook-err@test.com".to_string(),
            value: token_value.clone(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value.clone());
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let err = plugin.handle_verify_email(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 403);

    // User should still be unverified
    let u = ctx
        .database
        .get_user_by_email("hook-err@test.com")
        .await
        .unwrap()
        .unwrap();
    assert!(!u.email_verified);
}

// ------------------------------------------------------------------
// handle_verify_email -- auto_sign_in_after_verification
// ------------------------------------------------------------------

#[tokio::test]
async fn test_verify_email_auto_sign_in_creates_session() {
    let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(true);

    let ctx = test_helpers::create_test_context();
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("autosign@test.com")
                .with_name("AutoSign"),
        )
        .await
        .unwrap();

    let token_value = format!("verify_{}", Uuid::new_v4());
    ctx.database
        .create_verification(CreateVerification {
            identifier: "autosign@test.com".to_string(),
            value: token_value.clone(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["status"], true);
    // Session should be present
    assert!(body["session"]["token"].is_string());

    // Set-Cookie header should be present
    assert!(response.headers.contains_key("Set-Cookie"));
    let cookie_header = &response.headers["Set-Cookie"];
    assert!(cookie_header.contains("better-auth.session"));
}

#[tokio::test]
async fn test_verify_email_no_auto_sign_in_no_session() {
    let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(false);

    let ctx = test_helpers::create_test_context();
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("noautosign@test.com")
                .with_name("NoAutoSign"),
        )
        .await
        .unwrap();

    let token_value = format!("verify_{}", Uuid::new_v4());
    ctx.database
        .create_verification(CreateVerification {
            identifier: "noautosign@test.com".to_string(),
            value: token_value.clone(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["status"], true);
    // No session field expected
    assert!(body.get("session").is_none());
    // No Set-Cookie header expected
    assert!(!response.headers.contains_key("Set-Cookie"));
}

// ------------------------------------------------------------------
// handle_verify_email -- auto_sign_in + callbackURL -> 302 with cookie
// ------------------------------------------------------------------

#[tokio::test]
async fn test_verify_email_auto_sign_in_redirect_includes_cookie() {
    let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(true);

    let ctx = test_helpers::create_test_context();
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("redirect@test.com")
                .with_name("Redirect"),
        )
        .await
        .unwrap();

    let token_value = format!("verify_{}", Uuid::new_v4());
    ctx.database
        .create_verification(CreateVerification {
            identifier: "redirect@test.com".to_string(),
            value: token_value.clone(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    query.insert(
        "callbackURL".to_string(),
        "https://myapp.com/verified".to_string(),
    );
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 302);
    assert!(response.headers["Location"].starts_with("https://myapp.com/verified?verified=true"));
    // Session cookie should be present on the redirect
    assert!(response.headers.contains_key("Set-Cookie"));
    assert!(response.headers["Set-Cookie"].contains("better-auth.session"));
}

#[tokio::test]
async fn test_verify_email_redirect_without_auto_sign_in_no_cookie() {
    let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(false);

    let ctx = test_helpers::create_test_context();
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("redir-nocookie@test.com")
                .with_name("Redir"),
        )
        .await
        .unwrap();

    let token_value = format!("verify_{}", Uuid::new_v4());
    ctx.database
        .create_verification(CreateVerification {
            identifier: "redir-nocookie@test.com".to_string(),
            value: token_value.clone(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    query.insert(
        "callbackURL".to_string(),
        "https://myapp.com/verified".to_string(),
    );
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 302);
    assert!(!response.headers.contains_key("Set-Cookie"));
}

// ------------------------------------------------------------------
// handle_verify_email -- invalid token
// ------------------------------------------------------------------

#[tokio::test]
async fn test_verify_email_invalid_token() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context();

    let mut query = HashMap::new();
    query.insert("token".to_string(), "bogus-token".to_string());
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let err = plugin.handle_verify_email(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
}

#[tokio::test]
async fn test_verify_email_missing_token() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context();

    let req = test_helpers::create_auth_request(
        HttpMethod::Get,
        "/verify-email",
        None,
        None,
        HashMap::new(),
    );
    let err = plugin.handle_verify_email(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
}

// ------------------------------------------------------------------
// handle_verify_email -- already-verified user returns early
// ------------------------------------------------------------------

#[tokio::test]
async fn test_verify_email_already_verified_returns_ok() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context();

    let user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("already@test.com")
                .with_name("Already"),
        )
        .await
        .unwrap();
    // Mark verified
    ctx.database
        .update_user(
            &user.id,
            UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let token_value = format!("verify_{}", Uuid::new_v4());
    ctx.database
        .create_verification(CreateVerification {
            identifier: "already@test.com".to_string(),
            value: token_value.clone(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["status"], true);
}

// ------------------------------------------------------------------
// handle_send_verification_email
// ------------------------------------------------------------------

#[tokio::test]
async fn test_send_verification_email_already_verified_returns_error() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context();

    let user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("verified@test.com")
                .with_name("Verified"),
        )
        .await
        .unwrap();
    ctx.database
        .update_user(
            &user.id,
            UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let body = serde_json::json!({ "email": "verified@test.com" });
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/send-verification-email".to_string(),
        headers,
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    );
    let err = plugin
        .handle_send_verification_email(&req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 400);
}

#[tokio::test]
async fn test_send_verification_email_user_not_found() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context();

    let body = serde_json::json!({ "email": "nobody@test.com" });
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/send-verification-email".to_string(),
        headers,
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    );
    let err = plugin
        .handle_send_verification_email(&req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 404);
}

// ------------------------------------------------------------------
// create_session_cookie -- uses cookie crate
// ------------------------------------------------------------------

#[test]
fn test_create_session_cookie_format() {
    use better_auth_core::utils::cookie_utils::create_session_cookie;

    let ctx = test_helpers::create_test_context();
    let cookie_str = create_session_cookie("my-token-123", &ctx.config);
    // Should contain the cookie name and value
    assert!(cookie_str.contains("better-auth.session-token=my-token-123"));
    // Should contain Path
    assert!(cookie_str.contains("Path=/"));
    // Should contain HttpOnly (default)
    assert!(cookie_str.contains("HttpOnly"));
    // Should contain SameSite
    assert!(cookie_str.contains("SameSite=Lax"));
}

#[test]
fn test_create_session_cookie_special_characters_in_token() {
    use better_auth_core::utils::cookie_utils::create_session_cookie;

    let ctx = test_helpers::create_test_context();
    let token = "token+with/special=chars&more";
    let cookie_str = create_session_cookie(token, &ctx.config);
    // The cookie crate should handle encoding properly
    assert!(cookie_str.contains("better-auth.session-token="));
}
