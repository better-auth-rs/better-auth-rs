use super::token::create_email_verification_token;
use super::*;
use crate::plugins::test_helpers;
use async_trait::async_trait;
use better_auth_core::wire::UserView;
use better_auth_core::{AuthResult, CreateUser, UpdateUser};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use better_auth_core::{AuthPlugin, HttpMethod};

// ------------------------------------------------------------------
// Rust-specific builder/default surface
// ------------------------------------------------------------------

// Rust-specific surface: `EmailVerificationPlugin` builder methods and
// `EmailVerificationConfig` are public Rust APIs with no direct TS analogue.
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

// Rust-specific surface: `EmailVerificationPlugin` builder methods and
// `EmailVerificationConfig` are public Rust APIs with no direct TS analogue.
#[test]
fn test_builder_verification_token_expiry() {
    let plugin = EmailVerificationPlugin::new().verification_token_expiry(Duration::minutes(30));
    assert_eq!(
        plugin.config.verification_token_expiry,
        Duration::minutes(30)
    );
}

// Rust-specific surface: `EmailVerificationPlugin` builder methods and
// `EmailVerificationConfig` are public Rust APIs with no direct TS analogue.
#[test]
fn test_builder_send_on_sign_in() {
    let plugin = EmailVerificationPlugin::new().send_on_sign_in(true);
    assert!(plugin.config.send_on_sign_in);
}

// Rust-specific surface: `EmailVerificationPlugin` builder methods and
// `EmailVerificationConfig` are public Rust APIs with no direct TS analogue.
#[test]
fn test_builder_auto_sign_in_after_verification() {
    let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(true);
    assert!(plugin.config.auto_sign_in_after_verification);
}

// Rust-specific surface: `EmailVerificationPlugin` builder methods and
// `EmailVerificationConfig` are public Rust APIs with no direct TS analogue.
#[test]
fn test_builder_send_email_notifications() {
    let plugin = EmailVerificationPlugin::new().send_email_notifications(false);
    assert!(!plugin.config.send_email_notifications);
}

// Rust-specific surface: `EmailVerificationPlugin` builder methods and
// `EmailVerificationConfig` are public Rust APIs with no direct TS analogue.
#[test]
fn test_builder_require_verification_for_signin() {
    let plugin = EmailVerificationPlugin::new().require_verification_for_signin(true);
    assert!(plugin.config.require_verification_for_signin);
}

// Rust-specific surface: `EmailVerificationPlugin` builder methods and
// `EmailVerificationConfig` are public Rust APIs with no direct TS analogue.
#[test]
fn test_builder_auto_verify_new_users() {
    let plugin = EmailVerificationPlugin::new().auto_verify_new_users(true);
    assert!(plugin.config.auto_verify_new_users);
}

// Rust-specific surface: `EmailVerificationPlugin` builder methods and
// `EmailVerificationConfig` are public Rust APIs with no direct TS analogue.
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
// Custom sender
// ------------------------------------------------------------------

struct DummySender;

#[async_trait]
impl SendVerificationEmail for DummySender {
    async fn send(&self, _user: &UserView, _url: &str, _token: &str) -> AuthResult<()> {
        Ok(())
    }
}

// Rust-specific surface: `EmailVerificationPlugin::custom_send_verification_email`
// is a public Rust-only builder API.
#[test]
fn test_builder_custom_send_verification_email() {
    let plugin =
        EmailVerificationPlugin::new().custom_send_verification_email(Arc::new(DummySender));
    assert!(plugin.config.send_verification_email.is_some());
}

// Rust-specific surface: Rust hook builder methods on
// `EmailVerificationPlugin` have no direct TS analogue.
#[test]
fn test_builder_before_email_verification_hook() {
    let hook: EmailVerificationHook = Arc::new(|_user: &UserView| Box::pin(async { Ok(()) }));
    let plugin = EmailVerificationPlugin::new().before_email_verification(hook);
    assert!(plugin.config.before_email_verification.is_some());
}

// Rust-specific surface: Rust hook builder methods on
// `EmailVerificationPlugin` have no direct TS analogue.
#[test]
fn test_builder_after_email_verification_hook() {
    let hook: EmailVerificationHook = Arc::new(|_user: &UserView| Box::pin(async { Ok(()) }));
    let plugin = EmailVerificationPlugin::new().after_email_verification(hook);
    assert!(plugin.config.after_email_verification.is_some());
}

/// Helper to create a minimal wire user view for unit tests.
fn make_test_user(email: &str, verified: bool) -> UserView {
    UserView {
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

fn jwt_token(
    ctx: &better_auth_core::AuthContext<impl better_auth_core::AuthSchema>,
    email: &str,
    update_to: Option<&str>,
    request_type: Option<&str>,
) -> String {
    create_email_verification_token(
        &ctx.config.secret,
        email,
        update_to,
        Duration::hours(1),
        request_type,
    )
    .unwrap()
}

// Rust-specific surface: helper methods exposing plugin state are public Rust
// APIs with no direct TS analogue.
#[test]
fn test_should_send_on_sign_in() {
    let plugin = EmailVerificationPlugin::new();
    assert!(!plugin.should_send_on_sign_in());

    let plugin = EmailVerificationPlugin::new().send_on_sign_in(true);
    assert!(plugin.should_send_on_sign_in());
}

// Rust-specific surface: helper methods exposing plugin state are public Rust
// APIs with no direct TS analogue.
#[test]
fn test_is_verification_required() {
    let plugin = EmailVerificationPlugin::new();
    assert!(!plugin.is_verification_required());

    let plugin = EmailVerificationPlugin::new().require_verification_for_signin(true);
    assert!(plugin.is_verification_required());
}

// Rust-specific surface: helper methods exposing plugin state are public Rust
// APIs with no direct TS analogue.
#[tokio::test]
async fn test_is_user_verified_or_not_required() {
    let plugin = EmailVerificationPlugin::new();
    let user = make_test_user("a@b.com", false);
    // verification not required -> true even if unverified
    assert!(plugin.is_user_verified_or_not_required(&user));

    let plugin = EmailVerificationPlugin::new().require_verification_for_signin(true);
    // verification required + unverified -> false
    assert!(!plugin.is_user_verified_or_not_required(&user));

    let verified_user = make_test_user("a@b.com", true);
    // verified -> always true
    assert!(plugin.is_user_verified_or_not_required(&verified_user));
}

// ------------------------------------------------------------------
// to_user conversion
// ------------------------------------------------------------------

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[test]
fn test_to_user_preserves_fields() {
    let user = UserView {
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
    let converted = UserView::from(&user);
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

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[test]
fn test_plugin_name() {
    let plugin = EmailVerificationPlugin::new();
    assert_eq!(
        AuthPlugin::<
            better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema,
        >::name(&plugin,),
        "email-verification"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[test]
fn test_plugin_routes() {
    let plugin = EmailVerificationPlugin::new();
    let routes = AuthPlugin::<
        better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema,
    >::routes(&plugin);
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

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_on_request_unknown_route_returns_none() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context().await;
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/unknown", None, None, HashMap::new());
    let result = plugin.on_request(&req, &ctx).await.unwrap();
    assert!(result.is_none());
}

// ------------------------------------------------------------------
// send_verification_on_sign_in
// ------------------------------------------------------------------

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_send_verification_on_sign_in_disabled() {
    let plugin = EmailVerificationPlugin::new().send_on_sign_in(false);
    let ctx = test_helpers::create_test_context().await;
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

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_send_verification_on_sign_in_verified_user() {
    let plugin = EmailVerificationPlugin::new().send_on_sign_in(true);
    let ctx = test_helpers::create_test_context().await;
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

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_send_verification_on_sign_in_creates_token() {
    // Use a custom sender that records calls instead of needing an
    // email provider.
    let call_count = Arc::new(AtomicU32::new(0));
    let counter = call_count.clone();
    struct CountingSender(Arc<AtomicU32>);
    #[async_trait]
    impl SendVerificationEmail for CountingSender {
        async fn send(&self, _user: &UserView, _url: &str, _token: &str) -> AuthResult<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    let plugin = EmailVerificationPlugin::new()
        .send_on_sign_in(true)
        .send_email_notifications(false) // disable default path
        .custom_send_verification_email(Arc::new(CountingSender(counter)));

    let ctx = test_helpers::create_test_context().await;
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

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_on_user_created_custom_sender_fires_without_notifications() {
    let call_count = Arc::new(AtomicU32::new(0));
    let counter = call_count.clone();
    struct CountingSender(Arc<AtomicU32>);
    #[async_trait]
    impl SendVerificationEmail for CountingSender {
        async fn send(&self, _user: &UserView, _url: &str, _token: &str) -> AuthResult<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    let plugin = EmailVerificationPlugin::new()
        .send_email_notifications(false)
        .custom_send_verification_email(Arc::new(CountingSender(counter)));

    let ctx = test_helpers::create_test_context().await;
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

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_on_user_created_verified_user_skips_email() {
    let call_count = Arc::new(AtomicU32::new(0));
    let counter = call_count.clone();
    struct CountingSender(Arc<AtomicU32>);
    #[async_trait]
    impl SendVerificationEmail for CountingSender {
        async fn send(&self, _user: &UserView, _url: &str, _token: &str) -> AuthResult<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    let plugin = EmailVerificationPlugin::new()
        .custom_send_verification_email(Arc::new(CountingSender(counter)));

    let ctx = test_helpers::create_test_context().await;
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

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_verify_email_basic_flow() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context().await;

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

    let token_value = jwt_token(&ctx, "verify@test.com", None, None);

    // Call verify-email
    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value.clone());
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["status"], true);
    assert!(body["user"].is_null());

    // User should now be verified in the database
    let updated = ctx
        .database
        .get_user_by_email("verify@test.com")
        .await
        .unwrap()
        .unwrap();
    assert!(updated.email_verified);
}

// ------------------------------------------------------------------
// handle_verify_email -- hooks are called
// ------------------------------------------------------------------

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_verify_email_calls_before_and_after_hooks() {
    let before_count = Arc::new(AtomicU32::new(0));
    let after_count = Arc::new(AtomicU32::new(0));
    let bc = before_count.clone();
    let ac = after_count.clone();

    let before_hook: EmailVerificationHook = Arc::new(move |_user: &UserView| {
        let c = bc.clone();
        Box::pin(async move {
            c.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    });
    let after_hook: EmailVerificationHook = Arc::new(move |_user: &UserView| {
        let c = ac.clone();
        Box::pin(async move {
            c.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    });

    let plugin = EmailVerificationPlugin::new()
        .before_email_verification(before_hook)
        .after_email_verification(after_hook);

    let ctx = test_helpers::create_test_context().await;
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("hooks@test.com")
                .with_name("Hooks"),
        )
        .await
        .unwrap();

    let token_value = jwt_token(&ctx, "hooks@test.com", None, None);

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    assert_eq!(before_count.load(Ordering::Relaxed), 1);
    assert_eq!(after_count.load(Ordering::Relaxed), 1);
}

// Upstream reference: packages/better-auth/src/api/routes/email-verification.ts :: change-email-verification branch runs `afterEmailVerification(updatedUser, ...)` only after the email update succeeds.
#[tokio::test]
async fn test_change_email_verification_after_hook_observes_updated_user() {
    let captured = Arc::new(std::sync::Mutex::new(Vec::<(Option<String>, bool)>::new()));
    let hook_state = captured.clone();
    let after_hook: EmailVerificationHook = Arc::new(move |user: &UserView| {
        let hook_state = hook_state.clone();
        let email = user.email.clone();
        let verified = user.email_verified;
        Box::pin(async move {
            hook_state.lock().unwrap().push((email, verified));
            Ok(())
        })
    });

    let plugin = EmailVerificationPlugin::new().after_email_verification(after_hook);

    let ctx = test_helpers::create_test_context().await;
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("change-email@test.com")
                .with_name("ChangeEmail"),
        )
        .await
        .unwrap();

    let token_value = jwt_token(
        &ctx,
        "change-email@test.com",
        Some("updated-email@test.com"),
        Some("change-email-verification"),
    );

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(
        *captured.lock().unwrap(),
        vec![(Some("updated-email@test.com".to_string()), true)]
    );

    let updated_user = ctx
        .database
        .get_user_by_email("updated-email@test.com")
        .await
        .unwrap()
        .unwrap();
    assert!(updated_user.email_verified);
}

// Upstream reference: packages/better-auth/src/api/routes/email-verification.ts :: `afterEmailVerification` runs only after `updateUserByEmail(...)`, so failed updates must not fire the hook.
#[tokio::test]
async fn test_change_email_verification_does_not_fire_after_hook_when_update_fails() {
    let after_count = Arc::new(AtomicU32::new(0));
    let counter = after_count.clone();
    let after_hook: EmailVerificationHook = Arc::new(move |_user: &UserView| {
        let counter = counter.clone();
        Box::pin(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    });

    let plugin = EmailVerificationPlugin::new().after_email_verification(after_hook);

    let ctx = test_helpers::create_test_context().await;
    let _source_user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("duplicate-source@test.com")
                .with_name("DuplicateSource"),
        )
        .await
        .unwrap();
    let _existing_user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("duplicate-target@test.com")
                .with_name("DuplicateTarget"),
        )
        .await
        .unwrap();

    let token_value = jwt_token(
        &ctx,
        "duplicate-source@test.com",
        Some("duplicate-target@test.com"),
        Some("change-email-verification"),
    );

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let err = plugin.handle_verify_email(&req, &ctx).await.unwrap_err();

    assert_ne!(err.status_code(), 200);
    assert_eq!(after_count.load(Ordering::Relaxed), 0);

    let source_user = ctx
        .database
        .get_user_by_email("duplicate-source@test.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        source_user.email.as_deref(),
        Some("duplicate-source@test.com")
    );
    assert!(!source_user.email_verified);
}

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_verify_email_before_hook_error_aborts() {
    let before_hook: EmailVerificationHook =
        Arc::new(|_user: &UserView| Box::pin(async { Err(AuthError::forbidden("hook rejected")) }));

    let plugin = EmailVerificationPlugin::new().before_email_verification(before_hook);

    let ctx = test_helpers::create_test_context().await;
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("hook-err@test.com")
                .with_name("HookErr"),
        )
        .await
        .unwrap();

    let token_value = jwt_token(&ctx, "hook-err@test.com", None, None);

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

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_verify_email_auto_sign_in_creates_session() {
    let captured = Arc::new(std::sync::Mutex::new(String::new()));

    struct CapturingSender(Arc<std::sync::Mutex<String>>);
    #[async_trait]
    impl SendVerificationEmail for CapturingSender {
        async fn send(&self, _user: &UserView, _url: &str, token: &str) -> AuthResult<()> {
            *self.0.lock().unwrap() = token.to_string();
            Ok(())
        }
    }

    let plugin = EmailVerificationPlugin::new()
        .auto_sign_in_after_verification(true)
        .custom_send_verification_email(Arc::new(CapturingSender(captured.clone())));

    let ctx = test_helpers::create_test_context().await;
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("autosign@test.com")
                .with_name("AutoSign"),
        )
        .await
        .unwrap();

    let body = serde_json::json!({ "email": "autosign@test.com" });
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let send_req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/send-verification-email".to_string(),
        headers,
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    );
    let send_response = plugin
        .handle_send_verification_email(&send_req, &ctx)
        .await
        .unwrap();
    assert_eq!(send_response.status, 200);

    let mut query = HashMap::new();
    query.insert("token".to_string(), captured.lock().unwrap().clone());
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["status"], true);
    assert!(body["user"].is_null());

    // Set-Cookie header should be present
    assert!(response.headers.contains_key("Set-Cookie"));
    let cookie_header = &response.headers["Set-Cookie"];
    assert!(cookie_header.contains("better-auth.session"));
}

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_verify_email_no_auto_sign_in_no_session() {
    let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(false);

    let ctx = test_helpers::create_test_context().await;
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("noautosign@test.com")
                .with_name("NoAutoSign"),
        )
        .await
        .unwrap();

    let token_value = jwt_token(&ctx, "noautosign@test.com", None, None);

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

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_verify_email_auto_sign_in_redirect_includes_cookie() {
    let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(true);

    let ctx = test_helpers::create_test_context().await;
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("redirect@test.com")
                .with_name("Redirect"),
        )
        .await
        .unwrap();

    let token_value = jwt_token(&ctx, "redirect@test.com", None, None);

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    query.insert("callbackURL".to_string(), "/verified".to_string());
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 302);
    assert_eq!(response.headers["Location"], "/verified");
    // Session cookie should be present on the redirect
    assert!(response.headers.contains_key("Set-Cookie"));
    assert!(response.headers["Set-Cookie"].contains("better-auth.session"));
}

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_verify_email_redirect_without_auto_sign_in_no_cookie() {
    let plugin = EmailVerificationPlugin::new().auto_sign_in_after_verification(false);

    let ctx = test_helpers::create_test_context().await;
    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("redir-nocookie@test.com")
                .with_name("Redir"),
        )
        .await
        .unwrap();

    let token_value = jwt_token(&ctx, "redir-nocookie@test.com", None, None);

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    query.insert("callbackURL".to_string(), "/verified".to_string());
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 302);
    assert!(!response.headers.contains_key("Set-Cookie"));
}

// ------------------------------------------------------------------
// handle_verify_email -- invalid token
// ------------------------------------------------------------------

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_verify_email_invalid_token() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context().await;

    let mut query = HashMap::new();
    query.insert("token".to_string(), "bogus-token".to_string());
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let err = plugin.handle_verify_email(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
}

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_verify_email_missing_token() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context().await;

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

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_verify_email_already_verified_returns_ok() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context().await;

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

    let token_value = jwt_token(&ctx, "already@test.com", None, None);

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

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_send_verification_email_already_verified_returns_error() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context().await;

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

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[tokio::test]
async fn test_send_verification_email_user_not_found() {
    struct NoopSender;
    #[async_trait]
    impl SendVerificationEmail for NoopSender {
        async fn send(&self, _user: &UserView, _url: &str, _token: &str) -> AuthResult<()> {
            Ok(())
        }
    }

    let plugin =
        EmailVerificationPlugin::new().custom_send_verification_email(Arc::new(NoopSender));
    let ctx = test_helpers::create_test_context().await;

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
    let response = plugin
        .handle_send_verification_email(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
}

// ------------------------------------------------------------------
// create_session_cookie -- uses cookie crate
// ------------------------------------------------------------------

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[test]
fn test_create_session_cookie_format() {
    use better_auth_core::utils::cookie_utils::create_session_cookie;

    let ctx = test_helpers::create_test_context_blocking();
    let cookie_str = create_session_cookie("my-token-123", &ctx.config);
    // Should contain the cookie name and value
    assert!(cookie_str.contains("better-auth.session_token=my-token-123"));
    // Should contain Path
    assert!(cookie_str.contains("Path=/"));
    // Should contain HttpOnly (default)
    assert!(cookie_str.contains("HttpOnly"));
    // Should contain SameSite
    assert!(cookie_str.contains("SameSite=Lax"));
}

// Upstream reference: packages/better-auth/src/api/routes/email-verification.test.ts :: describe("Email Verification") and packages/better-auth/src/api/routes/email-verification.ts; adapted to the Rust email verification plugin.
#[test]
fn test_create_session_cookie_special_characters_in_token() {
    use better_auth_core::utils::cookie_utils::create_session_cookie;

    let ctx = test_helpers::create_test_context_blocking();
    let token = "token+with/special=chars&more";
    let cookie_str = create_session_cookie(token, &ctx.config);
    // The cookie crate should handle encoding properly
    assert!(cookie_str.contains("better-auth.session_token="));
}

// ------------------------------------------------------------------
// handle_verify_email -- callbackURL origin check
// ------------------------------------------------------------------

// Upstream reference: packages/better-auth/src/api/routes/email-verification.ts :: `use: [originCheck((ctx) => ctx.query.callbackURL)]` on the verifyEmail endpoint.
#[tokio::test]
async fn test_verify_email_rejects_untrusted_callback_url() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context().await;

    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("redirect-guard@test.com")
                .with_name("Redirect Guard"),
        )
        .await
        .unwrap();

    let token_value = jwt_token(&ctx, "redirect-guard@test.com", None, None);

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    query.insert(
        "callbackURL".to_string(),
        "https://evil.com/phish".to_string(),
    );
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 403);
}

// Upstream reference: packages/better-auth/src/api/routes/email-verification.ts :: `use: [originCheck((ctx) => ctx.query.callbackURL)]` on the verifyEmail endpoint.
#[tokio::test]
async fn test_verify_email_allows_relative_callback_url() {
    let plugin = EmailVerificationPlugin::new();
    let ctx = test_helpers::create_test_context().await;

    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("redirect-rel@test.com")
                .with_name("Redirect Rel"),
        )
        .await
        .unwrap();

    let token_value = jwt_token(&ctx, "redirect-rel@test.com", None, None);

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    query.insert("callbackURL".to_string(), "/dashboard".to_string());
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 302);
    assert_eq!(response.headers["Location"], "/dashboard");
}

// Upstream reference: packages/better-auth/src/api/routes/email-verification.ts :: `use: [originCheck((ctx) => ctx.query.callbackURL)]` on the verifyEmail endpoint.
#[tokio::test]
async fn test_verify_email_allows_trusted_origin_callback_url() {
    let plugin = EmailVerificationPlugin::new();
    let config = test_helpers::create_test_config().trusted_origin("https://trusted.com");
    let ctx = test_helpers::create_test_context_with_config(config).await;

    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("redirect-trusted@test.com")
                .with_name("Redirect Trusted"),
        )
        .await
        .unwrap();

    let token_value = jwt_token(&ctx, "redirect-trusted@test.com", None, None);

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    query.insert(
        "callbackURL".to_string(),
        "https://trusted.com/verified".to_string(),
    );
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 302);
    assert_eq!(response.headers["Location"], "https://trusted.com/verified");
}

// Upstream reference: packages/better-auth/src/api/routes/email-verification.ts :: `use: [originCheck((ctx) => ctx.query.callbackURL)]` on the verifyEmail endpoint; `advanced.disableOriginCheck` skips the check.
#[tokio::test]
async fn test_verify_email_skips_origin_check_when_disabled() {
    let plugin = EmailVerificationPlugin::new();
    let config = test_helpers::create_test_config().disable_origin_check(true);
    let ctx = test_helpers::create_test_context_with_config(config).await;

    let _user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("redirect-disabled@test.com")
                .with_name("Redirect Disabled"),
        )
        .await
        .unwrap();

    let token_value = jwt_token(&ctx, "redirect-disabled@test.com", None, None);

    let mut query = HashMap::new();
    query.insert("token".to_string(), token_value);
    query.insert(
        "callbackURL".to_string(),
        "https://evil.com/anywhere".to_string(),
    );
    let req =
        test_helpers::create_auth_request(HttpMethod::Get, "/verify-email", None, None, query);
    let response = plugin.handle_verify_email(&req, &ctx).await.unwrap();

    // With origin check disabled, the redirect should proceed
    assert_eq!(response.status, 302);
}
