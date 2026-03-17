use super::*;
use crate::plugins::test_helpers;
use async_trait::async_trait;
use better_auth_core::{AccountConfig, CreateUser};
use chrono::Duration;
use std::collections::HashMap;
use std::sync::Arc;

// -- change email tests ────────────────────────────────────────────

// Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
#[tokio::test]
async fn test_change_email_success() {
    let plugin = UserManagementPlugin::new().change_email_enabled(true);
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User")
            .with_email_verified(true),
        Duration::hours(24),
    )
    .await;

    let body = serde_json::json!({ "newEmail": "new@example.com" });
    let req = test_helpers::create_auth_request(
        HttpMethod::Post,
        "/change-email",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    );

    let response = plugin.handle_change_email(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);
}

// Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
#[tokio::test]
async fn test_change_email_same_email() {
    let plugin = UserManagementPlugin::new().change_email_enabled(true);
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User")
            .with_email_verified(true),
        Duration::hours(24),
    )
    .await;

    let body = serde_json::json!({ "newEmail": "test@example.com" });
    let req = test_helpers::create_auth_request(
        HttpMethod::Post,
        "/change-email",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    );

    let err = plugin.handle_change_email(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
}

// Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
#[tokio::test]
async fn test_change_email_unauthenticated() {
    let plugin = UserManagementPlugin::new().change_email_enabled(true);
    let (ctx, _user, _session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User")
            .with_email_verified(true),
        Duration::hours(24),
    )
    .await;

    let body = serde_json::json!({ "newEmail": "new@example.com" });
    let req = test_helpers::create_auth_request(
        HttpMethod::Post,
        "/change-email",
        None,
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    );

    let err = plugin.handle_change_email(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 401);
}

// Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
#[tokio::test]
async fn test_change_email_immediate_when_update_without_verification() {
    let plugin = UserManagementPlugin::new()
        .change_email_enabled(true)
        .update_without_verification(true);
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User")
            .with_email_verified(false),
        Duration::hours(24),
    )
    .await;

    // Initiate change -- should update immediately, no verification token
    let body = serde_json::json!({ "newEmail": "new@example.com" });
    let req = test_helpers::create_auth_request(
        HttpMethod::Post,
        "/change-email",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    );
    let response = plugin.handle_change_email(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    // Email should be updated immediately
    let updated_user = ctx
        .database
        .get_user_by_id(&user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated_user.email.as_deref(), Some("new@example.com"));
    // email_verified should be false (no verification was performed)
    assert!(!updated_user.email_verified);

    // No verification token should have been created
    let identifier = format!("change_email:{}:new@example.com", user.id);
    let verification = ctx
        .database
        .get_verification_by_identifier(&identifier)
        .await
        .unwrap();
    assert!(
        verification.is_none(),
        "no verification token should be created when update_without_verification=true"
    );
}

// -- delete user tests ─────────────────────────────────────────────

// Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
#[tokio::test]
async fn test_delete_user_immediate() {
    let plugin = UserManagementPlugin::new()
        .delete_user_enabled(true)
        .require_delete_verification(false);
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User")
            .with_email_verified(true),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request(
        HttpMethod::Post,
        "/delete-user",
        Some(&session.token),
        Some(b"{}".to_vec()),
        HashMap::new(),
    );

    let response = plugin.handle_delete_user(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    // User should be gone
    let deleted_user = ctx.database.get_user_by_id(&user.id).await.unwrap();
    assert!(deleted_user.is_none());
}

// Upstream reference: packages/better-auth/src/api/routes/update-user.ts :: deleteUser calls `deleteSessionCookie(ctx)`, which clears the account_data cookie when account.storeAccountCookie is enabled.
#[tokio::test]
async fn test_delete_user_immediate_clears_account_cookie_when_enabled() {
    let plugin = UserManagementPlugin::new()
        .delete_user_enabled(true)
        .require_delete_verification(false);
    let config = test_helpers::create_test_config().account(AccountConfig {
        store_account_cookie: true,
        ..Default::default()
    });
    let ctx = test_helpers::create_test_context_with_config(config).await;
    let (_user, session) = test_helpers::create_user_and_session(
        &ctx,
        CreateUser::new()
            .with_email("account-cookie@test.com")
            .with_name("Account Cookie")
            .with_email_verified(true),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request(
        HttpMethod::Post,
        "/delete-user",
        Some(&session.token),
        Some(b"{}".to_vec()),
        HashMap::new(),
    );

    let response = plugin.handle_delete_user(&req, &ctx).await.unwrap();
    let account_cookie_name = format!("{}=", related_cookie_name(&ctx.config, "account_data"));
    assert!(
        response
            .headers
            .get_all("Set-Cookie")
            .any(|cookie| cookie.starts_with(&account_cookie_name)),
        "delete-user should clear the account_data cookie when store_account_cookie is enabled"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
#[tokio::test]
async fn test_delete_user_with_verification() {
    let plugin = UserManagementPlugin::new()
        .delete_user_enabled(true)
        .require_delete_verification(true);
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User")
            .with_email_verified(true),
        Duration::hours(24),
    )
    .await;

    // 1. Request deletion -- should return pending status
    let req = test_helpers::create_auth_request(
        HttpMethod::Post,
        "/delete-user",
        Some(&session.token),
        Some(b"{}".to_vec()),
        HashMap::new(),
    );

    let response = plugin.handle_delete_user(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    // User should still exist
    let still_exists = ctx.database.get_user_by_id(&user.id).await.unwrap();
    assert!(still_exists.is_some());

    // 2. Seed and confirm the callback token
    let token = "delete-token-123";
    ctx.database
        .create_verification(better_auth_core::CreateVerification {
            identifier: format!("delete-account-{}", token),
            value: user.id.clone(),
            expires_at: chrono::Utc::now() + Duration::hours(24),
        })
        .await
        .unwrap();

    let mut query = HashMap::new();
    query.insert("token".to_string(), token.to_string());
    let req = test_helpers::create_auth_request(
        HttpMethod::Get,
        "/delete-user/callback",
        Some(&session.token),
        None,
        query,
    );
    let response = plugin
        .handle_delete_user_callback(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    // User should now be gone
    let deleted = ctx.database.get_user_by_id(&user.id).await.unwrap();
    assert!(deleted.is_none());
}

// Upstream reference: packages/better-auth/src/api/routes/update-user.ts :: deleteUserCallback calls `deleteSessionCookie(ctx)`, which clears the account_data cookie when account.storeAccountCookie is enabled.
#[tokio::test]
async fn test_delete_user_callback_clears_account_cookie_when_enabled() {
    let plugin = UserManagementPlugin::new()
        .delete_user_enabled(true)
        .require_delete_verification(true);
    let config = test_helpers::create_test_config().account(AccountConfig {
        store_account_cookie: true,
        ..Default::default()
    });
    let ctx = test_helpers::create_test_context_with_config(config).await;
    let (user, session) = test_helpers::create_user_and_session(
        &ctx,
        CreateUser::new()
            .with_email("callback-cookie@test.com")
            .with_name("Callback Cookie")
            .with_email_verified(true),
        Duration::hours(24),
    )
    .await;

    let token = "delete-cookie-token";
    ctx.database
        .create_verification(better_auth_core::CreateVerification {
            identifier: format!("delete-account-{token}"),
            value: user.id.clone(),
            expires_at: chrono::Utc::now() + Duration::hours(24),
        })
        .await
        .unwrap();

    let mut query = HashMap::new();
    query.insert("token".to_string(), token.to_string());
    query.insert(
        "callbackURL".to_string(),
        "https://example.com/goodbye".to_string(),
    );
    let req = test_helpers::create_auth_request(
        HttpMethod::Get,
        "/delete-user/callback",
        Some(&session.token),
        None,
        query,
    );

    let response = plugin
        .handle_delete_user_callback(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 302);
    let account_cookie_name = format!("{}=", related_cookie_name(&ctx.config, "account_data"));
    assert!(
        response
            .headers
            .get_all("Set-Cookie")
            .any(|cookie| cookie.starts_with(&account_cookie_name)),
        "delete-user callback should clear the account_data cookie when store_account_cookie is enabled"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
#[tokio::test]
async fn test_delete_user_unauthenticated() {
    let plugin = UserManagementPlugin::new()
        .delete_user_enabled(true)
        .require_delete_verification(false);
    let (ctx, _user, _session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User")
            .with_email_verified(true),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request(
        HttpMethod::Post,
        "/delete-user",
        None,
        Some(b"{}".to_vec()),
        HashMap::new(),
    );

    let err = plugin.handle_delete_user(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 401);
}

// Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
#[tokio::test]
async fn test_delete_user_verify_invalid_token() {
    let plugin = UserManagementPlugin::new().delete_user_enabled(true);
    let (ctx, _user, _session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User")
            .with_email_verified(true),
        Duration::hours(24),
    )
    .await;

    let mut query = HashMap::new();
    query.insert("token".to_string(), "invalid-token".to_string());
    let req = test_helpers::create_auth_request(
        HttpMethod::Get,
        "/delete-user/callback",
        Some(&_session.token),
        None,
        query,
    );

    let err = plugin
        .handle_delete_user_callback(&req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 404);
}

// Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
#[tokio::test]
async fn test_delete_user_before_hook_abort() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct AbortHook;
    #[async_trait]
    impl BeforeDeleteUser for AbortHook {
        async fn before_delete(&self, _user: &UserInfo) -> AuthResult<()> {
            Err(AuthError::forbidden("Deletion blocked by policy"))
        }
    }

    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();

    struct AfterHook(Arc<AtomicBool>);
    #[async_trait]
    impl AfterDeleteUser for AfterHook {
        async fn after_delete(&self, _user: &UserInfo) -> AuthResult<()> {
            self.0.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    let plugin = UserManagementPlugin::new()
        .delete_user_enabled(true)
        .require_delete_verification(false)
        .before_delete(Arc::new(AbortHook))
        .after_delete(Arc::new(AfterHook(called_clone)));
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User")
            .with_email_verified(true),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request(
        HttpMethod::Post,
        "/delete-user",
        Some(&session.token),
        Some(b"{}".to_vec()),
        HashMap::new(),
    );

    let err = plugin.handle_delete_user(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 403);

    // User should still exist
    let still_exists = ctx.database.get_user_by_id(&user.id).await.unwrap();
    assert!(still_exists.is_some());

    // after_delete should NOT have been called
    assert!(!called.load(Ordering::SeqCst));
}

// Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
#[tokio::test]
async fn test_plugin_routes_conditional() {
    // All disabled
    let plugin = UserManagementPlugin::new();
    assert!(<UserManagementPlugin as AuthPlugin>::routes(&plugin).is_empty());

    // Only change-email enabled
    let plugin = UserManagementPlugin::new().change_email_enabled(true);
    let routes = <UserManagementPlugin as AuthPlugin>::routes(&plugin);
    assert_eq!(routes.len(), 1);
    assert!(routes.iter().any(|r| r.path == "/change-email"));

    // Only delete-user enabled
    let plugin = UserManagementPlugin::new().delete_user_enabled(true);
    let routes = <UserManagementPlugin as AuthPlugin>::routes(&plugin);
    assert_eq!(routes.len(), 2);
    assert!(routes.iter().any(|r| r.path == "/delete-user"));
    assert!(routes.iter().any(|r| r.path == "/delete-user/callback"));

    // Both enabled
    let plugin = UserManagementPlugin::new()
        .change_email_enabled(true)
        .delete_user_enabled(true);
    assert_eq!(
        <UserManagementPlugin as AuthPlugin>::routes(&plugin).len(),
        3
    );
}

// Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
#[tokio::test]
async fn test_on_request_disabled_routes_passthrough() {
    let plugin = UserManagementPlugin::new(); // both disabled
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User")
            .with_email_verified(true),
        Duration::hours(24),
    )
    .await;

    let body = serde_json::json!({ "newEmail": "x@y.com" });
    let req = test_helpers::create_auth_request(
        HttpMethod::Post,
        "/change-email",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    );

    let result = plugin.on_request(&req, &ctx).await.unwrap();
    assert!(result.is_none(), "disabled routes should return None");
}
