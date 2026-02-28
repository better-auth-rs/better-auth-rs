use super::*;
use crate::plugins::test_helpers;
use better_auth_core::adapters::{AccountOps, MemoryDatabaseAdapter, SessionOps, UserOps};
use better_auth_core::entity::{AuthAccount, AuthSession};
use better_auth_core::{CreateSession, CreateUser, Session, User};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;

async fn create_admin_context() -> (
    AuthContext<MemoryDatabaseAdapter>,
    User,
    Session,
    User,
    Session,
) {
    let ctx = test_helpers::create_test_context();

    // Create admin user
    let admin = test_helpers::create_user(
        &ctx,
        CreateUser::new()
            .with_email("admin@example.com")
            .with_name("Admin")
            .with_role("admin"),
    )
    .await;
    let admin_session =
        test_helpers::create_session(&ctx, admin.id.clone(), Duration::hours(24)).await;

    // Create regular user
    let user = test_helpers::create_user(
        &ctx,
        CreateUser::new()
            .with_email("user@example.com")
            .with_name("Regular User")
            .with_role("user"),
    )
    .await;
    let user_session =
        test_helpers::create_session(&ctx, user.id.clone(), Duration::hours(24)).await;

    (ctx, admin, admin_session, user, user_session)
}

fn make_request(
    method: HttpMethod,
    path: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> AuthRequest {
    test_helpers::create_auth_json_request_no_query(method, path, Some(token), body)
}

fn make_request_with_query(
    method: HttpMethod,
    path: &str,
    token: &str,
    body: Option<serde_json::Value>,
    query: HashMap<String, String>,
) -> AuthRequest {
    test_helpers::create_auth_json_request(method, path, Some(token), body, query)
}

fn json_body(resp: &AuthResponse) -> serde_json::Value {
    serde_json::from_slice(&resp.body).unwrap()
}

// -----------------------------------------------------------------------
// Basic auth / access control
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_set_role() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/set-role",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
            "role": "moderator"
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["user"]["role"], "moderator");
}

#[tokio::test]
async fn test_non_admin_rejected() {
    let (ctx, _admin, _admin_session, _user, user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/set-role",
        &user_session.token,
        Some(serde_json::json!({
            "userId": "someone",
            "role": "admin"
        })),
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_unauthenticated_rejected() {
    let (ctx, _admin, _admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/set-role",
        "invalid-token",
        Some(serde_json::json!({
            "userId": user.id,
            "role": "admin"
        })),
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_custom_admin_role() {
    let config = Arc::new(better_auth_core::AuthConfig::new(
        "test-secret-key-at-least-32-chars-long",
    ));
    let database = Arc::new(MemoryDatabaseAdapter::new());
    let ctx = AuthContext::new(config, database.clone());

    // Create superadmin user with custom role
    let admin = database
        .create_user(
            CreateUser::new()
                .with_email("superadmin@example.com")
                .with_name("Super Admin")
                .with_role("superadmin"),
        )
        .await
        .unwrap();

    let admin_session = database
        .create_session(CreateSession {
            user_id: admin.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();

    let user = database
        .create_user(
            CreateUser::new()
                .with_email("user@example.com")
                .with_name("User")
                .with_role("user"),
        )
        .await
        .unwrap();

    let plugin = AdminPlugin::new().admin_role("superadmin");

    let req = make_request(
        HttpMethod::Post,
        "/admin/set-role",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
            "role": "moderator"
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["user"]["role"], "moderator");
}

#[tokio::test]
async fn test_non_admin_path_returns_none() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/api/not-admin",
        &admin_session.token,
        None,
    );

    // Routes not matching /admin/* should return None (not handled by plugin)
    let result = plugin.on_request(&req, &ctx).await.unwrap();
    assert!(result.is_none());
}

// -----------------------------------------------------------------------
// Create user
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_create_user() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/create-user",
        &admin_session.token,
        Some(serde_json::json!({
            "email": "new@example.com",
            "password": "securepassword123",
            "name": "New User"
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["user"]["email"], "new@example.com");
    assert_eq!(body["user"]["name"], "New User");
    assert_eq!(body["user"]["role"], "user");
}

#[tokio::test]
async fn test_create_user_with_custom_role() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/create-user",
        &admin_session.token,
        Some(serde_json::json!({
            "email": "mod@example.com",
            "password": "securepassword123",
            "name": "Moderator",
            "role": "moderator"
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["user"]["role"], "moderator");
}

#[tokio::test]
async fn test_create_user_creates_credential_account() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/create-user",
        &admin_session.token,
        Some(serde_json::json!({
            "email": "new@example.com",
            "password": "securepassword123",
            "name": "New User"
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    let user_id = body["user"]["id"].as_str().unwrap();

    // Verify a credential account was created
    let accounts = ctx.database.get_user_accounts(user_id).await.unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].provider_id(), "credential");
    assert!(accounts[0].password().is_some());
}

#[tokio::test]
async fn test_create_user_duplicate_email_rejected() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    // user@example.com already exists in the context
    let req = make_request(
        HttpMethod::Post,
        "/admin/create-user",
        &admin_session.token,
        Some(serde_json::json!({
            "email": "user@example.com",
            "password": "securepassword123",
            "name": "Duplicate"
        })),
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_create_user_default_role_config() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new().default_user_role("member");

    let req = make_request(
        HttpMethod::Post,
        "/admin/create-user",
        &admin_session.token,
        Some(serde_json::json!({
            "email": "newmember@example.com",
            "password": "securepassword123",
            "name": "New Member"
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["user"]["role"], "member");
}

// -----------------------------------------------------------------------
// List users
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_list_users() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Get,
        "/admin/list-users",
        &admin_session.token,
        None,
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["total"], 2); // admin + regular user
    assert_eq!(body["users"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_list_users_pagination() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let mut query = HashMap::new();
    query.insert("limit".to_string(), "1".to_string());
    query.insert("offset".to_string(), "0".to_string());

    let req = make_request_with_query(
        HttpMethod::Get,
        "/admin/list-users",
        &admin_session.token,
        None,
        query,
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["total"], 2); // total is still 2
    assert_eq!(body["users"].as_array().unwrap().len(), 1); // but only 1 returned
    assert_eq!(body["limit"], 1);
    assert_eq!(body["offset"], 0);
}

#[tokio::test]
async fn test_list_users_respects_max_page_limit() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new().max_page_limit(1);

    // Request limit=100 but max is 1
    let mut query = HashMap::new();
    query.insert("limit".to_string(), "100".to_string());

    let req = make_request_with_query(
        HttpMethod::Get,
        "/admin/list-users",
        &admin_session.token,
        None,
        query,
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    // Should be clamped to max_page_limit=1
    assert_eq!(body["users"].as_array().unwrap().len(), 1);
    assert_eq!(body["limit"], 1);
}

// -----------------------------------------------------------------------
// List user sessions
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_list_user_sessions() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/list-user-sessions",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    let sessions = body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1);
}

#[tokio::test]
async fn test_list_user_sessions_nonexistent_user() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/list-user-sessions",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": "nonexistent-id",
        })),
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// Ban / Unban
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ban_unban_user() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    // Ban user
    let req = make_request(
        HttpMethod::Post,
        "/admin/ban-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
            "banReason": "spam"
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["user"]["banned"], true);

    // Unban user
    let req = make_request(
        HttpMethod::Post,
        "/admin/unban-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["user"]["banned"], false);
}

#[tokio::test]
async fn test_cannot_ban_self() {
    let (ctx, admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/ban-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": admin.id,
        })),
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

/// Verifies the bug fix: unbanning clears ban_reason and ban_expires in the adapter.
#[tokio::test]
async fn test_unban_clears_ban_reason_and_expires() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    // Ban with reason and expiry
    let req = make_request(
        HttpMethod::Post,
        "/admin/ban-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
            "banReason": "spam",
            "banExpiresIn": 3600
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["user"]["banned"], true);
    assert_eq!(body["user"]["banReason"], "spam");
    assert!(!body["user"]["banExpires"].is_null());

    // Unban
    let req = make_request(
        HttpMethod::Post,
        "/admin/unban-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["user"]["banned"], false);

    // Verify ban_reason and ban_expires are cleared by checking the DB directly
    let updated_user = ctx
        .database
        .get_user_by_id(&user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!updated_user.banned);
    assert!(updated_user.ban_reason.is_none());
    assert!(updated_user.ban_expires.is_none());
}

#[tokio::test]
async fn test_ban_with_expiry() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/ban-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
            "banExpiresIn": 7200 // 2 hours
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["user"]["banned"], true);
    assert!(!body["user"]["banExpires"].is_null());
}

#[tokio::test]
async fn test_ban_revokes_user_sessions() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    // Confirm user has sessions
    let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
    assert!(!sessions.is_empty());

    // Ban user
    let req = make_request(
        HttpMethod::Post,
        "/admin/ban-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
            "banReason": "bad behavior"
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);

    // After ban, sessions should be revoked
    let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
    assert!(sessions.is_empty());
}

#[tokio::test]
async fn test_cannot_ban_admin_by_default() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    // Create second admin
    let admin2 = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("admin2@example.com")
                .with_name("Admin 2")
                .with_role("admin"),
        )
        .await
        .unwrap();

    let req = make_request(
        HttpMethod::Post,
        "/admin/ban-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": admin2.id,
        })),
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_allow_ban_admin_config() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new().allow_ban_admin(true);

    // Create second admin
    let admin2 = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("admin2@example.com")
                .with_name("Admin 2")
                .with_role("admin"),
        )
        .await
        .unwrap();

    let req = make_request(
        HttpMethod::Post,
        "/admin/ban-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": admin2.id,
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["user"]["banned"], true);
}

// -----------------------------------------------------------------------
// Impersonation
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_impersonate_and_stop() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    // Impersonate
    let req = make_request(
        HttpMethod::Post,
        "/admin/impersonate-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["user"]["email"], "user@example.com");
    assert!(body["session"]["token"].is_string());
}

/// Verifies the impersonation session has the impersonated_by field set.
#[tokio::test]
async fn test_impersonate_session_has_impersonated_by() {
    let (ctx, admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/impersonate-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    let imp_token = body["session"]["token"].as_str().unwrap();

    // Look up the impersonation session and check impersonated_by
    let imp_session = ctx.database.get_session(imp_token).await.unwrap().unwrap();
    assert_eq!(
        imp_session.impersonated_by().unwrap(),
        admin.id,
        "impersonated_by should be the admin's user id"
    );
}

/// Verifies the bug fix: stop-impersonating creates a new admin session.
#[tokio::test]
async fn test_stop_impersonating_creates_admin_session() {
    let (ctx, admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    // Impersonate
    let req = make_request(
        HttpMethod::Post,
        "/admin/impersonate-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    let body = json_body(&resp);
    let imp_token = body["session"]["token"].as_str().unwrap().to_string();

    // Stop impersonating using the impersonation session token
    let req = make_request(
        HttpMethod::Post,
        "/admin/stop-impersonating",
        &imp_token,
        None,
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);

    // Should return admin user and a new session
    assert_eq!(body["user"]["email"], "admin@example.com");
    assert!(body["session"]["token"].is_string());

    // The new session token should be for the admin
    let new_token = body["session"]["token"].as_str().unwrap();
    let new_session = ctx.database.get_session(new_token).await.unwrap().unwrap();
    assert_eq!(new_session.user_id, admin.id);
    assert!(
        new_session.impersonated_by.is_none(),
        "new admin session should not be an impersonation session"
    );

    // The response should include a Set-Cookie header
    assert!(resp.headers.contains_key("Set-Cookie"));

    // The old impersonation session should be deleted
    let old_session = ctx.database.get_session(&imp_token).await.unwrap();
    assert!(old_session.is_none());
}

#[tokio::test]
async fn test_stop_impersonating_non_impersonation_session_rejected() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    // Try to stop impersonating with a normal admin session (not impersonation)
    let req = make_request(
        HttpMethod::Post,
        "/admin/stop-impersonating",
        &admin_session.token,
        None,
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_cannot_impersonate_self() {
    let (ctx, admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/impersonate-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": admin.id,
        })),
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_impersonate_nonexistent_user_rejected() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/impersonate-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": "nonexistent-user-id",
        })),
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_impersonate_response_has_set_cookie() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/impersonate-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    assert!(
        resp.headers.contains_key("Set-Cookie"),
        "impersonate response should set a session cookie"
    );
}

// -----------------------------------------------------------------------
// Session management
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_revoke_user_sessions() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/revoke-user-sessions",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["success"], true);

    // Verify sessions are actually deleted
    let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
    assert!(sessions.is_empty());
}

#[tokio::test]
async fn test_revoke_specific_session() {
    let (ctx, _admin, admin_session, _user, user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/revoke-user-session",
        &admin_session.token,
        Some(serde_json::json!({
            "sessionToken": user_session.token,
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["success"], true);

    // Verify specific session is deleted
    let session = ctx.database.get_session(&user_session.token).await.unwrap();
    assert!(session.is_none());
}

// -----------------------------------------------------------------------
// Remove user
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_remove_user() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/remove-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["success"], true);

    // Verify user is deleted
    let deleted = ctx.database.get_user_by_id(&user.id).await.unwrap();
    assert!(deleted.is_none());
}

#[tokio::test]
async fn test_cannot_remove_self() {
    let (ctx, admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/remove-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": admin.id,
        })),
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_remove_user_cleans_up_sessions_and_accounts() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    // First create a user with an account
    let req = make_request(
        HttpMethod::Post,
        "/admin/create-user",
        &admin_session.token,
        Some(serde_json::json!({
            "email": "tobedeleted@example.com",
            "password": "securepassword123",
            "name": "To Be Deleted"
        })),
    );
    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    let body = json_body(&resp);
    let user_id = body["user"]["id"].as_str().unwrap().to_string();

    // Verify user has an account
    let accounts = ctx.database.get_user_accounts(&user_id).await.unwrap();
    assert_eq!(accounts.len(), 1);

    // Remove the user
    let req = make_request(
        HttpMethod::Post,
        "/admin/remove-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user_id,
        })),
    );
    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);

    // Verify user is deleted
    let deleted = ctx.database.get_user_by_id(&user_id).await.unwrap();
    assert!(deleted.is_none());

    // Verify accounts are cleaned up
    let accounts = ctx.database.get_user_accounts(&user_id).await.unwrap();
    assert!(accounts.is_empty());
}

#[tokio::test]
async fn test_remove_nonexistent_user() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/remove-user",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": "nonexistent-user-id",
        })),
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// Set user password
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_set_user_password() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    // First create a user with a credential account
    let req = make_request(
        HttpMethod::Post,
        "/admin/create-user",
        &admin_session.token,
        Some(serde_json::json!({
            "email": "pwuser@example.com",
            "password": "oldpassword123",
            "name": "PW User"
        })),
    );
    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    let body = json_body(&resp);
    let user_id = body["user"]["id"].as_str().unwrap().to_string();

    // Set new password
    let req = make_request(
        HttpMethod::Post,
        "/admin/set-user-password",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user_id,
            "newPassword": "newpassword456"
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["status"], true);
}

/// Verifies the bug fix: set-user-password also updates the credential account password.
#[tokio::test]
async fn test_set_user_password_updates_account() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    // First create a user with a credential account
    let req = make_request(
        HttpMethod::Post,
        "/admin/create-user",
        &admin_session.token,
        Some(serde_json::json!({
            "email": "pwuser@example.com",
            "password": "oldpassword123",
            "name": "PW User"
        })),
    );
    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    let body = json_body(&resp);
    let user_id = body["user"]["id"].as_str().unwrap().to_string();

    // Get the old password hash from the credential account
    let accounts_before = ctx.database.get_user_accounts(&user_id).await.unwrap();
    let old_password = accounts_before[0].password().unwrap().to_string();

    // Set new password
    let req = make_request(
        HttpMethod::Post,
        "/admin/set-user-password",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user_id,
            "newPassword": "newpassword456"
        })),
    );
    plugin.on_request(&req, &ctx).await.unwrap().unwrap();

    // Verify the credential account password was updated
    let accounts_after = ctx.database.get_user_accounts(&user_id).await.unwrap();
    let new_password = accounts_after[0].password().unwrap().to_string();
    assert_ne!(
        old_password, new_password,
        "credential account password should be updated"
    );
}

#[tokio::test]
async fn test_set_user_password_too_short() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/set-user-password",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
            "newPassword": "ab" // too short
        })),
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_set_password_nonexistent_user() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/set-user-password",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": "nonexistent-user-id",
            "newPassword": "newpassword456"
        })),
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// Permissions
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_has_permission_admin() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/has-permission",
        &admin_session.token,
        Some(serde_json::json!({
            "permissions": { "users": ["read", "write"] }
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["success"], true);
}

#[tokio::test]
async fn test_has_permission_non_admin() {
    let (ctx, _admin, _admin_session, _user, user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/has-permission",
        &user_session.token,
        Some(serde_json::json!({
            "permissions": { "users": ["read", "write"] }
        })),
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["success"], false);
    assert!(body["error"].is_string());
}

// -----------------------------------------------------------------------
// Set role edge cases
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_set_role_nonexistent_user() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/set-role",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": "nonexistent-user-id",
            "role": "admin"
        })),
    );

    let result = plugin.on_request(&req, &ctx).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_set_role_persists_in_database() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/set-role",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": user.id,
            "role": "editor"
        })),
    );

    plugin.on_request(&req, &ctx).await.unwrap().unwrap();

    // Verify role is persisted in the database
    let updated = ctx
        .database
        .get_user_by_id(&user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.role.as_deref(), Some("editor"));
}

// -----------------------------------------------------------------------
// Plugin name / routes
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_plugin_name() {
    let plugin = AdminPlugin::new();
    assert_eq!(
        <AdminPlugin as AuthPlugin<MemoryDatabaseAdapter>>::name(&plugin),
        "admin"
    );
}

#[tokio::test]
async fn test_plugin_routes_count() {
    let plugin = AdminPlugin::new();
    let routes = <AdminPlugin as AuthPlugin<MemoryDatabaseAdapter>>::routes(&plugin);
    assert_eq!(routes.len(), 13, "admin plugin should register 13 routes");
}
