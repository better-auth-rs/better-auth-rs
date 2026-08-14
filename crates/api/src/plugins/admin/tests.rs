use super::*;
use crate::plugins::test_helpers;
use better_auth_core::entity::{AuthAccount, AuthSession};
use better_auth_core::utils::cookie_utils::related_cookie_name;
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{AuthPlugin, CreateSession, CreateUser, HttpMethod};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn create_admin_context() -> (
    AuthContext<TestSchema>,
    UserView,
    SessionView,
    UserView,
    SessionView,
) {
    let ctx = test_helpers::create_test_context().await;

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

fn json_body(resp: &AuthResponse) -> serde_json::Value {
    serde_json::from_slice(&resp.body).unwrap()
}

fn set_cookie_value(resp: &AuthResponse, name: &str) -> Option<String> {
    resp.headers.get_all("Set-Cookie").find_map(|header| {
        let (cookie_name, remainder) = header.split_once('=')?;
        if cookie_name != name {
            return None;
        }
        Some(remainder.split(';').next().unwrap_or_default().to_string())
    })
}

#[tokio::test]
async fn test_custom_admin_role_can_use_permission_engine() {
    let config = Arc::new(better_auth_core::AuthConfig::new(
        "test-secret-key-at-least-32-chars-long",
    ));
    let database = test_helpers::create_test_database().await;
    let ctx = AuthContext::new(config, database.clone());

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

    let _user = database
        .create_user(
            CreateUser::new()
                .with_email("user@example.com")
                .with_name("User")
                .with_role("user"),
        )
        .await
        .unwrap();

    let plugin = AdminPlugin::with_config(AdminConfig {
        admin_roles: vec!["superadmin".to_string()],
        roles: HashMap::from([(
            "superadmin".to_string(),
            RolePermissions::new()
                .allow(
                    "user",
                    [
                        "create",
                        "list",
                        "set-role",
                        "ban",
                        "impersonate",
                        "delete",
                        "set-password",
                        "get",
                        "update",
                    ],
                )
                .allow("session", ["list", "revoke", "delete"]),
        )]),
        ..Default::default()
    });

    let req = make_request(
        HttpMethod::Get,
        "/admin/list-users",
        &admin_session.token,
        None,
    );

    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(json_body(&resp)["total"], 2);
}

#[tokio::test]
async fn test_ban_revokes_user_sessions() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
    assert!(!sessions.is_empty());

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

    let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
    assert!(sessions.is_empty());
}

#[tokio::test]
async fn test_unban_clears_ban_reason_and_expires() {
    let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

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
async fn test_impersonation_session_tracks_admin_id() {
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
    let admin_cookie_name = related_cookie_name(&ctx.config, "admin_session");
    assert!(
        set_cookie_value(&resp, &admin_cookie_name).is_some(),
        "impersonation should emit an admin_session cookie"
    );
    let token = json_body(&resp)["session"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let session = ctx.database.get_session(&token).await.unwrap().unwrap();

    assert_eq!(session.impersonated_by().unwrap(), admin.id);
}

#[tokio::test]
async fn test_stop_impersonating_restores_admin_session() {
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
    let impersonation_token = json_body(&resp)["session"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let admin_cookie_name = related_cookie_name(&ctx.config, "admin_session");
    let admin_cookie = set_cookie_value(&resp, &admin_cookie_name)
        .expect("impersonation should set the admin_session cookie");

    let mut req = make_request(
        HttpMethod::Post,
        "/admin/stop-impersonating",
        &impersonation_token,
        None,
    );
    req.headers.insert(
        "cookie".to_string(),
        format!("{admin_cookie_name}={admin_cookie}"),
    );
    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    let body = json_body(&resp);

    let restored_token = body["session"]["token"].as_str().unwrap();
    assert_eq!(
        restored_token, admin_session.token,
        "stop-impersonating should restore the original admin session token"
    );
    let restored_session = ctx
        .database
        .get_session(restored_token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored_session.user_id, admin.id);
    assert!(restored_session.impersonated_by.is_none());
    assert!(
        ctx.database
            .get_session(&impersonation_token)
            .await
            .unwrap()
            .is_none()
    );
    let cleared_admin_cookie = resp
        .headers
        .get_all("Set-Cookie")
        .find(|header| header.starts_with(&format!("{admin_cookie_name}=")))
        .expect("stop-impersonating should clear admin_session");
    assert!(
        cleared_admin_cookie.contains("Max-Age=0"),
        "admin_session should be cleared after stop-impersonating"
    );
}

#[tokio::test]
async fn test_list_user_sessions_missing_user_returns_empty_array() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/list-user-sessions",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": "missing-user",
        })),
    );
    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();

    assert_eq!(resp.status, 200);
    assert_eq!(json_body(&resp), serde_json::json!({ "sessions": [] }));
}

#[tokio::test]
async fn test_revoke_user_sessions_missing_user_still_succeeds() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/revoke-user-sessions",
        &admin_session.token,
        Some(serde_json::json!({
            "userId": "missing-user",
        })),
    );
    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();

    assert_eq!(resp.status, 200);
    assert_eq!(json_body(&resp), serde_json::json!({ "success": true }));
}

#[tokio::test]
async fn test_stop_impersonating_without_impersonated_session_returns_bad_request() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/stop-impersonating",
        &admin_session.token,
        None,
    );
    let err = plugin.on_request(&req, &ctx).await.unwrap_err();
    let response = err.to_auth_response();
    assert_eq!(response.status, 400);
    assert_eq!(
        json_body(&response),
        serde_json::json!({
            "code": "YOU_ARE_NOT_IMPERSONATING_ANYONE",
            "message": "You are not impersonating anyone"
        })
    );
}

#[tokio::test]
async fn test_remove_user_cleans_up_sessions_and_accounts() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

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
    let user_id = json_body(&resp)["user"]["id"].as_str().unwrap().to_string();

    let accounts = ctx.database.get_user_accounts(&user_id).await.unwrap();
    assert_eq!(accounts.len(), 1);

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

    assert!(
        ctx.database
            .get_user_by_id(&user_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ctx.database
            .get_user_accounts(&user_id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn test_set_user_password_updates_credential_account() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

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
    let user_id = json_body(&resp)["user"]["id"].as_str().unwrap().to_string();

    let before = ctx.database.get_user_accounts(&user_id).await.unwrap();
    let old_password = before[0].password().unwrap().to_string();

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

    let after = ctx.database.get_user_accounts(&user_id).await.unwrap();
    let new_password = after[0].password().unwrap().to_string();
    assert_ne!(old_password, new_password);
}

#[tokio::test]
async fn test_set_user_password_does_not_create_credential_account() {
    let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
    let plugin = AdminPlugin::new();

    let req = make_request(
        HttpMethod::Post,
        "/admin/create-user",
        &admin_session.token,
        Some(serde_json::json!({
            "email": "passwordless@example.com",
            "name": "Passwordless User"
        })),
    );
    let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    let user_id = json_body(&resp)["user"]["id"].as_str().unwrap().to_string();

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

    assert!(
        ctx.database
            .get_user_accounts(&user_id)
            .await
            .unwrap()
            .is_empty()
    );
}
