use super::*;
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthPlugin, CreateSession, CreateUser, HttpMethod, UpdateApiKey,
};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn create_test_context_with_user() -> (AuthContext<TestSchema>, UserView, SessionView) {
    let config = Arc::new(better_auth_core::AuthConfig::new(
        "test-secret-key-at-least-32-chars-long",
    ));
    let database = crate::plugins::test_helpers::create_test_database().await;
    let ctx = AuthContext::new(config, database.clone());

    let user = database
        .create_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
        )
        .await
        .unwrap();
    let wire_user = UserView::from(&user);

    let session = database
        .create_session(CreateSession {
            user_id: user.id().to_string(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    let wire_session = SessionView::from(&session);

    (ctx, wire_user, wire_session)
}

async fn create_user_with_session(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    email: &str,
) -> (UserView, SessionView) {
    let user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email(email.to_string())
                .with_name("Another User"),
        )
        .await
        .unwrap();
    let wire_user = UserView::from(&user);

    let session = ctx
        .database
        .create_session(CreateSession {
            user_id: user.id().to_string(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    let wire_session = SessionView::from(&session);

    (wire_user, wire_session)
}

fn create_auth_request(
    method: HttpMethod,
    path: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
    query: Option<HashMap<String, String>>,
) -> AuthRequest {
    let mut headers = HashMap::new();
    if let Some(token) = token {
        headers.insert("authorization".to_string(), format!("Bearer {}", token));
    }

    AuthRequest::from_parts(
        method,
        path.to_string(),
        headers,
        body.map(|b| serde_json::to_vec(&b).unwrap()),
        query.unwrap_or_default(),
    )
}

fn json_body(response: &AuthResponse) -> serde_json::Value {
    serde_json::from_slice(&response.body).unwrap()
}

/// Test helper: verify a key and return the same JSON shape the old HTTP
/// handler produced (`{ valid, error, key }`).  Calls `validate_api_key`
/// directly — no HTTP route involved.
async fn verify_key(
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    raw_key: &str,
    permissions: Option<&serde_json::Value>,
) -> serde_json::Value {
    match plugin.validate_api_key(ctx, raw_key, permissions).await {
        Ok(view) => serde_json::json!({ "valid": true, "error": null, "key": view }),
        Err(e) => serde_json::json!({
            "valid": false,
            "error": { "message": e.message, "code": e.code.as_str() },
            "key": null,
        }),
    }
}

/// Create a key via the HTTP handler (client-allowed fields only), then
/// patch server-only fields directly through the database.
///
/// `server_fields` may contain: remaining, refill_interval, refill_amount,
/// rate_limit_enabled, rate_limit_time_window, rate_limit_max, permissions.
async fn create_key_with_server_fields(
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    token: &str,
    client_body: serde_json::Value,
    server_fields: UpdateApiKey,
) -> (String, String) {
    let (id, raw_key) = create_key_and_get_raw(plugin, ctx, token, client_body).await;
    ctx.database
        .update_api_key(&id, server_fields)
        .await
        .unwrap();
    (id, raw_key)
}

/// Test helper: delete all expired keys and return a success JSON.
async fn delete_all_expired(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> serde_json::Value {
    let _ = ctx.database.delete_expired_api_keys().await.unwrap();
    serde_json::json!({ "success": true, "error": null })
}

async fn create_key_and_get_id(
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    token: &str,
    name: &str,
) -> String {
    let req = create_auth_request(
        HttpMethod::Post,
        "/api-key/create",
        Some(token),
        Some(serde_json::json!({ "name": name })),
        None,
    );
    let response = plugin.handle_create(&req, ctx).await.unwrap();
    assert_eq!(response.status, 200);
    json_body(&response)["id"].as_str().unwrap().to_string()
}

/// Helper: create a key and return (id, raw_key)
async fn create_key_and_get_raw(
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    token: &str,
    body: serde_json::Value,
) -> (String, String) {
    let req = create_auth_request(
        HttpMethod::Post,
        "/api-key/create",
        Some(token),
        Some(body),
        None,
    );
    let response = plugin.handle_create(&req, ctx).await.unwrap();
    assert_eq!(response.status, 200);
    let b = json_body(&response);
    (
        b["id"].as_str().unwrap().to_string(),
        b["key"].as_str().unwrap().to_string(),
    )
}

// -----------------------------------------------------------------------
// Existing tests (kept)
// -----------------------------------------------------------------------

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_create_and_get_do_not_expose_hash() {
    let plugin = ApiKeyPlugin::builder().prefix("ba_".to_string()).build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let create_req = create_auth_request(
        HttpMethod::Post,
        "/api-key/create",
        Some(&session.token),
        Some(serde_json::json!({ "name": "primary" })),
        None,
    );
    let create_response = plugin.handle_create(&create_req, &ctx).await.unwrap();
    assert_eq!(create_response.status, 200);

    let body = json_body(&create_response);
    assert!(body.get("key").is_some());
    assert!(body.get("key_hash").is_none());
    assert!(body.get("hash").is_none());

    let id = body["id"].as_str().unwrap();
    let mut query = HashMap::new();
    query.insert("id".to_string(), id.to_string());

    let get_req = create_auth_request(
        HttpMethod::Get,
        "/api-key/get",
        Some(&session.token),
        None,
        Some(query),
    );
    let get_response = plugin.handle_get(&get_req, &ctx).await.unwrap();
    assert_eq!(get_response.status, 200);

    let get_body = json_body(&get_response);
    assert!(get_body.get("key").is_none());
    assert!(get_body.get("key_hash").is_none());
}

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_create_rejects_invalid_expires_in() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let req = create_auth_request(
        HttpMethod::Post,
        "/api-key/create",
        Some(&session.token),
        Some(serde_json::json!({ "expiresIn": -1 })),
        None,
    );
    let response = plugin.handle_create(&req, &ctx).await;
    // Should be rejected due to validation (negative expires_in)
    assert!(response.is_err() || response.unwrap().status != 200);
}

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_get_update_delete_return_404_for_non_owner() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user1, session1) = create_test_context_with_user().await;
    let (_user2, session2) = create_user_with_session(&ctx, "other@example.com").await;
    let key_id = create_key_and_get_id(&plugin, &ctx, &session1.token, "owner-key").await;

    let mut get_query = HashMap::new();
    get_query.insert("id".to_string(), key_id.clone());
    let get_req = create_auth_request(
        HttpMethod::Get,
        "/api-key/get",
        Some(&session2.token),
        None,
        Some(get_query),
    );
    let get_err = plugin.handle_get(&get_req, &ctx).await.unwrap_err();
    assert_eq!(get_err.status_code(), 404);

    let update_req = create_auth_request(
        HttpMethod::Post,
        "/api-key/update",
        Some(&session2.token),
        Some(serde_json::json!({ "keyId": key_id, "name": "new-name" })),
        None,
    );
    let update_err = plugin.handle_update(&update_req, &ctx).await.unwrap_err();
    assert_eq!(update_err.status_code(), 404);

    let delete_req = create_auth_request(
        HttpMethod::Post,
        "/api-key/delete",
        Some(&session2.token),
        Some(serde_json::json!({ "keyId": key_id })),
        None,
    );
    let delete_err = plugin.handle_delete(&delete_req, &ctx).await.unwrap_err();
    assert_eq!(delete_err.status_code(), 404);
}

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_list_returns_only_user_keys() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, user1, session1) = create_test_context_with_user().await;
    let (_user2, session2) = create_user_with_session(&ctx, "other@example.com").await;

    let _ = create_key_and_get_id(&plugin, &ctx, &session1.token, "u1-key").await;
    let _ = create_key_and_get_id(&plugin, &ctx, &session2.token, "u2-key").await;

    let list_req = create_auth_request(
        HttpMethod::Get,
        "/api-key/list",
        Some(&session1.token),
        None,
        None,
    );
    let list_response = plugin.handle_list(&list_req, &ctx).await.unwrap();
    assert_eq!(list_response.status, 200);

    let list_body = json_body(&list_response);
    let list = list_body.as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["userId"].as_str().unwrap(), user1.id);
    assert!(list[0].get("key").is_none());
    assert!(list[0].get("key_hash").is_none());
}

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_owner_can_delete_key() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;
    let key_id = create_key_and_get_id(&plugin, &ctx, &session.token, "to-delete").await;

    let delete_req = create_auth_request(
        HttpMethod::Post,
        "/api-key/delete",
        Some(&session.token),
        Some(serde_json::json!({ "keyId": key_id })),
        None,
    );
    let delete_response = plugin.handle_delete(&delete_req, &ctx).await.unwrap();
    assert_eq!(delete_response.status, 200);

    let deleted = ctx.database.get_api_key_by_id(&key_id).await.unwrap();
    assert!(deleted.is_none());
}

// -----------------------------------------------------------------------
// New tests: verify, rate-limit, remaining/refill, delete expired, config
// -----------------------------------------------------------------------

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_verify_valid_key() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "verify-test" }),
    )
    .await;

    let body = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(body["valid"], true);
    assert!(body["key"].is_object());
}

#[tokio::test]
async fn test_verify_invalid_key() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, _session) = create_test_context_with_user().await;

    let body = verify_key(&plugin, &ctx, "definitely-not-a-valid-key", None).await;
    assert_eq!(body["valid"], false);
    assert!(body["error"].is_object());
}

#[tokio::test]
async fn test_verify_disabled_key() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (id, raw_key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "disable-test" }),
    )
    .await;

    let update = UpdateApiKey {
        enabled: Some(false),
        ..Default::default()
    };
    ctx.database.update_api_key(&id, update).await.unwrap();

    let body = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(body["valid"], false);
    assert_eq!(body["error"]["code"], "KEY_DISABLED");
}

#[tokio::test]
async fn test_verify_expired_key() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (id, raw_key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "expire-test" }),
    )
    .await;

    let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
    let update = UpdateApiKey {
        expires_at: Some(Some(past)),
        ..Default::default()
    };
    ctx.database.update_api_key(&id, update).await.unwrap();

    let body = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(body["valid"], false);
    assert_eq!(body["error"]["code"], "KEY_EXPIRED");

    // The key should have been deleted
    let deleted = ctx.database.get_api_key_by_id(&id).await.unwrap();
    assert!(deleted.is_none());
}

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_verify_remaining_consumption() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "remain-test" }),
        UpdateApiKey {
            remaining: Some(2),
            ..Default::default()
        },
    )
    .await;

    // First verify - remaining goes from 2 to 1
    let r1 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r1["valid"], true);
    assert_eq!(r1["key"]["remaining"], 1);

    // Second verify - remaining goes from 1 to 0
    let r2 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r2["valid"], true);
    assert_eq!(r2["key"]["remaining"], 0);

    // Third verify - should fail (usage exceeded)
    let r3 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r3["valid"], false);
    assert_eq!(r3["error"]["code"], "USAGE_EXCEEDED");
}

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_verify_rate_limiting() {
    let plugin = ApiKeyPlugin::builder()
        .rate_limit(RateLimitDefaults {
            enabled: true,
            time_window: 60_000,
            max_requests: 2,
        })
        .build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "rl-test" }),
        UpdateApiKey {
            rate_limit_enabled: Some(true),
            rate_limit_time_window: Some(60_000),
            rate_limit_max: Some(2),
            ..Default::default()
        },
    )
    .await;

    // First two should succeed
    let r1 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r1["valid"], true);

    let r2 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r2["valid"], true);

    // Third should fail with rate limit
    let r3 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r3["valid"], false);
    assert_eq!(r3["error"]["code"], "RATE_LIMITED");
}

#[tokio::test]
async fn test_delete_all_expired() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    // Create two keys
    let (id1, _) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "will-expire" }),
    )
    .await;
    let (_id2, _) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "wont-expire" }),
    )
    .await;

    // Expire the first key
    let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
    ctx.database
        .update_api_key(
            &id1,
            UpdateApiKey {
                expires_at: Some(Some(past)),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let body = delete_all_expired(&ctx).await;
    assert_eq!(body["success"], true);

    // Only the non-expired key should remain
    let remaining_keys = ctx.database.list_api_keys_by_user(&_user.id).await.unwrap();
    assert_eq!(remaining_keys.len(), 1);
}

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_verify_permissions() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "perm-test" }),
        UpdateApiKey {
            permissions: Some(
                serde_json::to_string(&serde_json::json!({
                    "admin": ["read", "write"],
                    "user": ["read"]
                }))
                .unwrap(),
            ),
            ..Default::default()
        },
    )
    .await;

    // Verify with matching permissions -> should pass
    let perms_ok = serde_json::json!({ "admin": ["read"] });
    let r1 = verify_key(&plugin, &ctx, &raw_key, Some(&perms_ok)).await;
    assert_eq!(r1["valid"], true);

    // Verify with non-matching permissions -> should fail
    let perms_fail = serde_json::json!({ "superadmin": ["delete"] });
    let r2 = verify_key(&plugin, &ctx, &raw_key, Some(&perms_fail)).await;
    assert_eq!(r2["valid"], false);
}

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_config_validation_prefix_length() {
    let plugin = ApiKeyPlugin::builder()
        .min_prefix_length(2)
        .max_prefix_length(5)
        .build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    // Too short prefix
    let req = create_auth_request(
        HttpMethod::Post,
        "/api-key/create",
        Some(&session.token),
        Some(serde_json::json!({ "name": "test", "prefix": "a" })),
        None,
    );
    let err = plugin.handle_create(&req, &ctx).await.unwrap_err();
    assert!(err.to_string().contains("prefix length"));

    // Too long prefix
    let req2 = create_auth_request(
        HttpMethod::Post,
        "/api-key/create",
        Some(&session.token),
        Some(serde_json::json!({ "name": "test", "prefix": "toolong" })),
        None,
    );
    let err2 = plugin.handle_create(&req2, &ctx).await.unwrap_err();
    assert!(err2.to_string().contains("prefix length"));
}

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_config_require_name() {
    let plugin = ApiKeyPlugin::builder().require_name(true).build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    // No name provided -> should fail
    let req = create_auth_request(
        HttpMethod::Post,
        "/api-key/create",
        Some(&session.token),
        Some(serde_json::json!({})),
        None,
    );
    let err = plugin.handle_create(&req, &ctx).await.unwrap_err();
    assert!(err.to_string().contains("name is required"));
}

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_config_metadata_disabled() {
    let plugin = ApiKeyPlugin::builder().build(); // enable_metadata defaults to false
    let (ctx, _user, session) = create_test_context_with_user().await;

    let req = create_auth_request(
        HttpMethod::Post,
        "/api-key/create",
        Some(&session.token),
        Some(serde_json::json!({ "name": "test", "metadata": { "env": "prod" } })),
        None,
    );
    let err = plugin.handle_create(&req, &ctx).await.unwrap_err();
    assert!(err.to_string().contains("Metadata is disabled"));
}

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_config_metadata_enabled() {
    let plugin = ApiKeyPlugin::builder().enable_metadata(true).build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let req = create_auth_request(
        HttpMethod::Post,
        "/api-key/create",
        Some(&session.token),
        Some(serde_json::json!({ "name": "test", "metadata": { "env": "prod" } })),
        None,
    );
    let resp = plugin.handle_create(&req, &ctx).await.unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert_eq!(body["metadata"]["env"], "prod");
}

// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_update_with_expires_in() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;
    let key_id = create_key_and_get_id(&plugin, &ctx, &session.token, "update-exp").await;

    let update_req = create_auth_request(
        HttpMethod::Post,
        "/api-key/update",
        Some(&session.token),
        Some(serde_json::json!({
            "keyId": key_id,
            "expiresIn": 86400
        })),
        None,
    );
    let resp = plugin.handle_update(&update_req, &ctx).await.unwrap();
    assert_eq!(resp.status, 200);
    let body = json_body(&resp);
    assert!(body["expiresAt"].is_string());
}

// Note: /api-key/verify and /api-key/delete-all-expired-api-keys are
// server-only in TS (no HTTP routes), so the Rust plugin does not expose
// them either. Route dispatch tests for these have been removed.

// Ensure refillInterval + refillAmount require each other (validation logic)
#[tokio::test]
async fn test_refill_logic() {
    let result = ApiKeyPlugin::validate_refill(Some(60_000), None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("refillAmount"));

    let result = ApiKeyPlugin::validate_refill(None, Some(10));
    assert!(result.is_err());

    let result = ApiKeyPlugin::validate_refill(Some(60_000), Some(10));
    assert!(result.is_ok());
}

// =======================================================================
// Comprehensive integration tests (9 scenarios from the test plan)
// =======================================================================

// 1. Virtual session: before_request injects session without DB writes
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_virtual_session_creates_no_db_session() {
    let plugin = ApiKeyPlugin::builder()
        .enable_session_for_api_keys(true)
        .build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    // Create an API key
    let (_id, raw_key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "virtual-session-test" }),
    )
    .await;

    // Count sessions before
    let sessions_before = ctx
        .database
        .get_user_sessions(&_user.id)
        .await
        .unwrap()
        .len();

    // Simulate a request to a protected route with only x-api-key header
    let mut headers = HashMap::new();
    headers.insert("x-api-key".to_string(), raw_key.clone());
    let req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/update-user".to_string(),
        headers,
        None,
        HashMap::new(),
    );

    // Call before_request -- should return InjectSession
    let action = plugin.before_request(&req, &ctx).await.unwrap();
    assert!(action.is_some(), "before_request should return an action");
    match action.unwrap() {
        BeforeRequestAction::InjectSession {
            user_id,
            session_token: _,
        } => {
            assert_eq!(user_id, _user.id);
        }
        BeforeRequestAction::Respond(_) => {
            panic!("Expected InjectSession, got Respond");
        }
    }

    // Count sessions after -- should be unchanged (no DB writes)
    let sessions_after = ctx
        .database
        .get_user_sessions(&_user.id)
        .await
        .unwrap()
        .len();
    assert_eq!(
        sessions_before, sessions_after,
        "No new sessions should be created in the database"
    );
}

// 2. Virtual session on /get-session: synthetic response
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_virtual_session_on_get_session() {
    let plugin = ApiKeyPlugin::builder()
        .enable_session_for_api_keys(true)
        .build();
    let (ctx, user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "get-session-test" }),
    )
    .await;

    // Send request to /get-session with x-api-key header
    let mut headers = HashMap::new();
    headers.insert("x-api-key".to_string(), raw_key.clone());
    let req = AuthRequest::from_parts(
        HttpMethod::Get,
        "/get-session".to_string(),
        headers,
        None,
        HashMap::new(),
    );

    let action = plugin.before_request(&req, &ctx).await.unwrap();
    assert!(action.is_some());
    match action.unwrap() {
        BeforeRequestAction::Respond(resp) => {
            assert_eq!(resp.status, 200);
            let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
            // Should contain user data
            assert_eq!(body["user"]["id"], user.id);
            assert_eq!(body["user"]["email"], "test@example.com");
            // Should contain session-like data
            assert!(body["session"]["id"].is_string());
            assert_eq!(body["session"]["userId"], user.id);
        }
        BeforeRequestAction::InjectSession { .. } => {
            panic!("Expected Respond for /get-session, got InjectSession");
        }
    }
}

// 3. Rate limiting: create key with rateLimitMax=2, 3rd call fails
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_rate_limiting_third_call_fails() {
    let plugin = ApiKeyPlugin::builder()
        .rate_limit(RateLimitDefaults {
            enabled: true,
            time_window: 60_000,
            max_requests: 2,
        })
        .build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "rl-integration" }),
        UpdateApiKey {
            rate_limit_enabled: Some(true),
            rate_limit_time_window: Some(60_000),
            rate_limit_max: Some(2),
            ..Default::default()
        },
    )
    .await;

    // First two pass
    let r1 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r1["valid"], true, "1st request should pass");

    let r2 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r2["valid"], true, "2nd request should pass");

    // Third should fail
    let r3 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r3["valid"], false, "3rd request should be rate-limited");
    assert_eq!(r3["error"]["code"], "RATE_LIMITED");
}

// 4. Remaining consumption: remaining=2, no refill, 3rd fails
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_remaining_consumption_no_refill() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "remaining-test" }),
        UpdateApiKey {
            remaining: Some(2),
            ..Default::default()
        },
    )
    .await;

    // 1st: remaining 2->1
    let r1 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r1["valid"], true);
    assert_eq!(r1["key"]["remaining"], 1);

    // 2nd: remaining 1->0
    let r2 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r2["valid"], true);
    assert_eq!(r2["key"]["remaining"], 0);

    // 3rd: usage exceeded
    let r3 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r3["valid"], false);
    assert_eq!(r3["error"]["code"], "USAGE_EXCEEDED");
}

// 5. Refill logic: remaining=1, refillInterval=100ms, refillAmount=10,
//    verify once -> remaining=0, wait 150ms, verify -> refill to 10 then
//    decrement to 9.
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_refill_resets_remaining_after_interval() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    // Use a very short refill interval for testing (100 ms)
    let (_id, raw_key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "refill-test" }),
        UpdateApiKey {
            remaining: Some(1),
            refill_interval: Some(100),
            refill_amount: Some(10),
            ..Default::default()
        },
    )
    .await;

    // First verify: remaining 1->0
    let r1 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r1["valid"], true);
    assert_eq!(r1["key"]["remaining"], 0);

    // Wait for refill interval to elapse
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Second verify: should refill to 10 and then decrement -> 9
    let r2 = verify_key(&plugin, &ctx, &raw_key, None).await;
    assert_eq!(r2["valid"], true, "Should succeed after refill");
    assert_eq!(r2["key"]["remaining"], 9, "Should be refillAmount - 1 = 9");
}

// 6. Permissions: key with {"admin": ["read"]}, verify with
//    {"admin": ["write"]} should fail
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_permissions_mismatch_fails() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "perm-mismatch" }),
        UpdateApiKey {
            permissions: Some(
                serde_json::to_string(&serde_json::json!({ "admin": ["read"] })).unwrap(),
            ),
            ..Default::default()
        },
    )
    .await;

    // Verify with matching permission -> pass
    let perms_ok = serde_json::json!({ "admin": ["read"] });
    let r1 = verify_key(&plugin, &ctx, &raw_key, Some(&perms_ok)).await;
    assert_eq!(r1["valid"], true);

    // Verify with mismatched permission -> fail
    let perms_fail = serde_json::json!({ "admin": ["write"] });
    let r2 = verify_key(&plugin, &ctx, &raw_key, Some(&perms_fail)).await;
    assert_eq!(r2["valid"], false);
}

// 7. Concurrent rate limiting: send 5 sequential verify requests with
//    rateLimitMax=2, only first 2 succeed (sequential proves logic is
//    correct; true concurrency race conditions are documented above).
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_concurrent_rate_limiting() {
    let plugin = ApiKeyPlugin::builder()
        .rate_limit(RateLimitDefaults {
            enabled: true,
            time_window: 60_000,
            max_requests: 2,
        })
        .build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_with_server_fields(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "concurrent-rl" }),
        UpdateApiKey {
            rate_limit_enabled: Some(true),
            rate_limit_time_window: Some(60_000),
            rate_limit_max: Some(2),
            ..Default::default()
        },
    )
    .await;

    let mut success_count = 0;
    let mut fail_count = 0;

    for _ in 0..5 {
        let body = verify_key(&plugin, &ctx, &raw_key, None).await;
        if body["valid"] == true {
            success_count += 1;
        } else {
            fail_count += 1;
            assert_eq!(body["error"]["code"], "RATE_LIMITED");
        }
    }

    assert_eq!(success_count, 2, "Only 2 out of 5 should succeed");
    assert_eq!(fail_count, 3, "3 out of 5 should be rate-limited");
}

// 8. Database compatibility: test delete_expired_api_keys through the
//    in-repo auth store implementation.
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_delete_expired_api_keys_memory_adapter() {
    let (ctx, _user, session) = create_test_context_with_user().await;
    let plugin = ApiKeyPlugin::builder().build();

    // Create two keys
    let (id1, _) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "will-expire" }),
    )
    .await;
    let (_id2, _) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "wont-expire" }),
    )
    .await;

    // Expire the first key by setting expires_at to the past
    let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
    ctx.database
        .update_api_key(
            &id1,
            UpdateApiKey {
                expires_at: Some(Some(past)),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Delete expired keys
    let deleted = ctx.database.delete_expired_api_keys().await.unwrap();
    assert_eq!(deleted, 1, "Should delete exactly 1 expired key");

    // Verify only the non-expired key remains
    let remaining = ctx.database.list_api_keys_by_user(&_user.id).await.unwrap();
    assert_eq!(remaining.len(), 1);
}

// 9. Delete expired: calling the store function directly removes only expired keys
#[tokio::test]
async fn test_delete_expired_removes_only_expired() {
    let plugin = ApiKeyPlugin::builder().build();
    let (ctx, _user, session) = create_test_context_with_user().await;

    // Create two keys, expire one
    let (id1, _) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "expired" }),
    )
    .await;
    let (_id2, _) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "active" }),
    )
    .await;

    let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
    ctx.database
        .update_api_key(
            &id1,
            UpdateApiKey {
                expires_at: Some(Some(past)),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let deleted = ctx.database.delete_expired_api_keys().await.unwrap();
    assert_eq!(deleted, 1);

    let remaining = ctx.database.list_api_keys_by_user(&_user.id).await.unwrap();
    assert_eq!(remaining.len(), 1);
}

// 10. before_request returns None when enableSessionForAPIKeys is false
// Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
#[tokio::test]
async fn test_before_request_disabled_returns_none() {
    let plugin = ApiKeyPlugin::builder().build(); // enable_session_for_api_keys defaults to false
    let (ctx, _user, session) = create_test_context_with_user().await;

    let (_id, raw_key) = create_key_and_get_raw(
        &plugin,
        &ctx,
        &session.token,
        serde_json::json!({ "name": "disabled-session" }),
    )
    .await;

    let mut headers = HashMap::new();
    headers.insert("x-api-key".to_string(), raw_key);
    let req = AuthRequest::from_parts(
        HttpMethod::Get,
        "/get-session".to_string(),
        headers,
        None,
        HashMap::new(),
    );

    let action = plugin.before_request(&req, &ctx).await.unwrap();
    assert!(
        action.is_none(),
        "before_request should return None when session emulation is disabled"
    );
}
