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
    let mut config = better_auth_core::AuthConfig::new("test-secret-key-at-least-32-chars-long");
    config.session.bearer = Some(Default::default());
    let config = Arc::new(config);
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
            user_id: user.id().into_owned(),
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
            user_id: user.id().into_owned(),
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
        Some(serde_json::json!(query.unwrap_or_default())),
    )
}

fn json_body(response: &AuthResponse) -> serde_json::Value {
    serde_json::from_slice(&response.body).unwrap()
}

/// Test helper: verify a key and return the same JSON shape the old HTTP
/// handler produced. Calls the public server-only verification method.
async fn verify_key(
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    raw_key: &str,
    permissions: Option<&serde_json::Value>,
) -> serde_json::Value {
    match plugin
        .verify_api_key(
            &VerifyApiKey {
                key: raw_key,
                config_id: None,
                permissions,
            },
            ctx,
        )
        .await
    {
        Ok(view) => serde_json::json!({ "valid": true, "error": null, "key": view }),
        Err(ApiKeyVerificationError::Validation(error)) => serde_json::json!({
            "valid": false,
            "error": error,
            "key": null,
        }),
        Err(
            ApiKeyVerificationError::Internal(error)
            | ApiKeyVerificationError::Endpoint(error)
            | ApiKeyVerificationError::Rejected(error),
        ) => panic!("Verification failed: {error}"),
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
        .update_api_key(&id.clone().into(), server_fields)
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
    // Upstream returns a paginated envelope rather than a bare array.
    let list = list_body["apiKeys"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list_body["total"], 1);
    // Upstream renamed the owner field to `referenceId` (a user or an
    // organization id) and stamps the owning configuration on every key.
    assert_eq!(
        list[0]["referenceId"].as_str().unwrap(),
        user1.id.typed().unwrap()
    );
    assert_eq!(list[0]["configId"].as_str().unwrap(), "default");
    assert!(list[0].get("userId").is_none());
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
    ctx.database
        .update_api_key(&id.clone().into(), update)
        .await
        .unwrap();

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
    ctx.database
        .update_api_key(&id.clone().into(), update)
        .await
        .unwrap();

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
            remaining: Some(2.0),
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
            time_window: 60_000.0,
            max_requests: 2.0,
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
            rate_limit_time_window: Some(60_000.0),
            rate_limit_max: Some(2.0),
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
            &id1.clone().into(),
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
    let remaining_keys = ctx
        .database
        .list_api_keys_by_reference(_user.id.typed().unwrap())
        .await
        .unwrap();
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
    let result = ApiKeyPlugin::validate_refill(Some(60_000.0), None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("refillAmount"));

    let result = ApiKeyPlugin::validate_refill(None, Some(10.0));
    assert!(result.is_err());

    let result = ApiKeyPlugin::validate_refill(Some(60_000.0), Some(10.0));
    assert!(result.is_ok());
}

#[path = "session_tests.rs"]
mod session_tests;

#[path = "verification_tests.rs"]
mod verification_tests;

async fn check_list_default_limit(ctx: &AuthContext<impl better_auth_core::AuthSchema>) {
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig::default());
    let mut keys = Vec::new();
    for (index, name) in ["D", "A", "E", "C", "B"].into_iter().enumerate() {
        let key = ctx
            .database
            .create_api_key(better_auth_core::CreateApiKey {
                reference_id: "list-owner".into(),
                config_id: "default".into(),
                name: Some(name.into()),
                key_hash: format!("stored-{index}"),
                prefix: None,
                start: None,
                expires_at: None,
                remaining: None,
                enabled: true,
                rate_limit_enabled: false,
                rate_limit_time_window: None,
                rate_limit_max: None,
                refill_interval: None,
                refill_amount: None,
                permissions: None,
                metadata: None,
            })
            .await
            .unwrap();
        keys.push(key);
    }
    assert_eq!(
        ctx.database
            .count_api_keys_by_reference("list-owner")
            .await
            .unwrap(),
        5
    );
    let query = types::ListKeysQuery {
        sort_by: Some("name".into()),
        sort_direction: Some("desc".into()),
        limit: Some(1),
        offset: Some(1),
        ..Default::default()
    };
    let result = handlers::list_keys_core("list-owner", &query, &plugin, ctx)
        .await
        .unwrap();
    assert_eq!(result.total, 2);
    assert_eq!(
        result
            .api_keys
            .iter()
            .map(|key| key.name.as_deref())
            .collect::<Vec<_>>(),
        [Some("D")]
    );
    assert_eq!((result.limit, result.offset), (Some(1), Some(1)));

    let cache = Arc::new(better_auth_core::store::MemoryCacheAdapter::new());
    for key in &keys {
        storage::put(cache.as_ref(), key, false).await.unwrap();
    }
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(cache),
        ..Default::default()
    });
    let result = handlers::list_keys_core("list-owner", &query, &plugin, ctx)
        .await
        .unwrap();
    assert_eq!(result.total, 5);
    assert_eq!(
        result
            .api_keys
            .iter()
            .map(|key| key.name.as_deref())
            .collect::<Vec<_>>(),
        [Some("D")]
    );

    let cache = Arc::new(better_auth_core::store::MemoryCacheAdapter::new());
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(cache),
        fallback_to_database: true,
        ..Default::default()
    });
    for _ in 0..2 {
        let result = handlers::list_keys_core("list-owner", &query, &plugin, ctx)
            .await
            .unwrap();
        assert_eq!(result.total, 2);
        assert_eq!(
            result
                .api_keys
                .iter()
                .map(|key| key.name.as_deref())
                .collect::<Vec<_>>(),
            [Some("D")]
        );
    }
    let cache = Arc::new(better_auth_core::store::MemoryCacheAdapter::new());
    for ((mut key, name), remaining) in keys
        .into_iter()
        .zip([
            Some("\u{e000}"),
            Some("\u{10000}"),
            Some("a"),
            None,
            Some("A"),
        ])
        .zip([Some(0.0), Some(-0.0), Some(1.0), Some(-1.0), None])
    {
        key.name = name.map(str::to_owned);
        key.remaining = remaining;
        storage::put(cache.as_ref(), &key, false).await.unwrap();
    }
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(cache),
        ..Default::default()
    });
    for direction in ["asc", "desc"] {
        let query = types::ListKeysQuery {
            sort_by: Some("name".into()),
            sort_direction: Some(direction.into()),
            ..Default::default()
        };
        let result = handlers::list_keys_core("list-owner", &query, &plugin, ctx)
            .await
            .unwrap();
        let mut expected = [
            None,
            Some("A"),
            Some("a"),
            Some("\u{10000}"),
            Some("\u{e000}"),
        ];
        if direction == "desc" {
            expected.reverse();
        }
        assert_eq!(
            result
                .api_keys
                .iter()
                .map(|key| key.name.as_deref())
                .collect::<Vec<_>>(),
            expected
        );
    }
    for (direction, expected) in [
        (
            "asc",
            [
                Some("A"),
                None,
                Some("\u{e000}"),
                Some("\u{10000}"),
                Some("a"),
            ],
        ),
        (
            "desc",
            [
                Some("a"),
                Some("\u{e000}"),
                Some("\u{10000}"),
                None,
                Some("A"),
            ],
        ),
    ] {
        let query = types::ListKeysQuery {
            sort_by: Some("remaining".into()),
            sort_direction: Some(direction.into()),
            ..Default::default()
        };
        let result = handlers::list_keys_core("list-owner", &query, &plugin, ctx)
            .await
            .unwrap();
        assert_eq!(
            result
                .api_keys
                .iter()
                .map(|key| key.name.as_deref())
                .collect::<Vec<_>>(),
            expected
        );
    }
}

#[tokio::test]
async fn list_memory_applies_adapter_default_before_public_pagination() {
    let mut config = crate::plugins::test_helpers::create_test_config();
    config.advanced.database.default_find_many_limit = Some(2.0);
    let config = Arc::new(config);
    let store = Arc::new(better_auth_core::store::EphemeralStore::new(config.clone()));
    let ctx = AuthContext::new(config, store);
    check_list_default_limit(&ctx).await;
}

#[tokio::test]
async fn list_sqlite_applies_adapter_default_before_public_pagination() {
    let mut config = crate::plugins::test_helpers::create_test_config();
    config.advanced.database.default_find_many_limit = Some(2.0);
    let config = Arc::new(config);
    let db = better_auth_seaorm::Database::connect("sqlite::memory:")
        .await
        .unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
        .await
        .unwrap();
    let store = Arc::new(better_auth_seaorm::SeaOrmStore::<TestSchema>::new(
        config.clone(),
        db,
    ));
    let ctx = AuthContext::new(config, store);
    check_list_default_limit(&ctx).await;
}
