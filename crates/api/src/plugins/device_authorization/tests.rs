use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use chrono::{Duration, Utc};
use serde_json::Value;

use better_auth_core::{AuthResponse, CreateDeviceCode, CreateUser, HttpMethod};

use crate::plugins::test_helpers;

use super::*;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

fn json_body(response: &AuthResponse) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}

fn device_token_request(device_code: &str, client_id: &str) -> better_auth_core::AuthRequest {
    test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/token",
        None,
        Some(serde_json::json!({
            "grant_type": DEVICE_GRANT_TYPE,
            "device_code": device_code,
            "client_id": client_id,
        })),
    )
}

fn device_verify_request(user_code: &str) -> better_auth_core::AuthRequest {
    let mut query = HashMap::new();
    let _ = query.insert("user_code".to_string(), user_code.to_string());
    test_helpers::create_auth_request(HttpMethod::Get, "/device", None, None, query)
}

async fn create_context_with_user(
    email: &str,
) -> (
    better_auth_core::AuthContext<TestSchema>,
    better_auth_core::wire::UserView,
    better_auth_core::wire::SessionView,
) {
    test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email(email.to_string())
            .with_name("Device Auth User"),
        Duration::hours(1),
    )
    .await
}

// Upstream source: packages/better-auth/src/plugins/device-authorization/routes.ts and device-authorization.test.ts; adapted to the Rust plugin handlers.
#[tokio::test]
async fn test_device_code_response_shape_and_storage() {
    let plugin = DeviceAuthorizationPlugin::new()
        .expires_in(Duration::minutes(5))
        .interval(Duration::seconds(2))
        .verification_uri("/auth/device?lang=en");
    let ctx = test_helpers::create_test_context().await;

    let request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/code",
        None,
        Some(serde_json::json!({
            "client_id": "test-client",
            "scope": "openid profile",
        })),
    );

    let response = plugin.handle_device_code(&request, &ctx).await.unwrap();
    let body = json_body(&response);

    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("Cache-Control"),
        Some(&"no-store".to_string())
    );
    assert_eq!(body["expires_in"], 300);
    assert_eq!(body["interval"], 2);
    assert!(body["device_code"].as_str().unwrap().len() >= 40);
    assert!(body["user_code"].as_str().unwrap().len() >= 8);
    assert!(
        body["user_code"]
            .as_str()
            .unwrap()
            .chars()
            .all(|char| { DEFAULT_USER_CODE_CHARSET.contains(&(char as u8)) })
    );
    assert!(
        body["verification_uri"]
            .as_str()
            .unwrap()
            .contains("/auth/device?lang=en")
    );
    assert!(
        body["verification_uri_complete"]
            .as_str()
            .unwrap()
            .contains("lang=en")
    );
    assert!(
        body["verification_uri_complete"]
            .as_str()
            .unwrap()
            .contains("user_code=")
    );

    let stored = ctx
        .database
        .get_device_code_by_device_code(body["device_code"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.polling_interval, Some(2000));
    assert_eq!(stored.client_id.as_deref(), Some("test-client"));
    assert_eq!(stored.scope.as_deref(), Some("openid profile"));
}

// Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: client validation scenarios; adapted to the Rust plugin builder API.
#[tokio::test]
async fn test_device_code_rejects_invalid_client() {
    let plugin = DeviceAuthorizationPlugin::new()
        .validate_client(|client_id| async move { Ok(client_id == "valid-client") });
    let ctx = test_helpers::create_test_context().await;

    let request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/code",
        None,
        Some(serde_json::json!({
            "client_id": "invalid-client",
        })),
    );

    let response = plugin.handle_device_code(&request, &ctx).await.unwrap();
    let body = json_body(&response);

    assert_eq!(response.status, 400);
    assert_eq!(body["error"], "invalid_client");
    assert_eq!(body["error_description"], INVALID_CLIENT_ID);
}

// Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: callback/generator coverage; adapted to the Rust plugin builder API.
#[tokio::test]
async fn test_device_code_uses_custom_generators_and_hook() {
    let hook_calls = Arc::new(AtomicUsize::new(0));
    let hook_calls_clone = hook_calls.clone();
    let plugin = DeviceAuthorizationPlugin::new()
        .generate_device_code_with(|| "custom-device-code".to_string())
        .generate_user_code_with(|| "CUSTOM12".to_string())
        .on_device_auth_request(move |client_id, scope| {
            let hook_calls = hook_calls_clone.clone();
            async move {
                assert_eq!(client_id, "hook-client");
                assert_eq!(scope.as_deref(), Some("openid"));
                hook_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .verification_uri("https://example.com/device");
    let ctx = test_helpers::create_test_context().await;

    let request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/code",
        None,
        Some(serde_json::json!({
            "client_id": "hook-client",
            "scope": "openid",
        })),
    );

    let response = plugin.handle_device_code(&request, &ctx).await.unwrap();
    let body = json_body(&response);

    assert_eq!(body["device_code"], "custom-device-code");
    assert_eq!(body["user_code"], "CUSTOM12");
    assert_eq!(body["verification_uri"], "https://example.com/device");
    assert_eq!(
        body["verification_uri_complete"],
        "https://example.com/device?user_code=CUSTOM12"
    );
    assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
}

// Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: "should return authorization_pending when not approved".
#[tokio::test]
async fn test_device_token_pending_returns_authorization_pending() {
    let plugin = DeviceAuthorizationPlugin::new();
    let ctx = test_helpers::create_test_context().await;

    let create_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/code",
        None,
        Some(serde_json::json!({ "client_id": "test-client" })),
    );
    let create_response = plugin
        .handle_device_code(&create_request, &ctx)
        .await
        .unwrap();
    let create_body = json_body(&create_response);

    let token_request =
        device_token_request(create_body["device_code"].as_str().unwrap(), "test-client");
    let token_response = plugin
        .handle_device_token(&token_request, &ctx)
        .await
        .unwrap();
    let token_body = json_body(&token_response);

    assert_eq!(token_response.status, 400);
    assert_eq!(token_body["error"], "authorization_pending");
    assert_eq!(token_body["error_description"], AUTHORIZATION_PENDING);
}

// Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: "should return expired_token for expired device codes".
#[tokio::test]
async fn test_device_token_expired_returns_error_and_deletes_record() {
    let plugin = DeviceAuthorizationPlugin::new();
    let ctx = test_helpers::create_test_context().await;

    let stored = ctx
        .database
        .create_device_code(CreateDeviceCode {
            device_code: "expired-device-code".to_string(),
            user_code: "EXPIRED12".to_string(),
            user_id: None,
            expires_at: Utc::now() - Duration::seconds(1),
            status: DEVICE_STATUS_PENDING.to_string(),
            last_polled_at: None,
            polling_interval: Some(5000),
            client_id: Some("test-client".to_string()),
            scope: None,
        })
        .await
        .unwrap();

    let response = plugin
        .handle_device_token(
            &device_token_request(&stored.device_code, "test-client"),
            &ctx,
        )
        .await
        .unwrap();
    let body = json_body(&response);

    assert_eq!(response.status, 400);
    assert_eq!(body["error"], "expired_token");
    assert_eq!(body["error_description"], EXPIRED_DEVICE_CODE);
    assert!(
        ctx.database
            .get_device_code_by_device_code(&stored.device_code)
            .await
            .unwrap()
            .is_none()
    );
}

// Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: "should return error for invalid device code".
#[tokio::test]
async fn test_device_token_invalid_device_code_returns_invalid_grant() {
    let plugin = DeviceAuthorizationPlugin::new();
    let ctx = test_helpers::create_test_context().await;

    let response = plugin
        .handle_device_token(
            &device_token_request("invalid-device-code", "test-client"),
            &ctx,
        )
        .await
        .unwrap();
    let body = json_body(&response);

    assert_eq!(response.status, 400);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], INVALID_DEVICE_CODE);
}

// Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: "should enforce rate limiting with slow_down error".
#[tokio::test]
async fn test_device_token_rate_limits_with_slow_down() {
    let plugin = DeviceAuthorizationPlugin::new().interval(Duration::seconds(5));
    let ctx = test_helpers::create_test_context().await;

    let create_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/code",
        None,
        Some(serde_json::json!({ "client_id": "test-client" })),
    );
    let create_response = plugin
        .handle_device_code(&create_request, &ctx)
        .await
        .unwrap();
    let create_body = json_body(&create_response);
    let device_code = create_body["device_code"].as_str().unwrap();

    let first = plugin
        .handle_device_token(&device_token_request(device_code, "test-client"), &ctx)
        .await
        .unwrap();
    assert_eq!(json_body(&first)["error"], "authorization_pending");

    let second = plugin
        .handle_device_token(&device_token_request(device_code, "test-client"), &ctx)
        .await
        .unwrap();
    let second_body = json_body(&second);

    assert_eq!(second.status, 400);
    assert_eq!(second_body["error"], "slow_down");
    assert_eq!(second_body["error_description"], POLLING_TOO_FREQUENTLY);
}

// Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: verification scenarios.
#[tokio::test]
async fn test_device_verify_strips_hyphens_and_preserves_input_shape() {
    let plugin = DeviceAuthorizationPlugin::new();
    let ctx = test_helpers::create_test_context().await;

    ctx.database
        .create_device_code(CreateDeviceCode {
            device_code: "verify-device-code".to_string(),
            user_code: "ABCD1234".to_string(),
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(5),
            status: DEVICE_STATUS_PENDING.to_string(),
            last_polled_at: None,
            polling_interval: Some(5000),
            client_id: Some("test-client".to_string()),
            scope: None,
        })
        .await
        .unwrap();

    let response = plugin
        .handle_device_verify(&device_verify_request("ABCD-1234"), &ctx)
        .await
        .unwrap();
    let body = json_body(&response);

    assert_eq!(response.status, 200);
    assert_eq!(body["user_code"], "ABCD-1234");
    assert_eq!(body["status"], DEVICE_STATUS_PENDING);
}

// Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: invalid user code verification.
#[tokio::test]
async fn test_device_verify_invalid_user_code_returns_error() {
    let plugin = DeviceAuthorizationPlugin::new();
    let ctx = test_helpers::create_test_context().await;

    let response = plugin
        .handle_device_verify(&device_verify_request("INVALID"), &ctx)
        .await
        .unwrap();
    let body = json_body(&response);

    assert_eq!(response.status, 400);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], INVALID_USER_CODE);
}

// Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: approval flow, scope preservation, and OAuth-compliant token response.
#[tokio::test]
async fn test_device_approve_flow_creates_session_and_returns_oauth_token_response() {
    let plugin = DeviceAuthorizationPlugin::new();
    let (ctx, _user, session) = create_context_with_user("approve@example.com").await;

    let create_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/code",
        None,
        Some(serde_json::json!({
            "client_id": "test-client",
            "scope": "read write profile",
        })),
    );
    let create_response = plugin
        .handle_device_code(&create_request, &ctx)
        .await
        .unwrap();
    let create_body = json_body(&create_response);
    let device_code = create_body["device_code"].as_str().unwrap().to_string();
    let user_code = create_body["user_code"].as_str().unwrap().to_string();

    let approve_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/approve",
        Some(&session.token),
        Some(serde_json::json!({ "userCode": user_code })),
    );
    let approve_response = plugin
        .handle_device_approve(&approve_request, &ctx)
        .await
        .unwrap();
    assert_eq!(json_body(&approve_response)["success"], true);

    let token_response = plugin
        .handle_device_token(&device_token_request(&device_code, "test-client"), &ctx)
        .await
        .unwrap();
    let token_body = json_body(&token_response);

    assert_eq!(token_response.status, 200);
    assert_eq!(
        token_response.headers.get("Cache-Control"),
        Some(&"no-store".to_string())
    );
    assert_eq!(
        token_response.headers.get("Pragma"),
        Some(&"no-cache".to_string())
    );
    assert_eq!(token_body["token_type"], "Bearer");
    assert_eq!(token_body["scope"], "read write profile");
    assert!(token_body["expires_in"].as_i64().unwrap() > 0);

    let access_token = token_body["access_token"].as_str().unwrap();
    assert!(
        ctx.database
            .get_session(access_token)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        ctx.database
            .get_device_code_by_device_code(&device_code)
            .await
            .unwrap()
            .is_none()
    );
}

// Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: denial flow.
#[tokio::test]
async fn test_device_deny_flow_returns_access_denied_and_deletes_record() {
    let plugin = DeviceAuthorizationPlugin::new();
    let (ctx, _user, session) = create_context_with_user("deny@example.com").await;

    let create_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/code",
        None,
        Some(serde_json::json!({ "client_id": "test-client" })),
    );
    let create_response = plugin
        .handle_device_code(&create_request, &ctx)
        .await
        .unwrap();
    let create_body = json_body(&create_response);
    let device_code = create_body["device_code"].as_str().unwrap().to_string();
    let user_code = create_body["user_code"].as_str().unwrap().to_string();

    let deny_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/deny",
        Some(&session.token),
        Some(serde_json::json!({ "userCode": user_code })),
    );
    let deny_response = plugin
        .handle_device_deny(&deny_request, &ctx)
        .await
        .unwrap();
    assert_eq!(json_body(&deny_response)["success"], true);

    let token_response = plugin
        .handle_device_token(&device_token_request(&device_code, "test-client"), &ctx)
        .await
        .unwrap();
    let token_body = json_body(&token_response);

    assert_eq!(token_response.status, 400);
    assert_eq!(token_body["error"], "access_denied");
    assert_eq!(token_body["error_description"], ACCESS_DENIED);
    assert!(
        ctx.database
            .get_device_code_by_device_code(&device_code)
            .await
            .unwrap()
            .is_none()
    );
}

// Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: auth-required and double-processing guard scenarios.
#[tokio::test]
async fn test_device_approve_requires_authentication_and_blocks_double_processing() {
    let plugin = DeviceAuthorizationPlugin::new();
    let (ctx, _user, session) = create_context_with_user("double@example.com").await;

    let create_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/code",
        None,
        Some(serde_json::json!({ "client_id": "test-client" })),
    );
    let create_response = plugin
        .handle_device_code(&create_request, &ctx)
        .await
        .unwrap();
    let create_body = json_body(&create_response);
    let user_code = create_body["user_code"].as_str().unwrap().to_string();

    let unauthenticated_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/approve",
        None,
        Some(serde_json::json!({ "userCode": user_code.clone() })),
    );
    let unauthenticated_response = plugin
        .handle_device_approve(&unauthenticated_request, &ctx)
        .await
        .unwrap();
    let unauthenticated_body = json_body(&unauthenticated_response);
    assert_eq!(unauthenticated_response.status, 401);
    assert_eq!(unauthenticated_body["error"], "unauthorized");
    assert_eq!(
        unauthenticated_body["error_description"],
        AUTHENTICATION_REQUIRED
    );

    let approve_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/approve",
        Some(&session.token),
        Some(serde_json::json!({ "userCode": user_code.clone() })),
    );
    let first_response = plugin
        .handle_device_approve(&approve_request, &ctx)
        .await
        .unwrap();
    assert_eq!(json_body(&first_response)["success"], true);

    let second_response = plugin
        .handle_device_approve(&approve_request, &ctx)
        .await
        .unwrap();
    let second_body = json_body(&second_response);
    assert_eq!(second_response.status, 400);
    assert_eq!(second_body["error"], "invalid_request");
    assert_eq!(
        second_body["error_description"],
        DEVICE_CODE_ALREADY_PROCESSED
    );
}

// Deliberate hardening divergence from the current TS runtime: exactly one
// approval request may process a pending device code.
#[tokio::test]
async fn test_device_approve_allows_only_one_concurrent_decision() {
    let plugin = DeviceAuthorizationPlugin::new();
    let (ctx, _user, session) = create_context_with_user("decision-race@example.com").await;

    let create_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/code",
        None,
        Some(serde_json::json!({ "client_id": "test-client" })),
    );
    let create_response = plugin
        .handle_device_code(&create_request, &ctx)
        .await
        .unwrap();
    let create_body = json_body(&create_response);
    let user_code = create_body["user_code"].as_str().unwrap().to_string();

    let first_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/approve",
        Some(&session.token),
        Some(serde_json::json!({ "userCode": user_code.clone() })),
    );
    let second_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/approve",
        Some(&session.token),
        Some(serde_json::json!({ "userCode": user_code })),
    );

    let (first_response, second_response) = tokio::join!(
        plugin.handle_device_approve(&first_request, &ctx),
        plugin.handle_device_approve(&second_request, &ctx),
    );

    let first_response = first_response.unwrap();
    let second_response = second_response.unwrap();

    let success_count = [first_response.status, second_response.status]
        .into_iter()
        .filter(|status| *status == 200)
        .count();
    assert_eq!(success_count, 1);

    let already_processed_count = [json_body(&first_response), json_body(&second_response)]
        .into_iter()
        .filter(|body| {
            body["error"] == "invalid_request"
                && body["error_description"] == DEVICE_CODE_ALREADY_PROCESSED
        })
        .count();
    assert_eq!(already_processed_count, 1);
}

// Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: client mismatch scenario.
#[tokio::test]
async fn test_device_token_rejects_client_id_mismatch() {
    let plugin = DeviceAuthorizationPlugin::new();
    let ctx = test_helpers::create_test_context().await;

    let create_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/code",
        None,
        Some(serde_json::json!({ "client_id": "client-a" })),
    );
    let create_response = plugin
        .handle_device_code(&create_request, &ctx)
        .await
        .unwrap();
    let create_body = json_body(&create_response);

    let response = plugin
        .handle_device_token(
            &device_token_request(create_body["device_code"].as_str().unwrap(), "client-b"),
            &ctx,
        )
        .await
        .unwrap();
    let body = json_body(&response);

    assert_eq!(response.status, 400);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], CLIENT_ID_MISMATCH);
}

// Deliberate hardening divergence from the current TS runtime: exactly one
// poller may redeem an approved device code.
#[tokio::test]
async fn test_device_token_allows_only_one_concurrent_redemption() {
    let plugin = DeviceAuthorizationPlugin::new();
    let (ctx, _user, session) = create_context_with_user("concurrent@example.com").await;

    let create_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/code",
        None,
        Some(serde_json::json!({ "client_id": "test-client" })),
    );
    let create_response = plugin
        .handle_device_code(&create_request, &ctx)
        .await
        .unwrap();
    let create_body = json_body(&create_response);
    let device_code = create_body["device_code"].as_str().unwrap().to_string();
    let user_code = create_body["user_code"].as_str().unwrap().to_string();

    let approve_request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/device/approve",
        Some(&session.token),
        Some(serde_json::json!({ "userCode": user_code })),
    );
    let approve_response = plugin
        .handle_device_approve(&approve_request, &ctx)
        .await
        .unwrap();
    assert_eq!(json_body(&approve_response)["success"], true);

    let first_request = device_token_request(&device_code, "test-client");
    let second_request = device_token_request(&device_code, "test-client");

    let (first_response, second_response) = tokio::join!(
        plugin.handle_device_token(&first_request, &ctx),
        plugin.handle_device_token(&second_request, &ctx),
    );

    let first_response = first_response.unwrap();
    let second_response = second_response.unwrap();

    let success_count = [first_response.status, second_response.status]
        .into_iter()
        .filter(|status| *status == 200)
        .count();
    assert_eq!(success_count, 1);

    let invalid_grant_count = [json_body(&first_response), json_body(&second_response)]
        .into_iter()
        .filter(|body| body["error"] == "invalid_grant")
        .count();
    assert_eq!(invalid_grant_count, 1);
}
