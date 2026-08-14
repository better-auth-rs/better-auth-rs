use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Duration;

use super::*;
use crate::plugins::test_helpers;
use better_auth_core::{CreatePasskey, CreateUser, HttpMethod};

fn passkey_plugin() -> PasskeyPlugin {
    PasskeyPlugin::new()
        .rp_id("localhost")
        .rp_name("Better Auth Test")
        .origin("http://localhost:3000")
}

fn cookie_header(response: &better_auth_core::AuthResponse) -> &str {
    response
        .headers
        .get("Set-Cookie")
        .expect("response should include a Set-Cookie header")
}

fn credential_id(label: &str) -> String {
    URL_SAFE_NO_PAD.encode(label.as_bytes())
}

#[test]
fn test_extract_passkey_snapshot_fields_requires_all_expected_fields() {
    let value = serde_json::json!({
        "cred": {
            "counter": 7,
            "backup_state": true
        }
    });

    let err = super::webauthn::extract_passkey_snapshot_fields(&value).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Internal server error: Stored passkey JSON missing backup_eligible"
    );
}

#[test]
fn test_extract_passkey_snapshot_fields_reads_expected_values() {
    let value = serde_json::json!({
        "cred": {
            "counter": 11,
            "backup_state": true,
            "backup_eligible": false
        }
    });

    let (counter, backed_up, backup_eligible) =
        super::webauthn::extract_passkey_snapshot_fields(&value).unwrap();
    assert_eq!(counter, 11);
    assert!(backed_up);
    assert!(!backup_eligible);
}

#[tokio::test]
async fn test_generate_register_options_sets_cookie_and_uses_query_name() {
    let plugin = passkey_plugin();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    ctx.database
        .create_passkey(CreatePasskey {
            user_id: user.id.clone(),
            name: Some("Existing Key".to_string()),
            credential_id: credential_id("cred-existing"),
            public_key: "public-key".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: Some("usb,nfc".to_string()),
            credential: "invalid-stored-passkey".to_string(),
            aaguid: Some("00000000-0000-0000-0000-000000000000".to_string()),
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_request(
        HttpMethod::Get,
        "/passkey/generate-register-options",
        Some(&session.token),
        None,
        HashMap::from([
            ("name".to_string(), "Custom Account Label".to_string()),
            (
                "authenticatorAttachment".to_string(),
                "cross-platform".to_string(),
            ),
        ]),
    );

    let response = plugin
        .handle_generate_register_options(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert!(cookie_header(&response).contains("better-auth-passkey="));

    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert!(body["challenge"].is_string());
    assert_eq!(body["user"]["name"], "Custom Account Label");
    assert_eq!(
        body["authenticatorSelection"]["authenticatorAttachment"],
        "cross-platform"
    );
    assert_eq!(
        body["excludeCredentials"][0]["id"],
        credential_id("cred-existing")
    );
    assert_eq!(body["excludeCredentials"][0]["transports"][0], "usb");
}

#[tokio::test]
async fn test_generate_authenticate_options_is_get_and_sets_cookie_without_auth() {
    let plugin = passkey_plugin();
    let ctx = test_helpers::create_test_context().await;
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/passkey/generate-authenticate-options",
        None,
        None,
    );

    let response = plugin
        .handle_generate_authenticate_options(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert!(cookie_header(&response).contains("better-auth-passkey="));

    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert!(body["challenge"].is_string());
    assert!(body.get("allowCredentials").is_none());
}

#[tokio::test]
async fn test_generate_authenticate_options_with_auth_lists_allow_credentials() {
    let plugin = passkey_plugin();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    ctx.database
        .create_passkey(CreatePasskey {
            user_id: user.id.clone(),
            name: Some("Authenticator".to_string()),
            credential_id: credential_id("cred-auth"),
            public_key: "public-key".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: Some("internal".to_string()),
            credential: "invalid-stored-passkey".to_string(),
            aaguid: None,
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/passkey/generate-authenticate-options",
        Some(&session.token),
        None,
    );

    let response = plugin
        .handle_generate_authenticate_options(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        body["allowCredentials"][0]["id"],
        credential_id("cred-auth")
    );
    assert_eq!(body["allowCredentials"][0]["transports"][0], "internal");
}

#[tokio::test]
async fn test_verify_registration_without_challenge_cookie_returns_challenge_not_found() {
    let plugin = passkey_plugin();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let body = serde_json::json!({
        "response": {
            "id": "fake-credential-id",
            "rawId": "ZmFrZS1yYXctaWQ",
            "response": {
                "attestationObject": "ZmFrZS1hdHRlc3RhdGlvbg",
                "clientDataJSON": "ZmFrZS1jbGllbnQtZGF0YQ"
            },
            "type": "public-key"
        }
    });
    let mut req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/verify-registration",
        Some(&session.token),
        Some(body),
    );
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());

    let response = plugin.handle_verify_registration(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 400);

    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["message"], "Challenge not found");
}

#[tokio::test]
async fn test_verify_authentication_without_challenge_cookie_returns_challenge_not_found() {
    let plugin = passkey_plugin();
    let ctx = test_helpers::create_test_context().await;

    let body = serde_json::json!({
        "response": {
            "id": credential_id("cred-auth"),
            "rawId": credential_id("cred-auth"),
            "response": {
                "authenticatorData": "ZmFrZS1hdXRoLWRhdGE",
                "clientDataJSON": "ZmFrZS1jbGllbnQtZGF0YQ",
                "signature": "ZmFrZS1zaWduYXR1cmU"
            },
            "type": "public-key"
        }
    });
    let mut req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/verify-authentication",
        None,
        Some(body),
    );
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());

    let response = plugin
        .handle_verify_authentication(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 400);

    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["message"], "Challenge not found");
}

#[tokio::test]
async fn test_list_user_passkeys_includes_updated_at_and_optional_fields() {
    let plugin = passkey_plugin();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    ctx.database
        .create_passkey(CreatePasskey {
            user_id: user.id.clone(),
            name: None,
            credential_id: credential_id("cred-list"),
            public_key: "public-key".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
            credential: "invalid-stored-passkey".to_string(),
            aaguid: Some("00000000-0000-0000-0000-000000000000".to_string()),
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/passkey/list-user-passkeys",
        Some(&session.token),
        None,
    );
    let response = plugin.handle_list_user_passkeys(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert!(body[0]["updatedAt"].is_string());
    assert_eq!(body[0]["aaguid"], "00000000-0000-0000-0000-000000000000");
    assert!(body[0].get("name").is_none());
}

#[tokio::test]
async fn test_delete_passkey_non_owner_is_forbidden() {
    let plugin = passkey_plugin();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("owner@example.com")
            .with_name("Owner"),
        Duration::hours(1),
    )
    .await;
    let other = test_helpers::create_user(
        &ctx,
        CreateUser::new()
            .with_email("other@example.com")
            .with_name("Other"),
    )
    .await;

    let passkey = ctx
        .database
        .create_passkey(CreatePasskey {
            user_id: other.id.clone(),
            name: Some("Other Key".to_string()),
            credential_id: credential_id("cred-other-delete"),
            public_key: "public-key".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
            credential: "invalid-stored-passkey".to_string(),
            aaguid: None,
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/delete-passkey",
        Some(&session.token),
        Some(serde_json::json!({ "id": passkey.id })),
    );

    let err = plugin.handle_delete_passkey(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 403);
    assert_eq!(err.to_string(), "Unauthorized");
}

#[tokio::test]
async fn test_update_passkey_non_owner_uses_ts_error_message() {
    let plugin = passkey_plugin();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("owner@example.com")
            .with_name("Owner"),
        Duration::hours(1),
    )
    .await;
    let other = test_helpers::create_user(
        &ctx,
        CreateUser::new()
            .with_email("other@example.com")
            .with_name("Other"),
    )
    .await;

    let passkey = ctx
        .database
        .create_passkey(CreatePasskey {
            user_id: other.id.clone(),
            name: Some("Other Key".to_string()),
            credential_id: credential_id("cred-other-update"),
            public_key: "public-key".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
            credential: "invalid-stored-passkey".to_string(),
            aaguid: None,
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/update-passkey",
        Some(&session.token),
        Some(serde_json::json!({
            "id": passkey.id,
            "name": "Hijacked",
        })),
    );

    let err = plugin.handle_update_passkey(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 403);
    assert_eq!(
        err.to_string(),
        "You are not allowed to register this passkey"
    );
}
