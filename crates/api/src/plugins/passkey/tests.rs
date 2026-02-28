use super::*;
use crate::plugins::test_helpers;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_auth_core::adapters::{PasskeyOps, UserOps, VerificationOps};
use better_auth_core::entity::AuthPasskey;
use better_auth_core::{CreatePasskey, CreateUser, CreateVerification, HttpMethod};
use chrono::{Duration, Utc};

fn encoded_client_data(challenge: &str, client_type: &str, origin: &str) -> String {
    let client_data = serde_json::json!({
        "type": client_type,
        "challenge": challenge,
        "origin": origin,
    });
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&client_data).unwrap())
}

#[tokio::test]
async fn test_verify_registration_requires_insecure_opt_in() {
    let plugin = PasskeyPlugin::new();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let body = serde_json::json!({
        "response": {
            "id": "cred-1",
            "response": {
                "clientDataJSON": encoded_client_data("challenge-1", "webauthn.create", "http://localhost:3000"),
            }
        }
    });

    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/verify-registration",
        Some(&session.token),
        Some(body),
    );

    let err = plugin
        .handle_verify_registration(&req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 501);
}

#[tokio::test]
async fn test_verify_registration_consumes_exact_challenge_once() {
    let plugin = PasskeyPlugin::new().allow_insecure_unverified_assertion(true);
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let challenge = "register-challenge";
    let identifier = format!("passkey_reg:{}", user.id);

    ctx.database
        .create_verification(CreateVerification {
            identifier: identifier.clone(),
            value: challenge.to_string(),
            expires_at: Utc::now() + Duration::minutes(5),
        })
        .await
        .unwrap();

    let wrong_body = serde_json::json!({
        "response": {
            "id": "cred-reg-1",
            "response": {
                "clientDataJSON": encoded_client_data("wrong-challenge", "webauthn.create", "http://localhost:3000"),
                "attestationObject": "fake-attestation",
            }
        }
    });
    let wrong_req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/verify-registration",
        Some(&session.token),
        Some(wrong_body),
    );
    let err = plugin
        .handle_verify_registration(&wrong_req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 400);

    assert!(
        ctx.database
            .get_verification(&identifier, challenge)
            .await
            .unwrap()
            .is_some()
    );

    let ok_body = serde_json::json!({
        "response": {
            "id": "cred-reg-1",
            "response": {
                "clientDataJSON": encoded_client_data(challenge, "webauthn.create", "http://localhost:3000"),
                "attestationObject": "fake-attestation",
            }
        }
    });
    let ok_req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/verify-registration",
        Some(&session.token),
        Some(ok_body),
    );
    let response = plugin
        .handle_verify_registration(&ok_req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    assert!(
        ctx.database
            .get_verification(&identifier, challenge)
            .await
            .unwrap()
            .is_none()
    );

    let passkeys = ctx.database.list_passkeys_by_user(&user.id).await.unwrap();
    assert_eq!(passkeys.len(), 1);
}

#[tokio::test]
async fn test_verify_authentication_checks_type_origin_and_prevents_replay() {
    let plugin = PasskeyPlugin::new().allow_insecure_unverified_assertion(true);
    let (ctx, user, _session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let credential_id = "cred-auth-1";
    ctx.database
        .create_passkey(CreatePasskey {
            user_id: user.id.clone(),
            name: "Authenticator".to_string(),
            credential_id: credential_id.to_string(),
            public_key: "fake-public-key".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
        })
        .await
        .unwrap();

    let challenge = "auth-challenge-1";
    let identifier = format!("passkey_auth:{}", challenge);

    ctx.database
        .create_verification(CreateVerification {
            identifier: identifier.clone(),
            value: challenge.to_string(),
            expires_at: Utc::now() + Duration::minutes(5),
        })
        .await
        .unwrap();

    let wrong_type_body = serde_json::json!({
        "response": {
            "id": credential_id,
            "response": {
                "clientDataJSON": encoded_client_data(challenge, "webauthn.create", "http://localhost:3000"),
            }
        }
    });
    let wrong_type_req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/verify-authentication",
        None,
        Some(wrong_type_body),
    );
    let err = plugin
        .handle_verify_authentication(&wrong_type_req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 400);

    let wrong_origin_body = serde_json::json!({
        "response": {
            "id": credential_id,
            "response": {
                "clientDataJSON": encoded_client_data(challenge, "webauthn.get", "http://evil.example"),
            }
        }
    });
    let wrong_origin_req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/verify-authentication",
        None,
        Some(wrong_origin_body),
    );
    let err = plugin
        .handle_verify_authentication(&wrong_origin_req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 400);

    assert!(
        ctx.database
            .get_verification(&identifier, challenge)
            .await
            .unwrap()
            .is_some()
    );

    let ok_body = serde_json::json!({
        "response": {
            "id": credential_id,
            "response": {
                "clientDataJSON": encoded_client_data(challenge, "webauthn.get", "http://localhost:3000"),
            }
        }
    });
    let ok_req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/verify-authentication",
        None,
        Some(ok_body.clone()),
    );
    let response = plugin
        .handle_verify_authentication(&ok_req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    assert!(
        ctx.database
            .get_verification(&identifier, challenge)
            .await
            .unwrap()
            .is_none()
    );

    let replay_req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/verify-authentication",
        None,
        Some(ok_body),
    );
    let err = plugin
        .handle_verify_authentication(&replay_req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 400);

    let passkey = ctx
        .database
        .get_passkey_by_credential_id(credential_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(passkey.counter(), 1);
}

#[tokio::test]
async fn test_generate_register_options_returns_challenge_and_stores_verification() {
    let plugin = PasskeyPlugin::new();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Get,
        "/passkey/generate-register-options",
        Some(&session.token),
        None,
    );

    let response = plugin
        .handle_generate_register_options(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert!(body["challenge"].is_string());
    assert_eq!(body["rp"]["id"], "localhost");
    assert_eq!(body["rp"]["name"], "Better Auth");
    assert!(body["user"]["id"].is_string());
    assert!(body["pubKeyCredParams"].is_array());
    assert!(body["excludeCredentials"].is_array());

    // Verify challenge was stored
    let challenge = body["challenge"].as_str().unwrap();
    let identifier = format!("passkey_reg:{}", user.id);
    let verification = ctx
        .database
        .get_verification(&identifier, challenge)
        .await
        .unwrap();
    assert!(verification.is_some());
}

#[tokio::test]
async fn test_generate_register_options_unauthenticated() {
    let plugin = PasskeyPlugin::new();
    let (ctx, _user, _session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Get,
        "/passkey/generate-register-options",
        None,
        None,
    );

    let err = plugin
        .handle_generate_register_options(&req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 401);
}

#[tokio::test]
async fn test_generate_authenticate_options_returns_challenge() {
    let plugin = PasskeyPlugin::new();
    let (ctx, _user, _session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    // No auth required for this endpoint
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/generate-authenticate-options",
        None,
        None,
    );

    let response = plugin
        .handle_generate_authenticate_options(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert!(body["challenge"].is_string());
    assert_eq!(body["rpId"], "localhost");
    assert!(body["allowCredentials"].is_array());
    assert_eq!(body["allowCredentials"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_generate_authenticate_options_with_auth_includes_credentials() {
    let plugin = PasskeyPlugin::new();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    // Create a passkey for the user
    ctx.database
        .create_passkey(CreatePasskey {
            user_id: user.id.clone(),
            name: "Test Key".to_string(),
            credential_id: "cred-gen-auth-1".to_string(),
            public_key: "pk".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: Some("[\"usb\"]".to_string()),
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
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
    let allow = body["allowCredentials"].as_array().unwrap();
    assert_eq!(allow.len(), 1);
    assert_eq!(allow[0]["id"], "cred-gen-auth-1");
}

#[tokio::test]
async fn test_list_user_passkeys() {
    let plugin = PasskeyPlugin::new();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    // No passkeys yet
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Get,
        "/passkey/list-user-passkeys",
        Some(&session.token),
        None,
    );
    let response = plugin.handle_list_user_passkeys(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);
    let body: Vec<serde_json::Value> = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body.len(), 0);

    // Create a passkey
    ctx.database
        .create_passkey(CreatePasskey {
            user_id: user.id.clone(),
            name: "My Key".to_string(),
            credential_id: "cred-list-1".to_string(),
            public_key: "pk".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
        })
        .await
        .unwrap();

    let response = plugin.handle_list_user_passkeys(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);
    let body: Vec<serde_json::Value> = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body.len(), 1);
    assert_eq!(body[0]["name"], "My Key");
    assert_eq!(body[0]["credentialID"], "cred-list-1");
}

#[tokio::test]
async fn test_list_user_passkeys_unauthenticated() {
    let plugin = PasskeyPlugin::new();
    let (ctx, _user, _session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Get,
        "/passkey/list-user-passkeys",
        None,
        None,
    );
    let err = plugin
        .handle_list_user_passkeys(&req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 401);
}

#[tokio::test]
async fn test_delete_passkey_success() {
    let plugin = PasskeyPlugin::new();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let passkey = ctx
        .database
        .create_passkey(CreatePasskey {
            user_id: user.id.clone(),
            name: "To Delete".to_string(),
            credential_id: "cred-del-1".to_string(),
            public_key: "pk".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
        })
        .await
        .unwrap();

    let body = serde_json::json!({ "id": passkey.id });
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/delete-passkey",
        Some(&session.token),
        Some(body),
    );

    let response = plugin.handle_delete_passkey(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    // Verify deleted
    let result = ctx.database.get_passkey_by_id(&passkey.id).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_delete_passkey_non_owner_rejected() {
    let plugin = PasskeyPlugin::new();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    // Create another user's passkey
    let other_user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("other@example.com")
                .with_name("Other User"),
        )
        .await
        .unwrap();

    let passkey = ctx
        .database
        .create_passkey(CreatePasskey {
            user_id: other_user.id.clone(),
            name: "Other's Key".to_string(),
            credential_id: "cred-other-del".to_string(),
            public_key: "pk".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
        })
        .await
        .unwrap();

    let body = serde_json::json!({ "id": passkey.id });
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/delete-passkey",
        Some(&session.token),
        Some(body),
    );

    let err = plugin.handle_delete_passkey(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 404);

    // Verify NOT deleted
    let result = ctx.database.get_passkey_by_id(&passkey.id).await.unwrap();
    assert!(result.is_some());
}

#[tokio::test]
async fn test_update_passkey_success() {
    let plugin = PasskeyPlugin::new();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let passkey = ctx
        .database
        .create_passkey(CreatePasskey {
            user_id: user.id.clone(),
            name: "Old Name".to_string(),
            credential_id: "cred-upd-1".to_string(),
            public_key: "pk".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
        })
        .await
        .unwrap();

    let body = serde_json::json!({ "id": passkey.id, "name": "New Name" });
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/update-passkey",
        Some(&session.token),
        Some(body),
    );

    let response = plugin.handle_update_passkey(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let resp_body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(resp_body["passkey"]["name"], "New Name");

    // Verify persisted
    let updated = ctx
        .database
        .get_passkey_by_id(&passkey.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.name(), "New Name");
}

#[tokio::test]
async fn test_update_passkey_non_owner_rejected() {
    let plugin = PasskeyPlugin::new();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let other_user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("other-upd@example.com")
                .with_name("Other"),
        )
        .await
        .unwrap();

    let passkey = ctx
        .database
        .create_passkey(CreatePasskey {
            user_id: other_user.id.clone(),
            name: "Other's Key".to_string(),
            credential_id: "cred-other-upd".to_string(),
            public_key: "pk".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
        })
        .await
        .unwrap();

    let body = serde_json::json!({ "id": passkey.id, "name": "Hijacked" });
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/update-passkey",
        Some(&session.token),
        Some(body),
    );

    let err = plugin.handle_update_passkey(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 404);

    // Verify unchanged
    let unchanged = ctx
        .database
        .get_passkey_by_id(&passkey.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.name(), "Other's Key");
}

#[tokio::test]
async fn test_expired_challenge_rejected() {
    let plugin = PasskeyPlugin::new().allow_insecure_unverified_assertion(true);
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let challenge = "expired-challenge";
    let identifier = format!("passkey_reg:{}", user.id);

    // Create an already-expired verification
    ctx.database
        .create_verification(CreateVerification {
            identifier: identifier.clone(),
            value: challenge.to_string(),
            expires_at: Utc::now() - Duration::seconds(1),
        })
        .await
        .unwrap();

    let body = serde_json::json!({
        "response": {
            "id": "cred-exp-1",
            "response": {
                "clientDataJSON": encoded_client_data(challenge, "webauthn.create", "http://localhost:3000"),
                "attestationObject": "fake",
            }
        }
    });
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/verify-registration",
        Some(&session.token),
        Some(body),
    );

    let err = plugin
        .handle_verify_registration(&req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 400);
}

#[tokio::test]
async fn test_verify_authentication_requires_insecure_opt_in() {
    let plugin = PasskeyPlugin::new(); // default: insecure=false
    let (ctx, _user, _session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let body = serde_json::json!({
        "response": {
            "id": "cred-1",
            "response": {
                "clientDataJSON": encoded_client_data("c", "webauthn.get", "http://localhost:3000"),
            }
        }
    });

    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/verify-authentication",
        None,
        Some(body),
    );

    let err = plugin
        .handle_verify_authentication(&req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 501);
}

#[tokio::test]
async fn test_memory_passkey_list_is_sorted_by_created_at_desc() {
    let (ctx, user, _session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let first = ctx
        .database
        .create_passkey(CreatePasskey {
            user_id: user.id.clone(),
            name: "first".to_string(),
            credential_id: "cred-sort-1".to_string(),
            public_key: "pk-1".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
        })
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(2)).await;

    let second = ctx
        .database
        .create_passkey(CreatePasskey {
            user_id: user.id.clone(),
            name: "second".to_string(),
            credential_id: "cred-sort-2".to_string(),
            public_key: "pk-2".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
        })
        .await
        .unwrap();

    let listed = ctx.database.list_passkeys_by_user(&user.id).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].id(), second.id());
    assert_eq!(listed[1].id(), first.id());
}
