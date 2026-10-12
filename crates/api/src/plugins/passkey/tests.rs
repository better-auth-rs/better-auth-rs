#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Duration;

use super::*;
use crate::plugins::test_helpers;
use better_auth_core::{CreatePasskey, CreateUser, HttpMethod};

#[path = "descriptor_tests.rs"]
mod descriptor_tests;

pub(super) fn assert_verification_error(
    result: AuthResult<AuthResponse>,
    status: &str,
    http_status: u16,
    expected: FieldMap,
) -> AuthResult<AuthResponse> {
    let error = result
        .err()
        .ok_or_else(|| AuthError::internal("Passkey verification must throw an APIError"))?;
    assert!(error.is_api_error_instance(better_auth_core::ApiErrorClass::BetterAuth));
    assert_eq!(error.status_value()?, FieldValue::from(status));
    assert_eq!(error.status_code()?, http_status);
    let body = error
        .body_value()?
        .as_object()
        .ok_or_else(|| AuthError::internal("Passkey APIError body must be an object"))?
        .snapshot_fields()?;
    assert_eq!(
        body.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    assert_eq!(body, expected);
    let response = error.to_http_response()?;
    assert_eq!(response.status, http_status);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body.bytes()?)?,
        serde_json::Value::Object(expected.json()?)
    );
    assert!(!response.headers.contains_key("Set-Cookie"));
    Ok(response)
}

#[test]
fn verification_catch_preserves_only_better_auth_instances() -> AuthResult<()> {
    use better_auth_core::{ApiErrorClass, ApiErrorInit};

    for registration in [false, true] {
        for class in [ApiErrorClass::BetterAuth, ApiErrorClass::BetterCall] {
            let error = AuthError::try_api_error(ApiErrorInit {
                class,
                status: "CONFLICT".into(),
                body: FieldMap::from([("message".into(), "callback rejected".into())]).into(),
                ..Default::default()
            })?;
            let original = error.raw_value().cloned();
            let error = super::registration::verification_error(error, registration);
            if class == ApiErrorClass::BetterAuth {
                assert!(
                    error
                        .raw_value()
                        .zip(original.as_ref())
                        .is_some_and(|(value, original)| value.strict_equals(original))
                );
            } else {
                let (status, http_status, code, message) = if registration {
                    (
                        "INTERNAL_SERVER_ERROR",
                        500,
                        "FAILED_TO_VERIFY_REGISTRATION",
                        "Failed to verify registration",
                    )
                } else {
                    (
                        "BAD_REQUEST",
                        400,
                        "AUTHENTICATION_FAILED",
                        "Authentication failed",
                    )
                };
                test_helpers::assert_coded_api_error(&error, status, http_status, code, message);
            }
        }
        let structural = AuthError::from_thrown(
            FieldMap::from([
                ("name".into(), "APIError".into()),
                ("statusCode".into(), 409.0.into()),
            ])
            .into(),
        );
        let error = super::registration::verification_error(structural, registration);
        assert_eq!(error.status_code()?, if registration { 500 } else { 400 });
    }
    Ok(())
}

#[tokio::test]
async fn verification_catch_retains_original_error_and_logger_failure() -> AuthResult<()> {
    use better_auth_core::{
        FieldFunction,
        store::{EphemeralStore, StatelessSchema},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    for registration in [false, true] {
        for logger_fails in [false, true] {
            let original: FieldValue =
                FieldMap::from([("cause".into(), "verification".into())]).into();
            let logger_error: FieldValue =
                FieldMap::from([("cause".into(), "logger".into())]).into();
            let calls = Arc::new(AtomicUsize::new(0));
            let logger: better_auth_core::FieldObject = FieldMap::from([
                ("level".into(), "error".into()),
                (
                    "log".into(),
                    FieldFunction::contextual({
                        let original = original.clone();
                        let logger_error = logger_error.clone();
                        let calls = calls.clone();
                        move |_, arguments| {
                            assert_eq!(arguments.len(), 3);
                            assert!(
                                arguments
                                    .first()
                                    .is_some_and(|value| value.strict_equals(&"error".into()))
                            );
                            assert!(arguments.get(1).is_some_and(|value| value.strict_equals(
                                &if registration {
                                    "Failed to verify registration".into()
                                } else {
                                    "Failed to verify authentication".into()
                                }
                            )));
                            assert!(
                                arguments
                                    .get(2)
                                    .is_some_and(|value| value.strict_equals(&original))
                            );
                            calls.fetch_add(1, Ordering::SeqCst);
                            if logger_fails {
                                Err(AuthError::from_thrown(logger_error.clone()))
                            } else {
                                Ok(FieldValue::Undefined)
                            }
                        }
                    })
                    .into(),
                ),
            ])
            .into();
            let mut config = test_helpers::create_test_config();
            config.logger = logger.into();
            let config = Arc::new(config);
            let ctx: AuthContext<StatelessSchema> =
                AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))?;
            let error = ctx
                .with_native_context(Default::default(), |_| async move {
                    Ok(super::registration::verification_error(
                        AuthError::from_thrown(original),
                        registration,
                    ))
                })
                .await?;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            if logger_fails {
                assert!(
                    error
                        .raw_value()
                        .is_some_and(|value| value.strict_equals(&logger_error))
                );
            } else {
                assert_eq!(error.status_code()?, if registration { 500 } else { 400 });
            }
        }
    }
    Ok(())
}

fn passkey_plugin() -> PasskeyPlugin {
    PasskeyPlugin::new()
        .rp_id("localhost")
        .rp_name("Better Auth Test")
        .origin("http://localhost:3000")
}

#[tokio::test]
async fn native_session_relationship_uses_missing_id_semantics_at_each_passkey_boundary() {
    use better_auth_core::{
        CreateSession,
        store::{EphemeralStore, StatelessSchema},
        user_fields::{UserFieldConfig, UserFieldReference},
    };
    let plugin = passkey_plugin();
    let mut config = test_helpers::create_test_config();
    let _ = config.user.fields_mut().insert(
        "image".into(),
        UserFieldConfig {
            references: Some(UserFieldReference {
                model: "session".into(),
                field: "id".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let ctx: AuthContext<StatelessSchema> = test_helpers::initialize_test_context(
        config.clone(),
        Arc::new(EphemeralStore::new(config)),
        &[&plugin],
    )
    .await
    .unwrap();
    let session = ctx
        .database
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            user_id: "canonical-owner".into(),
            expires_at: (chrono::Utc::now() + Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    let mut user = CreateUser::new()
        .with_email("many-passkey@example.test")
        .with_name("Selected");
    user.image = Some(session.id.typed().unwrap().clone()).into();
    ctx.database.create_user(user).await.unwrap();
    let request = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/passkey/generate-register-options",
        Some(session.token.typed().unwrap()),
        None,
    );
    let error = plugin
        .handle_generate_register_options(&request, &ctx)
        .await
        .unwrap_err();
    crate::plugins::test_helpers::assert_coded_api_error(
        &error,
        "UNAUTHORIZED",
        401,
        "SESSION_REQUIRED",
        "Passkey registration requires an authenticated session",
    );
    let response = plugin
        .handle_list_user_passkeys(&request, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body.bytes().unwrap().as_ref(), b"[]");
    let response = plugin
        .handle_generate_authenticate_options(&request, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
    assert!(body.get("allowCredentials").is_none());
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
            additional_fields: Default::default(),
            user_id: user.id.clone(),
            name: Some("Existing Key".to_string()).into(),
            credential_id: credential_id("cred-existing"),
            public_key: "public-key".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: Some("usb,nfc".to_string()),
            credential: better_auth_core::PasskeyCredentialState::Legacy(
                "unused by options".into(),
            ),
            aaguid: Some("00000000-0000-0000-0000-000000000000".to_string()).into(),
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_request(
        HttpMethod::Get,
        "/passkey/generate-register-options",
        Some(session.token.typed().unwrap()),
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

    let body: serde_json::Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
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

    let body: serde_json::Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
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
            additional_fields: Default::default(),
            user_id: user.id.clone(),
            name: Some("Authenticator".to_string()).into(),
            credential_id: credential_id("cred-auth"),
            public_key: "public-key".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: Some("internal".to_string()),
            credential: better_auth_core::PasskeyCredentialState::Legacy(
                "unused by options".into(),
            ),
            aaguid: None.into(),
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/passkey/generate-authenticate-options",
        Some(session.token.typed().unwrap()),
        None,
    );

    let response = plugin
        .handle_generate_authenticate_options(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    let body: serde_json::Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
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
        Some(session.token.typed().unwrap()),
        Some(body),
    );
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());

    assert_verification_error(
        plugin.handle_verify_registration(&req, &ctx).await,
        "BAD_REQUEST",
        400,
        FieldMap::from([
            ("message".into(), "Challenge not found".into()),
            ("code".into(), "CHALLENGE_NOT_FOUND".into()),
        ]),
    )
    .unwrap();
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

    assert_verification_error(
        plugin.handle_verify_authentication(&req, &ctx).await,
        "BAD_REQUEST",
        400,
        FieldMap::from([
            ("message".into(), "Challenge not found".into()),
            ("code".into(), "CHALLENGE_NOT_FOUND".into()),
        ]),
    )
    .unwrap();
}

#[tokio::test]
async fn test_list_user_passkeys_matches_upstream_optional_fields() {
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
            additional_fields: Default::default(),
            user_id: user.id.clone(),
            name: None.into(),
            credential_id: credential_id("cred-list"),
            public_key: "public-key".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
            credential: better_auth_core::PasskeyCredentialState::Legacy(
                "unused by options".into(),
            ),
            aaguid: Some("00000000-0000-0000-0000-000000000000".to_string()).into(),
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/passkey/list-user-passkeys",
        Some(session.token.typed().unwrap()),
        None,
    );
    let response = plugin.handle_list_user_passkeys(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let body: serde_json::Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
    assert!(body[0].get("updatedAt").is_none());
    assert_eq!(body[0]["aaguid"], "00000000-0000-0000-0000-000000000000");
    assert_eq!(body[0].get("name"), Some(&serde_json::Value::Null));
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
            additional_fields: Default::default(),
            user_id: other.id.clone(),
            name: Some("Other Key".to_string()).into(),
            credential_id: credential_id("cred-other-delete"),
            public_key: "public-key".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
            credential: better_auth_core::PasskeyCredentialState::Legacy(
                "unused by options".into(),
            ),
            aaguid: None.into(),
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/delete-passkey",
        Some(session.token.typed().unwrap()),
        Some(serde_json::json!({ "id": passkey.id })),
    );

    let err = plugin.handle_delete_passkey(&req, &ctx).await.unwrap_err();
    assert!(err.is_api_error_instance(better_auth_core::ApiErrorClass::BetterAuth));
    assert_eq!(err.status_value().unwrap(), "UNAUTHORIZED".into());
    assert_eq!(err.status_code().unwrap(), 401);
    assert!(err.body_value().unwrap().is_undefined());
    assert!(
        better_auth_core::ResponseBody::Native(err.body_value().unwrap())
            .bytes()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        ctx.database
            .get_passkey_by_id(passkey.id.typed().unwrap())
            .await
            .unwrap(),
        Some(passkey)
    );
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
            additional_fields: Default::default(),
            user_id: other.id.clone(),
            name: Some("Other Key".to_string()).into(),
            credential_id: credential_id("cred-other-update"),
            public_key: "public-key".to_string(),
            counter: 0,
            device_type: "singleDevice".to_string(),
            backed_up: false,
            transports: None,
            credential: better_auth_core::PasskeyCredentialState::Legacy(
                "unused by options".into(),
            ),
            aaguid: None.into(),
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/update-passkey",
        Some(session.token.typed().unwrap()),
        Some(serde_json::json!({
            "id": passkey.id,
            "name": "Hijacked",
        })),
    );

    let err = plugin.handle_update_passkey(&req, &ctx).await.unwrap_err();
    test_helpers::assert_coded_api_error(
        &err,
        "UNAUTHORIZED",
        401,
        "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
        "You are not allowed to register this passkey",
    );
}
