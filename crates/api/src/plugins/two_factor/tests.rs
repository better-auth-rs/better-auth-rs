use super::*;
use crate::plugins::test_helpers;
use better_auth_core::AuthPlugin;
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{CreateAccount, CreateUser};
use chrono::Duration;
use cookie::Cookie;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

pub(super) async fn create_test_context_with_credential_user(
    email: &str,
    two_factor_enabled: bool,
) -> (AuthContext<TestSchema>, UserView, SessionView) {
    let mut ctx = test_helpers::create_test_context().await;
    let mut init = better_auth_core::AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
    init.extensions = ctx.extensions.clone();
    init.metadata = ctx.metadata.clone();
    TwoFactorPlugin::new().on_init(&mut init).await.unwrap();
    ctx.extensions = init.extensions;
    ctx.metadata = init.metadata;
    let user = test_helpers::create_user(
        &ctx,
        CreateUser::new()
            .with_email(email)
            .with_name("Two Factor Tester"),
    )
    .await;

    let password_hash = better_auth_core::hash_password(None, "password123")
        .await
        .unwrap();
    _ = ctx
        .database
        .create_account(CreateAccount {
            user_id: (user.id.clone()).into(),
            account_id: (user.id.clone()).into(),
            provider_id: ("credential".to_string()).into(),
            access_token: Default::default(),
            refresh_token: Default::default(),
            id_token: Default::default(),
            access_token_expires_at: Default::default(),
            refresh_token_expires_at: Default::default(),
            scope: Default::default(),
            password: (Some(password_hash))
                .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            ..Default::default()
        })
        .await
        .unwrap();

    let user = if two_factor_enabled {
        UserView::from(
            &ctx.database
                .update_user(
                    user.id.typed().unwrap(),
                    better_auth_core::UpdateUser {
                        two_factor_enabled: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .unwrap(),
        )
    } else {
        user
    };

    let session =
        test_helpers::create_session(&ctx, user.id.typed().unwrap().clone(), Duration::hours(1))
            .await;
    (ctx, user, session)
}

pub(super) fn cookie_value(header: &str) -> String {
    Cookie::parse(header)
        .expect("Set-Cookie header should parse")
        .value()
        .to_string()
}

#[test]
fn test_signed_cookie_round_trip_and_tamper_rejection() {
    let signed = sign_cookie_value("secret-value", "payload-value").unwrap();
    let verified = verify_signed_cookie_value("secret-value", &signed).unwrap();
    assert_eq!(verified.as_deref(), Some("payload-value"));

    let tampered = signed.replacen("payload-value", "other-value", 1);
    let tampered_verified = verify_signed_cookie_value("secret-value", &tampered).unwrap();
    assert!(tampered_verified.is_none());
}

#[tokio::test]
async fn test_sign_in_after_hook_sets_pending_cookie_and_preserves_remember_choice() {
    let (ctx, user, session) =
        create_test_context_with_credential_user("challenge@example.com", true).await;

    let req = AuthRequest::new(better_auth_core::HttpMethod::Post, "/sign-in/email");
    let manager = ctx.session_manager();
    manager
        .set_session_cookie(
            &req,
            manager.internal_data(&user, &session).await.unwrap(),
            Some(true),
        )
        .await
        .unwrap();
    let mut response = AuthResponse::new(200);
    manager.finish_response(&req, &mut response).unwrap();
    TwoFactorPlugin::new()
        .after_request(&req, &mut response, &ctx)
        .await
        .unwrap();
    manager.finish_response(&req, &mut response).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body.bytes().unwrap()).unwrap()["twoFactorRedirect"],
        true
    );
    assert!(req.new_session().unwrap().is_none());
    assert!(
        ctx.database
            .get_session(session.token.typed().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    let two_factor_cookie = response
        .headers
        .get_all("set-cookie")
        .find(|header| header.starts_with("better-auth.two_factor="))
        .cloned()
        .unwrap();
    let dont_remember_cookie = response
        .headers
        .get_all("set-cookie")
        .find(|header| header.starts_with("better-auth.dont_remember="))
        .cloned()
        .unwrap();

    let two_factor_req = test_helpers::create_auth_request_no_query(
        better_auth_core::HttpMethod::Post,
        "/two-factor/verify-otp",
        None,
        None,
    );
    let mut req = two_factor_req;
    req.headers.insert(
        "cookie".to_string(),
        format!(
            "better-auth.two_factor={}; better-auth.dont_remember={}",
            cookie_value(&two_factor_cookie),
            cookie_value(&dont_remember_cookie)
        ),
    );

    let identifier = read_signed_cookie(&req, TWO_FACTOR_COOKIE_SUFFIX, &ctx)
        .unwrap()
        .expect("signed cookie should verify");
    let verification = ctx
        .database
        .get_verification_by_identifier(&identifier)
        .await
        .unwrap()
        .expect("challenge should persist a pending verification");
    assert_eq!(verification.value, user.id);
}

#[tokio::test]
async fn test_inspect_trusted_device_rotates_server_state() {
    let (ctx, user, _session) =
        create_test_context_with_credential_user("trusted@example.com", true).await;

    let trust_cookie = create_trust_device_cookie_header(&user, &ctx)
        .await
        .unwrap();
    let mut req = test_helpers::create_auth_request_no_query(
        better_auth_core::HttpMethod::Post,
        "/sign-in/email",
        None,
        None,
    );
    req.headers.insert(
        "cookie".to_string(),
        format!("better-auth.trust_device={}", cookie_value(&trust_cookie)),
    );

    let original_cookie = read_signed_cookie(&req, TRUST_DEVICE_COOKIE_SUFFIX, &ctx)
        .unwrap()
        .expect("trust cookie should verify");
    let original_identifier = original_cookie
        .split_once('!')
        .expect("trust cookie should include the identifier")
        .1
        .to_string();

    let result = inspect_trusted_device(&req, &user, &ctx).await.unwrap();
    assert!(result.trusted);
    assert_eq!(result.set_cookie_headers.len(), 1);

    let rotated_cookie = result.set_cookie_headers[0].clone();
    let mut rotated_req = test_helpers::create_auth_request_no_query(
        better_auth_core::HttpMethod::Post,
        "/sign-in/email",
        None,
        None,
    );
    rotated_req.headers.insert(
        "cookie".to_string(),
        format!("better-auth.trust_device={}", cookie_value(&rotated_cookie)),
    );
    let rotated_value = read_signed_cookie(&rotated_req, TRUST_DEVICE_COOKIE_SUFFIX, &ctx)
        .unwrap()
        .expect("rotated trust cookie should verify");
    let rotated_identifier = rotated_value
        .split_once('!')
        .expect("rotated cookie should include the identifier")
        .1
        .to_string();

    assert_ne!(original_identifier, rotated_identifier);
    assert!(
        ctx.database
            .get_verification_by_identifier(&original_identifier)
            .await
            .unwrap()
            .is_none(),
        "the previous trust-device record should be deleted during rotation",
    );
    assert!(
        ctx.database
            .get_verification_by_identifier(&rotated_identifier)
            .await
            .unwrap()
            .is_some(),
        "the rotated trust-device record should be persisted",
    );
}

#[tokio::test]
async fn test_verify_existing_session_factor_enables_two_factor_and_reissues_session() {
    let (ctx, user, session) =
        create_test_context_with_credential_user("reissue@example.com", false).await;

    let request = AuthRequest::new(
        better_auth_core::HttpMethod::Post,
        "/two-factor/verify-totp",
    );
    let (response, _) = verify_existing_session_factor(
        &request,
        user.clone(),
        session.clone(),
        Some(EnrollmentMethod::Totp),
        &ctx,
        std::future::ready(Ok(())),
    )
    .await
    .unwrap();

    let queued = request.take_response_headers().unwrap();
    let set_cookie_headers: Vec<_> = queued.get_all("set-cookie").collect();
    assert_eq!(response.user.two_factor_enabled, Some(false));
    assert_eq!(
        response.token.as_str(),
        Some(session.token.typed().unwrap().as_str())
    );
    assert_eq!(set_cookie_headers.len(), 1);
    assert!(
        ctx.database
            .get_session(session.token.typed().unwrap())
            .await
            .unwrap()
            .is_none(),
        "the original session should be deleted after re-issuing",
    );
    let mut request = test_helpers::create_auth_request_no_query(
        better_auth_core::HttpMethod::Get,
        "/get-session",
        None,
        None,
    );
    let _ = request.headers.insert(
        "cookie".into(),
        format!(
            "better-auth.session_token={}",
            cookie_value(&set_cookie_headers[0])
        ),
    );
    let (enabled_user, new_session) = ctx.require_session(&request).await.unwrap();
    assert_ne!(new_session.token, session.token);
    assert_eq!(enabled_user.two_factor_enabled, Some(true));
}

#[tokio::test]
async fn test_view_backup_codes_returns_decrypted_codes() {
    let plugin = TwoFactorPlugin::new();
    let (ctx, user, _session) =
        create_test_context_with_credential_user("view-codes@example.com", true).await;

    let expected_codes = vec!["ABCDE-12345".to_string(), "FGHIJ-67890".to_string()];
    let encrypted = encrypt_value(
        &ctx.config.secret,
        &serde_json::to_string(&expected_codes).unwrap(),
    )
    .unwrap();
    _ = ctx
        .database
        .create_two_factor(better_auth_core::CreateTwoFactor {
            additional_fields: Default::default(),
            verified: true,
            user_id: user.id.typed().unwrap().clone(),
            secret: encrypt_value(&ctx.config.secret, "totp-secret").unwrap(),
            backup_codes: encrypted,
        })
        .await
        .unwrap();

    let backup_codes = plugin
        .view_backup_codes(user.id.typed().unwrap(), &ctx)
        .await
        .unwrap();
    assert_eq!(
        backup_codes.json().unwrap(),
        Some(serde_json::json!(expected_codes))
    );
}

#[tokio::test]
async fn test_view_backup_codes_rejects_invalid_stored_json() {
    let plugin = TwoFactorPlugin::new();
    let (ctx, user, _session) =
        create_test_context_with_credential_user("invalid-view-codes@example.com", true).await;

    _ = ctx
        .database
        .create_two_factor(better_auth_core::CreateTwoFactor {
            additional_fields: Default::default(),
            verified: true,
            user_id: user.id.typed().unwrap().clone(),
            secret: encrypt_value(&ctx.config.secret, "totp-secret").unwrap(),
            backup_codes: encrypt_value(&ctx.config.secret, "not-json").unwrap(),
        })
        .await
        .unwrap();

    let err = plugin
        .view_backup_codes(user.id.typed().unwrap(), &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "Invalid backup code");
}

#[test]
fn test_routes_do_not_expose_view_backup_codes() {
    let plugin = TwoFactorPlugin::new();
    assert!(
        <TwoFactorPlugin as AuthPlugin<TestSchema>>::routes(&plugin)
            .iter()
            .all(|route| route.path != "/two-factor/view-backup-codes"),
        "view-backup-codes must stay server-only",
    );
}

#[tokio::test]
async fn body_schemas_keep_each_instances_global_and_nested_password_policy() {
    let strict = TwoFactorPlugin::new().totp_allow_passwordless(true);
    let optional = TwoFactorPlugin::new()
        .allow_passwordless(true)
        .totp_allow_passwordless(false);
    let strict_routes = <TwoFactorPlugin as AuthPlugin<TestSchema>>::routes(&strict);
    let optional_routes = <TwoFactorPlugin as AuthPlugin<TestSchema>>::routes(&optional);
    for (routes, enable_required, totp_required) in
        [(strict_routes, true, false), (optional_routes, false, true)]
    {
        for (path, required) in [
            ("/two-factor/enable", enable_required),
            ("/two-factor/get-totp-uri", totp_required),
        ] {
            let route = routes.iter().find(|route| route.path == path).unwrap();
            let mut request = AuthRequest::new(better_auth_core::HttpMethod::Post, path);
            request.body = Some(br#"{"unknown":"raw"}"#.to_vec());
            let result = route
                .body_validator
                .as_ref()
                .unwrap()
                .validate(&request)
                .await;
            if required {
                let response = result.unwrap_err().to_auth_response();
                let body: serde_json::Value =
                    serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
                assert_eq!(
                    body["message"],
                    "[body.password] Invalid input: expected string, received undefined"
                );
            } else {
                request.set_endpoint_body(result.unwrap());
                assert_eq!(
                    request.input_body().unwrap(),
                    Some(if path.ends_with("enable") {
                        serde_json::json!({"method":"totp"})
                    } else {
                        serde_json::json!({})
                    })
                );
                assert_eq!(
                    request.body.as_deref(),
                    Some(br#"{"unknown":"raw"}"#.as_slice())
                );
            }
        }
    }
}
