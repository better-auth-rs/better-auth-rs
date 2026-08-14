use super::*;
use crate::plugins::test_helpers;
use better_auth_core::AuthPlugin;
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{CreateAccount, CreateUser};
use chrono::Duration;
use cookie::Cookie;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn create_test_context_with_credential_user(
    email: &str,
    two_factor_enabled: bool,
) -> (AuthContext<TestSchema>, UserView, SessionView) {
    let ctx = test_helpers::create_test_context().await;
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
            user_id: user.id.clone(),
            account_id: user.id.clone(),
            provider_id: "credential".to_string(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: Some(password_hash),
        })
        .await
        .unwrap();

    let user = if two_factor_enabled {
        UserView::from(
            &ctx.database
                .update_user(
                    &user.id,
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

    let session = test_helpers::create_session(&ctx, user.id.clone(), Duration::hours(1)).await;
    (ctx, user, session)
}

fn cookie_value(header: &str) -> String {
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
async fn test_begin_sign_in_challenge_sets_pending_cookie_and_remember_choice() {
    let (ctx, user, _session) =
        create_test_context_with_credential_user("challenge@example.com", true).await;

    let challenge = begin_sign_in_challenge(&user, Some(false), &ctx)
        .await
        .unwrap();
    assert!(challenge.response.two_factor_redirect);

    let two_factor_cookie = challenge
        .set_cookie_headers
        .iter()
        .find(|header| header.starts_with("better-auth.two_factor="))
        .cloned()
        .expect("challenge should set the two-factor cookie");
    let dont_remember_cookie = challenge
        .set_cookie_headers
        .iter()
        .find(|header| header.starts_with("better-auth.dont_remember="))
        .cloned()
        .expect("challenge should set the remember-choice cookie");

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
    assert_eq!(verification.value(), user.id);
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

    let (response, set_cookie_headers) =
        verify_existing_session_factor(user.clone(), session.clone(), true, &ctx)
            .await
            .unwrap();

    assert!(!response.user.two_factor_enabled);
    assert_ne!(response.token, session.token);
    assert_eq!(set_cookie_headers.len(), 1);
    assert!(
        ctx.database
            .get_session(&session.token)
            .await
            .unwrap()
            .is_none(),
        "the original session should be deleted after re-issuing",
    );
    assert!(
        ctx.database
            .get_session(&response.token)
            .await
            .unwrap()
            .is_some(),
        "the new session token should be persisted",
    );
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
            user_id: user.id.clone(),
            secret: encrypt_value(&ctx.config.secret, "totp-secret").unwrap(),
            backup_codes: encrypted,
        })
        .await
        .unwrap();

    let backup_codes = plugin.view_backup_codes(&user.id, &ctx).await.unwrap();
    assert_eq!(backup_codes, expected_codes);
}

#[tokio::test]
async fn test_view_backup_codes_rejects_invalid_stored_json() {
    let plugin = TwoFactorPlugin::new();
    let (ctx, user, _session) =
        create_test_context_with_credential_user("invalid-view-codes@example.com", true).await;

    _ = ctx
        .database
        .create_two_factor(better_auth_core::CreateTwoFactor {
            user_id: user.id.clone(),
            secret: encrypt_value(&ctx.config.secret, "totp-secret").unwrap(),
            backup_codes: encrypt_value(&ctx.config.secret, "\"not-an-array\"").unwrap(),
        })
        .await
        .unwrap();

    let err = plugin.view_backup_codes(&user.id, &ctx).await.unwrap_err();
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
