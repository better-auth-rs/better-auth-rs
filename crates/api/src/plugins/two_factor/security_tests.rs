use super::tests::{cookie_value, create_test_context_with_credential_user};
use super::*;
use crate::plugins::test_helpers;
use better_auth_core::HttpMethod;
use std::sync::Mutex;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

struct FailChallengeDeletion;

#[better_auth_core::database_hooks()]
impl better_auth_seaorm::SeaOrmHooks<TestSchema> for FailChallengeDeletion {
    async fn before_delete_verification(
        &self,
        verification: &better_auth_core::wire::VerificationView,
        _ctx: &better_auth_seaorm::SeaOrmHookContext<'_, TestSchema>,
    ) -> AuthResult<better_auth_seaorm::HookControl> {
        if verification.identifier == "failure-challenge" {
            return Err(AuthError::Database(better_auth_core::DatabaseError::Query(
                "injected challenge deletion failure".into(),
            )));
        }
        Ok(better_auth_seaorm::HookControl::Continue)
    }
}

#[tokio::test]
async fn challenge_database_failures_preserve_upstream_errors_and_cookie_expiry() {
    let connection = better_auth_seaorm::Database::connect("sqlite::memory:")
        .await
        .unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&connection)
        .await
        .unwrap();
    let config = Arc::new(test_helpers::create_test_config());
    let database =
        better_auth_seaorm::SeaOrmStore::<TestSchema>::new(config.clone(), connection.clone())
            .hook(FailChallengeDeletion);
    let ctx = AuthContext::new(config, Arc::new(database));
    let user = test_helpers::create_user(
        &ctx,
        better_auth_core::CreateUser::new().with_email("factor-failure@example.com"),
    )
    .await;
    for (identifier, value) in [
        ("failure-challenge", user.id.typed().unwrap().as_str()),
        ("2fa-attempts-failure-challenge", "5"),
    ] {
        let _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: identifier.into(),
                value: value.into(),
                expires_at: (Utc::now() + Duration::minutes(5)).into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    let state = ResolvedTwoFactorState::Pending(PendingTwoFactorState {
        user,
        key: "failure-challenge".into(),
        dont_remember: false,
    });
    let req = AuthRequest::new(HttpMethod::Post, "/two-factor/verify-totp");
    let failure = begin_attempt(&state, &req, &ctx).await.err().unwrap();
    assert!(matches!(
        failure,
        AuthError::Upstream {
            status: 500,
            code: "FAILED_TO_INVALIDATE_TWO_FACTOR_CHALLENGE",
            message: "Failed to invalidate two-factor challenge",
        }
    ));
    assert!(
        req.take_response_headers()
            .unwrap()
            .get_all("Set-Cookie")
            .any(|cookie| cookie.starts_with("better-auth.two_factor=")
                && cookie.contains("Max-Age=0"))
    );
    connection.close().await.unwrap();
    let failure = begin_attempt(&state, &req, &ctx).await.err().unwrap();
    assert_eq!(failure.status_code(), 401);
    assert_eq!(failure.to_string(), "Invalid two factor cookie");
}

#[derive(Default)]
struct OtpOutbox(Mutex<Vec<String>>);

#[async_trait]
impl SendTwoFactorOtp for OtpOutbox {
    async fn send(&self, _: &UserView, otp: &str) -> AuthResult<()> {
        self.0.lock().unwrap().push(otp.to_owned());
        Ok(())
    }
}

fn challenge_request(challenge: &SignInTwoFactorRedirect) -> AuthRequest {
    let header = challenge
        .set_cookie_headers
        .iter()
        .find(|header| header.starts_with("better-auth.two_factor="))
        .unwrap();
    let mut req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/two-factor/verify-backup-code",
        None,
        None,
    );
    let _ = req.headers.insert(
        "cookie".into(),
        format!("better-auth.two_factor={}", cookie_value(header)),
    );
    req
}

#[tokio::test]
async fn otp_enrollment_rotates_session_and_does_not_enroll_an_authenticator() {
    let (ctx, user, session) =
        create_test_context_with_credential_user("otp-enrollment@example.com", false).await;
    let body = EnableRequest {
        password: Some("password123".into()),
        issuer: None,
        method: EnrollmentMethod::Otp,
    };
    let missing_sender = enable_core(
        &AuthRequest::new(better_auth_core::HttpMethod::Post, "/two-factor/enable"),
        &body,
        &user,
        &session,
        &TwoFactorConfig::default(),
        &ctx,
    )
    .await
    .unwrap_err();
    assert_eq!(
        missing_sender.error_payload().1.as_deref(),
        Some("OTP_NOT_CONFIGURED")
    );
    let config = TwoFactorConfig {
        send_otp: Some(Arc::new(OtpOutbox::default())),
        ..Default::default()
    };
    let request = AuthRequest::new(better_auth_core::HttpMethod::Post, "/two-factor/enable");
    let (response, _) = enable_core(&request, &body, &user, &session, &config, &ctx)
        .await
        .unwrap();
    let queued = request.take_response_headers().unwrap();
    let cookies: Vec<_> = queued.get_all("set-cookie").collect();
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        serde_json::json!({"method":"otp"})
    );
    assert!(
        ctx.database
            .get_two_factor_by_user_id(user.id.typed().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ctx.database
            .get_session(&session.token)
            .await
            .unwrap()
            .is_none()
    );
    let mut req =
        test_helpers::create_auth_request_no_query(HttpMethod::Get, "/get-session", None, None);
    let _ = req.headers.insert(
        "cookie".into(),
        format!("better-auth.session_token={}", cookie_value(&cookies[0])),
    );
    let (updated, current) = ctx.require_session(&req).await.unwrap();
    assert!(updated.two_factor_enabled);
    assert_ne!(session.token, current.token);
}

#[tokio::test]
async fn authenticator_enrollment_can_restart_only_until_verified() {
    let (ctx, user, session) =
        create_test_context_with_credential_user("totp-enrollment@example.com", false).await;
    let body = EnableRequest {
        password: Some("password123".into()),
        issuer: None,
        method: EnrollmentMethod::Totp,
    };
    let config = TwoFactorConfig::default();
    let (first, _) = enable_core(
        &AuthRequest::new(better_auth_core::HttpMethod::Post, "/two-factor/enable"),
        &body,
        &user,
        &session,
        &config,
        &ctx,
    )
    .await
    .unwrap();
    let first_record = ctx
        .database
        .get_two_factor_by_user_id(user.id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(!first_record.verified);
    let (second, _) = enable_core(
        &AuthRequest::new(better_auth_core::HttpMethod::Post, "/two-factor/enable"),
        &body,
        &user,
        &session,
        &config,
        &ctx,
    )
    .await
    .unwrap();
    let second_record = ctx
        .database
        .get_two_factor_by_user_id(user.id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_record.id, second_record.id);
    assert_ne!(first.totp_uri, second.totp_uri);
    let pending = begin_sign_in_challenge(
        &user,
        None,
        &AuthRequest::new(better_auth_core::HttpMethod::Post, "/sign-in/email"),
        &ctx,
    )
    .await
    .unwrap();
    assert!(pending.response.two_factor_methods.is_empty());
    let unverified = verify_totp_core(
        &challenge_request(&pending),
        &VerifyTotpRequest {
            code: "000000".into(),
            trust_device: None,
        },
        &config,
        &ctx,
    )
    .await
    .unwrap_err();
    assert_eq!(unverified.to_string(), "TOTP not enabled");
    let secret = decrypt_value(&ctx.config.secret, &second_record.secret).unwrap();
    let code = build_totp(&config, &secret, None, &user, &ctx)
        .unwrap()
        .generate_current()
        .unwrap();
    let request = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/two-factor/verify-totp",
        Some(&session.token),
        None,
    );
    let _ = verify_totp_core(
        &request,
        &VerifyTotpRequest {
            code,
            trust_device: None,
        },
        &config,
        &ctx,
    )
    .await
    .unwrap();
    let rejected = enable_core(
        &AuthRequest::new(better_auth_core::HttpMethod::Post, "/two-factor/enable"),
        &body,
        &user,
        &session,
        &config,
        &ctx,
    )
    .await
    .unwrap_err();
    assert_eq!(
        rejected.error_payload().1.as_deref(),
        Some("TOTP_ALREADY_ENABLED")
    );
    let preserved = ctx
        .database
        .get_two_factor_by_user_id(user.id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preserved.secret, second_record.secret);
    assert_eq!(preserved.backup_codes, second_record.backup_codes);
    assert!(preserved.verified);
}

#[tokio::test]
async fn failed_challenge_budget_and_account_lock_survive_new_challenges() {
    let (ctx, user, session) =
        create_test_context_with_credential_user("locked@example.com", false).await;
    let config = TwoFactorConfig {
        skip_verification_on_enable: true,
        ..Default::default()
    };
    let (enrollment, _) = enable_core(
        &AuthRequest::new(better_auth_core::HttpMethod::Post, "/two-factor/enable"),
        &EnableRequest {
            password: Some("password123".into()),
            issuer: None,
            method: EnrollmentMethod::Totp,
        },
        &user,
        &session,
        &config,
        &ctx,
    )
    .await
    .unwrap();
    let user = UserView::from(
        &ctx.database
            .get_user_by_id(user.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap(),
    );
    let invalid = VerifyBackupCodeRequest {
        code: "incorrect".into(),
        disable_session: None,
        trust_device: None,
    };
    for round in 0..2 {
        let challenge = begin_sign_in_challenge(
            &user,
            None,
            &AuthRequest::new(better_auth_core::HttpMethod::Post, "/sign-in/email"),
            &ctx,
        )
        .await
        .unwrap();
        let req = challenge_request(&challenge);
        for _ in 0..5 {
            assert_eq!(
                verify_backup_code_core(&req, &invalid, &config, &ctx)
                    .await
                    .unwrap_err()
                    .status_code(),
                401
            );
        }
        let blocked = verify_backup_code_core(&req, &invalid, &config, &ctx)
            .await
            .unwrap_err();
        assert_eq!(blocked.status_code(), if round == 0 { 400 } else { 429 });
        if round == 0 {
            assert!(!req.take_response_headers().unwrap().is_empty());
        }
    }
    let challenge = begin_sign_in_challenge(
        &user,
        None,
        &AuthRequest::new(better_auth_core::HttpMethod::Post, "/sign-in/email"),
        &ctx,
    )
    .await
    .unwrap();
    let req = challenge_request(&challenge);
    let valid = VerifyBackupCodeRequest {
        code: enrollment.backup_codes.unwrap()[0].clone(),
        disable_session: None,
        trust_device: None,
    };
    assert_eq!(
        verify_backup_code_core(&req, &valid, &config, &ctx)
            .await
            .unwrap_err()
            .error_payload()
            .1
            .as_deref(),
        Some("ACCOUNT_TEMPORARILY_LOCKED")
    );
    let factor = ctx
        .database
        .get_two_factor_by_user_id(user.id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(factor.failed_verification_count, 10);
    ctx.database
        .record_two_factor_failure(&factor.id, 10, Utc::now() - Duration::seconds(1))
        .await
        .unwrap();
    let _ = verify_backup_code_core(&req, &valid, &config, &ctx)
        .await
        .unwrap();
    let factor = ctx
        .database
        .get_two_factor_by_user_id(user.id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(factor.failed_verification_count, 0);
    assert!(factor.locked_until.is_none());
}

#[tokio::test]
async fn concurrent_otp_requests_create_only_one_session_and_invalidate_older_codes() {
    let (ctx, user, _) =
        create_test_context_with_credential_user("otp-once@example.com", true).await;
    let outbox = Arc::new(OtpOutbox::default());
    let config = TwoFactorConfig {
        send_otp: Some(outbox.clone()),
        ..Default::default()
    };
    let challenge = begin_sign_in_challenge(
        &user,
        None,
        &AuthRequest::new(better_auth_core::HttpMethod::Post, "/sign-in/email"),
        &ctx,
    )
    .await
    .unwrap();
    let req = challenge_request(&challenge);
    let _ = send_otp_core(&req, &config, &ctx).await.unwrap();
    let _ = send_otp_core(&req, &config, &ctx).await.unwrap();
    let code = outbox.0.lock().unwrap()[1].clone();
    let body = VerifyOtpRequest {
        code,
        trust_device: None,
    };
    let before = ctx
        .database
        .get_user_sessions(user.id.typed().unwrap())
        .await
        .unwrap()
        .len();
    let (first, second) = tokio::join!(
        verify_otp_core(&req, &body, &config, &ctx),
        verify_otp_core(&req, &body, &config, &ctx)
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(
        ctx.database
            .get_user_sessions(user.id.typed().unwrap())
            .await
            .unwrap()
            .len(),
        before + 1
    );
    let identifier = read_signed_cookie(&req, TWO_FACTOR_COOKIE_SUFFIX, &ctx)
        .unwrap()
        .unwrap();
    assert!(
        ctx.database
            .consume_verification_by_identifier(&otp_verification_identifier(&identifier))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ctx.database
            .consume_verification_by_identifier(&identifier)
            .await
            .unwrap()
            .is_none()
    );
}
