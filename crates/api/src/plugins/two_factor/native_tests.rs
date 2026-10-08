#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "The native route contracts require complete fixture snapshots and immediate failure on missing state."
)]

use super::*;
use better_auth_core::{
    AuthInitContext, AuthPlugin, CreateUser, HttpMethod,
    store::{AuthStore, EphemeralStore, StatelessSchema},
};
use std::sync::Mutex;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    ctx: AuthContext<StatelessSchema>,
    config: TwoFactorConfig,
    request: AuthRequest,
    user: UserView,
    id: SchemaValue<String>,
    fields: better_auth_core::plugin_runtime::ModelFields,
}

impl Fixture {
    async fn new(backup_codes: FieldValue, verified: FieldValue) -> AuthResult<Self> {
        let config = TwoFactorConfig {
            backup_code_options: BackupCodeOptions {
                storage: BackupCodeStorage::Plain,
                ..Default::default()
            },
            ..Default::default()
        };
        let auth_config = Arc::new(crate::plugins::test_helpers::create_test_config());
        let store: Arc<dyn AuthStore<StatelessSchema>> =
            Arc::new(EphemeralStore::new(auth_config.clone()));
        let mut init = AuthInitContext::new(auth_config.clone(), store.clone());
        TwoFactorPlugin::with_config(config.clone())
            .on_init(&mut init)
            .await?;
        let parts = init.into_parts();
        let fields = parts.plugin_fields.clone();
        let store = store.with_runtime(
            auth_config.clone(),
            parts.database_hooks,
            parts.plugin_fields,
        )?;
        let user = store
            .create_user(CreateUser {
                id: Some("native-factor-user".into()),
                ..CreateUser::new()
                    .with_email("native@factor.test")
                    .with_name("Selected User")
            })
            .await?;
        let user = store
            .update_user_by_id_value(
                &user.id.field_value(),
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?
            .ok_or_else(|| AuthError::internal("Missing fixture user"))?;
        let row = store
            .create_two_factor_record(FieldMap::from([
                ("userId".into(), user.id.field_value()),
                ("secret".into(), 7.0.into()),
                ("backupCodes".into(), backup_codes),
                ("verified".into(), verified),
            ]))
            .await?;
        let id = SchemaValue::from_field(row.get("id").cloned().unwrap_or_default());
        for (identifier, value) in [
            ("native-factor-challenge", user.id.clone()),
            ("2fa-attempts-native-factor-challenge", "0".into()),
        ] {
            let _ = store
                .create_verification(CreateVerification {
                    identifier: identifier.into(),
                    value,
                    expires_at: (Utc::now() + Duration::minutes(5)).into(),
                    ..Default::default()
                })
                .await?;
        }
        let mut ctx = AuthContext::new(auth_config, store);
        ctx.extensions = parts.extensions;
        ctx.metadata = parts.metadata;
        let mut request = AuthRequest::new(HttpMethod::Post, "/two-factor/verify-backup-code");
        let signed = sign_cookie_value(ctx.config.signing_secret(), "native-factor-challenge")?;
        let _ = request
            .headers
            .insert("cookie".into(), format!("better-auth.two_factor={signed}"));
        Ok(Self {
            ctx,
            config,
            request,
            user,
            id,
            fields,
        })
    }

    async fn verify(&self, code: &str) -> AuthResult<(SessionTokenResponse, Vec<String>)> {
        verify_backup_code_core(
            &self.request,
            &VerifyBackupCodeRequest {
                code: code.into(),
                disable_session: Some(true),
                trust_device: None,
            },
            &self.config,
            &self.ctx,
        )
        .await
    }

    async fn factor(&self) -> AuthResult<TwoFactor> {
        self.ctx
            .database
            .get_two_factor_by_user_id_value(&self.user.id)
            .await?
            .ok_or_else(|| AuthError::internal("Missing fixture factor"))
    }

    async fn attempts(&self) -> AuthResult<Option<FieldValue>> {
        Ok(self
            .ctx
            .database
            .get_verification_by_identifier("2fa-attempts-native-factor-challenge")
            .await?
            .map(|row| row.value.field_value()))
    }
}

#[tokio::test]
async fn mixed_backup_codes_keep_nonmatching_values_and_native_view_output() -> TestResult {
    let codes: FieldValue = vec![
        "used".into(),
        7.0.into(),
        "keep".into(),
        FieldMap::from([("nested".into(), true.into())]).into(),
        "used".into(),
        "2026-01-02T03:04:05Z".into(),
    ]
    .into();
    let fixture = Fixture::new(codes, true.into()).await?;
    let view = view_backup_codes_core(
        "native-factor-user",
        &fixture.config.backup_code_options,
        &fixture.ctx,
    )
    .await?;
    assert!(
        view.as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_date().is_some())
    );
    let (response, cookies) = fixture.verify("used").await?;
    assert!(response.token.is_undefined());
    assert!(cookies.is_empty());
    assert!(fixture.attempts().await?.is_none());
    let row = fixture.factor().await?;
    assert_eq!(row.failed_verification_count.field_value(), 0.0.into());
    assert!(row.locked_until.field_value().is_null());
    assert_eq!(
        row.backup_codes.field_value().as_str(),
        Some("[7,\"keep\",{\"nested\":true},\"2026-01-02T03:04:05.000Z\"]")
    );
    assert!(
        fixture
            .ctx
            .database
            .get_verification_by_identifier("native-factor-challenge")
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn backup_invalid_values_and_method_errors_keep_distinct_failure_budgets() -> TestResult {
    for (value, invalid_code) in [
        (FieldValue::Null, true),
        (false.into(), true),
        (0.0.into(), true),
        ("".into(), true),
        ("not-json".into(), true),
        (7.0.into(), false),
        (
            FieldMap::from([("value".into(), true.into())]).into(),
            false,
        ),
        ("\"text\"".into(), false),
    ] {
        let fixture = Fixture::new(value.clone(), true.into()).await?;
        let error = fixture.verify("not-present").await.unwrap_err();
        assert_eq!(error.status_code(), if invalid_code { 401 } else { 500 });
        assert_eq!(
            fixture.attempts().await?,
            Some(if invalid_code { "1" } else { "0" }.into())
        );
        assert_eq!(
            fixture
                .factor()
                .await?
                .failed_verification_count
                .field_value(),
            if invalid_code { 1.0 } else { 0.0 }.into()
        );
        assert!(
            fixture
                .factor()
                .await?
                .backup_codes
                .field_value()
                .strict_equals(&value)
        );
        assert!(
            fixture
                .ctx
                .database
                .get_verification_by_identifier("native-factor-challenge")
                .await?
                .is_some()
        );
    }
    Ok(())
}

#[tokio::test]
async fn failed_attempt_reuses_main_challenge_expiry() -> TestResult {
    let fixture = Fixture::new("[]".into(), true.into()).await?;
    let challenge = fixture
        .ctx
        .database
        .get_verification_by_identifier("native-factor-challenge")
        .await?
        .unwrap();
    fixture
        .ctx
        .database
        .delete_verification_by_identifier("2fa-attempts-native-factor-challenge")
        .await?;
    let _ = fixture
        .ctx
        .database
        .create_verification(CreateVerification {
            identifier: "2fa-attempts-native-factor-challenge".into(),
            value: "0".into(),
            expires_at: (Utc::now() + Duration::minutes(1)).into(),
            ..Default::default()
        })
        .await?;
    assert_eq!(
        fixture.verify("missing").await.unwrap_err().status_code(),
        401
    );
    let counter = fixture
        .ctx
        .database
        .get_verification_by_identifier("2fa-attempts-native-factor-challenge")
        .await?
        .unwrap();
    assert_eq!(counter.value.field_value(), "1".into());
    assert_eq!(
        counter.expires_at.field_value(),
        challenge.expires_at.field_value()
    );
    Ok(())
}

#[tokio::test]
async fn native_secret_errors_restore_attempts_after_strict_verified_check() -> TestResult {
    for verified in [
        false.into(),
        FieldValue::Null,
        0.0.into(),
        "false".into(),
        true.into(),
    ] {
        let fixture = Fixture::new("[]".into(), verified.clone()).await?;
        let error = verify_totp_core(
            &fixture.request,
            &VerifyTotpRequest {
                code: "123456".into(),
                trust_device: None,
            },
            &fixture.config,
            &fixture.ctx,
        )
        .await
        .unwrap_err();
        if verified.strict_equals(&false.into()) {
            assert_eq!(error.to_string(), "TOTP not enabled");
        } else {
            assert!(
                matches!(error, AuthError::Internal(message) if message == "hex string expected, got number")
            );
        }
        assert_eq!(fixture.attempts().await?, Some("0".into()));
        assert_eq!(
            fixture
                .factor()
                .await?
                .failed_verification_count
                .field_value(),
            0.0.into()
        );
    }
    Ok(())
}

#[tokio::test]
async fn otp_native_values_preserve_counter_parsing_and_consumption() -> TestResult {
    for (value, status, replacement, failures) in [
        (17.0.into(), 500, None, 0.0),
        (vec![FieldValue::from("otp")].into(), 500, None, 0.0),
        (FieldValue::Null, 401, Some("undefined:1"), 1.0),
        (FieldValue::Undefined, 401, Some("undefined:1"), 1.0),
        ("otp:  +2tail".into(), 401, Some("otp:3"), 1.0),
        ("otp:-1".into(), 401, Some("otp:0"), 1.0),
        ("otp:Infinity".into(), 401, Some("otp:1"), 1.0),
        ("otp:0xF".into(), 401, Some("otp:1"), 1.0),
        ("otp:5".into(), 400, None, 0.0),
    ] {
        let fixture = Fixture::new("[]".into(), true.into()).await?;
        let identifier = otp_verification_identifier("native-factor-challenge");
        let _ = fixture
            .ctx
            .database
            .create_verification(CreateVerification {
                identifier: identifier.clone().into(),
                value: SchemaValue::from_field(value),
                expires_at: (Utc::now() + Duration::minutes(5)).into(),
                ..Default::default()
            })
            .await?;
        let error = verify_otp_core(
            &fixture.request,
            &VerifyOtpRequest {
                code: "wrong".into(),
                trust_device: None,
            },
            &fixture.config,
            &fixture.ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(error.status_code(), status);
        let remaining = fixture
            .ctx
            .database
            .get_verification_by_identifier(&identifier)
            .await?;
        assert_eq!(
            remaining.map(|row| row.value.field_value()),
            replacement.map(FieldValue::from)
        );
        assert_eq!(
            fixture
                .factor()
                .await?
                .failed_verification_count
                .field_value(),
            failures.into()
        );
        assert_eq!(fixture.attempts().await?, Some("0".into()));
    }
    Ok(())
}

struct ReplacingCipher {
    store: Arc<dyn AuthStore<StatelessSchema>>,
    id: SchemaValue<String>,
    seen: Mutex<Vec<FieldValue>>,
}

#[tokio::test]
async fn decrypted_short_secret_reaches_totp_verification() -> TestResult {
    let fixture = Fixture::new("[]".into(), true.into()).await?;
    let encrypted = encrypt_value(fixture.ctx.config.encryption_secret(), "x")?;
    let _ = fixture
        .ctx
        .database
        .update_two_factor_record(
            &fixture.id,
            FieldMap::from([("secret".into(), encrypted.into())]),
        )
        .await?;
    let error = verify_totp_core(
        &fixture.request,
        &VerifyTotpRequest {
            code: "not-a-number".into(),
            trust_device: None,
        },
        &fixture.config,
        &fixture.ctx,
    )
    .await
    .unwrap_err();
    assert_eq!(error.status_code(), 401);
    assert_eq!(fixture.attempts().await?, Some("1".into()));
    assert_eq!(
        fixture
            .factor()
            .await?
            .failed_verification_count
            .field_value(),
        1.0.into()
    );
    Ok(())
}

#[async_trait]
impl TwoFactorCipher for ReplacingCipher {
    async fn encrypt(&self, plaintext: &str) -> AuthResult<String> {
        Ok(plaintext.into())
    }
    async fn decrypt(&self, _: &str) -> AuthResult<String> {
        Err(AuthError::internal(
            "The native callback must receive ciphertext",
        ))
    }
    async fn decrypt_native(&self, ciphertext: &FieldValue) -> AuthResult<FieldValue> {
        self.seen.lock().unwrap().push(ciphertext.clone());
        let _ = self
            .store
            .update_two_factor_record(
                &self.id,
                FieldMap::from([("backupCodes".into(), "newer-codes".into())]),
            )
            .await?;
        Ok(vec![FieldValue::from("used")].into())
    }
}

#[tokio::test]
async fn native_cipher_receives_original_value_and_cas_keeps_concurrent_replacement() -> TestResult
{
    let original: FieldValue = FieldMap::from([("opaque".into(), 7.0.into())]).into();
    let mut fixture = Fixture::new(original.clone(), true.into()).await?;
    let _ = fixture
        .ctx
        .database
        .update_two_factor_record(
            &fixture.id,
            FieldMap::from([("failedVerificationCount".into(), 4.0.into())]),
        )
        .await?;
    let cipher = Arc::new(ReplacingCipher {
        store: fixture.ctx.database.clone(),
        id: fixture.id.clone(),
        seen: Mutex::new(Vec::new()),
    });
    fixture.config.backup_code_options.storage = BackupCodeStorage::Custom(cipher.clone());
    let error = fixture.verify("used").await.unwrap_err();
    assert_eq!(error.status_code(), 409);
    assert_eq!(cipher.seen.lock().unwrap().len(), 1);
    assert!(
        cipher
            .seen
            .lock()
            .unwrap()
            .first()
            .unwrap()
            .strict_equals(&original)
    );
    assert_eq!(
        fixture.factor().await?.backup_codes.field_value(),
        "newer-codes".into()
    );
    assert_eq!(
        fixture
            .factor()
            .await?
            .failed_verification_count
            .field_value(),
        4.0.into()
    );
    assert!(fixture.attempts().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn finalization_preserves_selected_native_owner_token_and_cookie() -> TestResult {
    use better_auth_core::user_fields::{
        FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType,
    };
    let mut fixture = Fixture::new("[]".into(), true.into()).await?;
    let mut config = fixture.ctx.config.as_ref().clone();
    let _ = config.session.fields_mut().insert(
        "token".into(),
        UserFieldConfig {
            field_type: UserFieldType::String,
            transform: Some(FieldTransforms {
                input: None,
                output: Some(UserFieldTransform::new(|_| Ok(42.0.into()))),
            }),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let store =
        fixture
            .ctx
            .database
            .with_runtime(config.clone(), Vec::new(), fixture.fields.clone())?;
    fixture.ctx = AuthContext::new(config, store);
    fixture
        .ctx
        .database
        .delete_verification_by_identifier("native-factor-challenge")
        .await?;
    let _ = fixture
        .ctx
        .database
        .create_verification(CreateVerification {
            identifier: "native-factor-challenge".into(),
            value: SchemaValue::from_field(17.0.into()),
            expires_at: (Utc::now() + Duration::minutes(5)).into(),
            ..Default::default()
        })
        .await?;
    let mut selected = FieldMap::from(fixture.user);
    let _ = selected.insert("id".into(), 17.0.into());
    let _ = selected.insert("name".into(), "Selected Native Owner".into());
    let user = UserView::try_from(selected)?;
    let (response, cookies) = finalize_pending_two_factor(
        PendingTwoFactorState {
            user,
            key: "native-factor-challenge".into(),
            dont_remember: false,
            expires_at: (Utc::now() + Duration::minutes(5)).into(),
        },
        &fixture.request,
        false,
        &fixture.ctx,
    )
    .await?;
    assert_eq!(response.token, 42.0.into());
    assert_eq!(response.user.id.field_value(), 17.0.into());
    assert_eq!(
        response.user.field_values()?.get("name"),
        Some(&FieldValue::from("Selected Native Owner"))
    );
    let published = fixture.request.new_session()?.unwrap();
    assert_eq!(published.user_field("id"), &FieldValue::from(17.0));
    assert_eq!(
        published.session.field_values()?.get("userId"),
        Some(&17.0.into())
    );
    assert_eq!(
        published.session.field_values()?.get("token"),
        Some(&42.0.into())
    );
    let queued = fixture.request.take_response_headers()?;
    let cookie = queued
        .get_all("Set-Cookie")
        .find(|cookie| cookie.starts_with("better-auth.session_token="))
        .unwrap();
    assert_eq!(
        verify_signed_cookie_value(
            fixture.ctx.config.signing_secret(),
            &tests::cookie_value(cookie)
        )?,
        Some("42".into())
    );
    assert!(cookies.is_empty());
    assert!(queued.get_all("Set-Cookie").any(
        |cookie| cookie.starts_with("better-auth.two_factor=") && cookie.contains("Max-Age=0")
    ));
    assert!(
        fixture
            .ctx
            .database
            .get_verification_by_identifier("native-factor-challenge")
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn trust_device_failure_preserves_session_and_challenge_cookie_effects() -> TestResult {
    let mut fixture = Fixture::new("[]".into(), true.into()).await?;
    fixture.ctx.extensions.insert(TwoFactorConfig {
        trust_device_max_age: f64::INFINITY,
        ..fixture.config.clone()
    });
    let error = finalize_pending_two_factor(
        PendingTwoFactorState {
            user: fixture.user.clone(),
            key: "native-factor-challenge".into(),
            dont_remember: false,
            expires_at: (Utc::now() + Duration::minutes(5)).into(),
        },
        &fixture.request,
        true,
        &fixture.ctx,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, AuthError::Config(_)));
    assert!(fixture.request.new_session()?.is_some());
    assert!(
        fixture
            .ctx
            .database
            .get_verification_by_identifier("native-factor-challenge")
            .await?
            .is_none()
    );
    let queued = fixture.request.take_response_headers()?;
    assert!(
        queued
            .get_all("Set-Cookie")
            .any(|cookie| cookie.starts_with("better-auth.session_token="))
    );
    assert!(queued.get_all("Set-Cookie").any(
        |cookie| cookie.starts_with("better-auth.two_factor=") && cookie.contains("Max-Age=0")
    ));
    assert!(
        !queued
            .get_all("Set-Cookie")
            .any(|cookie| cookie.starts_with("better-auth.trust_device=")
                || cookie.starts_with("better-auth.dont_remember="))
    );
    Ok(())
}
