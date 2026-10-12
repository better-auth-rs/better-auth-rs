#![expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use crate::plugins::passkey::{
    PasskeyAuthenticationHook, PasskeyAuthenticationOptions, PasskeyAuthenticationVerification,
    PasskeyEndpoint,
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct DeleteSelected {
    store: Arc<dyn AuthStore<BundledSchema>>,
    id: String,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl PasskeyAuthenticationHook for DeleteSelected {
    async fn after_verification(
        &self,
        _: PasskeyEndpoint<'_>,
        verification: &PasskeyAuthenticationVerification,
        _: &Value,
    ) -> AuthResult<()> {
        assert!(verification.verified);
        assert_eq!(verification.authentication_info.new_counter, 1);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.store.delete_passkey(&self.id).await
    }
}

#[tokio::test]
async fn nullable_updates_reach_authentication_and_rename_business_boundaries() -> TestResult {
    for authentication in [true, false] {
        let path = std::env::temp_dir().join(format!(
            "better-auth-passkey-null-update-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        drop(std::fs::File::create_new(&path)?);
        let mut fixture = Fixture::create(&path).await?;
        let raw = fixture.ctx.database.clone();
        let (owner, login) = test_helpers::create_user_and_session(
            &fixture.ctx,
            CreateUser::new()
                .with_name("Owner")
                .with_email("null-update@passkey.example"),
            fixture.ctx.config.session.expires_in(),
        )
        .await;
        let authenticator = Authenticator::new()?;
        let passkey = seed_native(&fixture, &owner, &authenticator).await?;
        let sessions_before = raw.get_user_sessions(owner.id.typed()?).await?;
        let calls = Arc::new(AtomicUsize::new(0));
        if authentication {
            let plugin = PasskeyPlugin::new()
                .rp_id(RP_ID)
                .rp_name("Nullable passkey update")
                .origin(ORIGIN)
                .authentication(PasskeyAuthenticationOptions {
                    after_verification: Some(Arc::new(DeleteSelected {
                        store: raw.clone(),
                        id: passkey.id.typed()?.clone(),
                        calls: calls.clone(),
                    })),
                    ..Default::default()
                });
            let (pending, cookie) = options(
                fixture
                    .route(&request(
                        "/passkey/generate-authenticate-options",
                        None,
                        None,
                        None,
                    ))
                    .await?,
            )?;
            let signed = authenticator.authenticate(
                &challenge(&pending)?,
                1,
                owner.id.typed()?.as_bytes(),
            )?;
            let request = request(
                "/passkey/verify-authentication",
                None,
                Some(json!({"response":signed})),
                Some(&cookie),
            );
            let context = fixture.ctx.initialize_request_context().await?;
            let response = plugin
                .handle_verify_authentication(&request, &context)
                .await?;
            let response = test_helpers::finalize_response(&context, &request, response);
            assert!(response.headers.contains_key("Set-Cookie"));
            let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
            assert_login(response, owner.id.typed()?)?;
            let sessions = raw.get_user_sessions(owner.id.typed()?).await?;
            assert_eq!(sessions.len(), sessions_before.len() + 1);
            let created = sessions
                .iter()
                .find(|session| !sessions_before.iter().any(|old| old.id == session.id))
                .ok_or("Authentication must persist its new session")?;
            assert_eq!(
                body,
                json!({
                    "session":fixture.ctx.session_view(created).await?,
                    "user":fixture.ctx.user_view(&owner).await?,
                })
            );
        } else {
            let store = raw.clone();
            let id = passkey.id.typed()?.clone();
            let observed = calls.clone();
            let fields = UserConfig {
                additional_fields: Some(
                    [(
                        "name".into(),
                        UserFieldConfig {
                            required: Some(false),
                            transform: Some(FieldTransforms {
                                input: Some(UserFieldTransform::new_async(move |value| {
                                    let store = store.clone();
                                    let id = id.clone();
                                    let observed = observed.clone();
                                    async move {
                                        observed.fetch_add(1, Ordering::SeqCst);
                                        store.delete_passkey(&id).await?;
                                        Ok(value)
                                    }
                                })),
                                output: None,
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            };
            let config = fixture.ctx.config.as_ref().clone();
            install_fields(&mut fixture, raw.clone(), config, fields, Vec::new()).await?;
            let error = fixture
                .route(&request(
                    "/passkey/update-passkey",
                    Some(login.token.typed()?),
                    Some(json!({"id":passkey.id,"name":"Renamed"})),
                    None,
                ))
                .await
                .err()
                .ok_or("A missing rename update must fail")?;
            test_helpers::assert_coded_api_error(
                &error,
                "INTERNAL_SERVER_ERROR",
                500,
                "FAILED_TO_UPDATE_PASSKEY",
                "Failed to update passkey",
            );
            assert_eq!(
                raw.get_user_sessions(owner.id.typed()?).await?,
                sessions_before
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            raw.list_passkeys_by_user(owner.id.typed()?)
                .await?
                .is_empty()
        );
        assert_eq!(raw.get_user_by_id(owner.id.typed()?).await?, Some(owner));
        drop(raw);
        fixture.close().await?;
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[tokio::test]
async fn counter_and_backup_flags_preserve_validation_order_without_persistence() -> TestResult {
    let path = std::env::temp_dir().join(format!(
        "better-auth-passkey-counter-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    drop(std::fs::File::create_new(&path)?);
    let mut fixture = Fixture::create(&path).await?;
    let raw = fixture.ctx.database.clone();
    let owner = raw
        .create_user(
            CreateUser::new()
                .with_name("Owner")
                .with_email("counter@passkey.example"),
        )
        .await?;
    let authenticator = Authenticator::new()?;
    let wrong_key = Authenticator::new()?;
    let passkey = seed_native(&fixture, &owner, &authenticator).await?;
    let passkey = raw
        .update_passkey_authentication(
            &passkey.id,
            UpdatePasskeyAuthentication::Native { counter: 2 },
        )
        .await?;
    let logs = Arc::new(Mutex::new(Vec::<FieldValue>::new()));
    let observed = logs.clone();
    let logger: better_auth_core::FieldObject = FieldMap::from([
        ("level".into(), "error".into()),
        (
            "log".into(),
            better_auth_core::FieldFunction::contextual(move |_, arguments| {
                assert_eq!(arguments.len(), 3);
                let error = arguments
                    .get(2)
                    .ok_or_else(|| AuthError::internal("Logger error is absent"))?;
                observed.lock().unwrap().push(
                    vec![
                        arguments.first().cloned().expect("Logger level is present"),
                        arguments
                            .get(1)
                            .cloned()
                            .expect("Logger message is present"),
                        error.model_property("name")?,
                        error.model_property("message")?,
                        error.enumerable_fields()?.into(),
                    ]
                    .into(),
                );
                Ok(FieldValue::Undefined)
            })
            .into(),
        ),
    ])
    .into();
    let mut config = fixture.ctx.config.as_ref().clone();
    config.logger = logger.into();
    config.initialize_logger()?;
    let conversions = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let counter_value = Arc::new(FieldValue::from(FieldMap::new()));
    for (method, result) in [
        ("valueOf", FieldValue::Number(2.0)),
        ("toString", "projected counter".into()),
    ] {
        let receiver = Arc::downgrade(&counter_value);
        let observed = conversions.clone();
        counter_value.set_model_property(
            method,
            better_auth_core::FieldFunction::contextual(move |this, arguments| {
                let original = receiver.upgrade().expect("Counter value remains alive");
                assert!(this.strict_equals(original.as_ref()));
                assert!(arguments.is_empty());
                observed.lock().unwrap().push(method);
                Ok(result.clone())
            })
            .into(),
        )?;
    }
    for dynamic in [false, true] {
        let projected = counter_value.clone();
        let fields = UserConfig {
            additional_fields: Some(
                [(
                    "counter".into(),
                    UserFieldConfig {
                        field_type: better_auth_core::user_fields::UserFieldType::Number,
                        required: Some(true),
                        transform: Some(FieldTransforms {
                            input: None,
                            output: Some(UserFieldTransform::new(move |value| {
                                assert_eq!(value, FieldValue::Number(2.0));
                                Ok(if dynamic {
                                    projected.as_ref().clone()
                                } else {
                                    value
                                })
                            })),
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        };
        install_fields(
            &mut fixture,
            raw.clone(),
            config.clone(),
            fields,
            Vec::new(),
        )
        .await?;
        for (signer, flags, counter_valid, origin, rp_id) in [
            (&authenticator, 0x05, false, ORIGIN, RP_ID),
            (&wrong_key, 0x05, false, ORIGIN, RP_ID),
            (&authenticator, 0x15, false, ORIGIN, RP_ID),
            (&wrong_key, 0x15, false, ORIGIN, RP_ID),
            (&authenticator, 0x15, true, ORIGIN, RP_ID),
            (&wrong_key, 0x15, true, ORIGIN, RP_ID),
            (
                &authenticator,
                0x15,
                false,
                "https://wrong-origin.test",
                RP_ID,
            ),
            (&authenticator, 0x15, false, ORIGIN, "wrong-rp.test"),
        ] {
            logs.lock().unwrap().clear();
            conversions.lock().unwrap().clear();
            let (pending, cookie) = options(
                fixture
                    .route(&request(
                        "/passkey/generate-authenticate-options",
                        None,
                        None,
                        None,
                    ))
                    .await?,
            )?;
            let counter = if counter_valid {
                3
            } else if dynamic {
                0
            } else {
                1
            };
            let signed = signer.authenticate_for(
                &challenge(&pending)?,
                counter,
                owner.id.typed()?.as_bytes(),
                flags,
                origin,
                rp_id,
            )?;
            let input = request(
                "/passkey/verify-authentication",
                None,
                Some(json!({"response": signed})),
                Some(&cookie),
            );
            let response = fixture
                .ctx
                .with_native_context(Default::default(), |context| async move {
                    route(&context, &input).await
                })
                .await;
            assert_authentication_error(response)?;
            let origin_message = format!(
                "Unexpected authentication response origin \"{origin}\", expected \"{ORIGIN}\""
            );
            let (error_name, message) = if origin != ORIGIN {
                ("Error", origin_message.as_str())
            } else if rp_id != RP_ID {
                ("UnexpectedRPIDHash", "Unexpected RP ID hash")
            } else if counter_valid {
                (
                    "InvalidBackupFlags",
                    "Single-device credential indicated that it was backed up, which should be impossible.",
                )
            } else if dynamic {
                (
                    "Error",
                    "Response counter value 0 was lower than expected projected counter",
                )
            } else {
                (
                    "Error",
                    "Response counter value 1 was lower than expected 2",
                )
            };
            assert_eq!(
                *logs.lock().unwrap(),
                [FieldValue::from_json(json!([
                    "error",
                    "Failed to verify authentication",
                    error_name,
                    message,
                    if matches!(error_name, "InvalidBackupFlags" | "UnexpectedRPIDHash") {
                        json!({"name":error_name})
                    } else {
                        json!({})
                    },
                ]))?]
            );
            assert_eq!(
                *conversions.lock().unwrap(),
                if !dynamic || origin != ORIGIN || rp_id != RP_ID {
                    Vec::new()
                } else if counter_valid {
                    vec!["valueOf"]
                } else {
                    vec!["valueOf", "valueOf", "toString"]
                }
            );
            assert_eq!(
                raw.get_passkey_by_id(passkey.id.typed()?).await?,
                Some(passkey.clone())
            );
            assert_eq!(
                raw.get_user_by_id(owner.id.typed()?).await?,
                Some(owner.clone())
            );
            assert!(raw.get_user_sessions(owner.id.typed()?).await?.is_empty());
        }
    }
    drop(raw);
    fixture.close().await?;
    std::fs::remove_file(path)?;
    Ok(())
}
