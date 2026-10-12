#![expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Native method contracts assert receiver identity, exact errors, and committed storage. Fixture locks must be available."
)]
use super::*;
use crate::plugins::passkey::transport_method_fixture::{CASES, Transport};
use better_auth_core::FieldFunction;

impl Transport {
    async fn install(
        &self,
        fixture: &mut Fixture,
        raw: Arc<dyn AuthStore<BundledSchema>>,
        config: AuthConfig,
    ) -> TestResult {
        let receiver = self.receiver.clone();
        install_fields(
            fixture,
            raw,
            config,
            UserConfig {
                additional_fields: Some(
                    [(
                        "transports".into(),
                        output(UserFieldTransform::new(move |_| {
                            Ok(receiver.as_ref().clone())
                        })),
                    )]
                    .into(),
                ),
            },
            Vec::new(),
        )
        .await
    }
}

#[tokio::test]
async fn native_options_retain_split_results_and_original_method_errors() -> TestResult {
    let path = std::env::temp_dir().join(format!(
        "better-auth-passkey-split-options-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    drop(std::fs::File::create_new(&path)?);
    let mut fixture = Fixture::create(&path).await?;
    let raw = fixture.ctx.database.clone();
    let (owner, session) = test_helpers::create_user_and_session(
        &fixture.ctx,
        CreateUser::new()
            .with_name("Owner")
            .with_email("split-options@passkey.example"),
        fixture.ctx.config.session.expires_in(),
    )
    .await;
    let authenticator = Authenticator::new()?;
    let passkey = seed_native(&fixture, &owner, &authenticator).await?;
    let sessions = raw.get_user_sessions(owner.id.typed()?).await?;
    for name in CASES {
        let transport = Transport::new(name)?;
        let config = fixture.ctx.config.as_ref().clone();
        transport.install(&mut fixture, raw.clone(), config).await?;
        for (path, property) in [
            ("/passkey/generate-register-options", "excludeCredentials"),
            ("/passkey/generate-authenticate-options", "allowCredentials"),
        ] {
            transport.events.lock().unwrap().clear();
            let response = fixture
                .route(&request(path, Some(session.token.typed()?), None, None))
                .await;
            transport.assert_calls(name);
            if Transport::fails(name) {
                let error = response.err().ok_or("Expected original split error")?;
                if name == "noncallable" {
                    assert!(
                        matches!(error, AuthError::TypeError(message) if message == "passkey.transports?.split is not a function. (In 'passkey.transports?.split(\",\")', 'passkey.transports?.split' is 17)")
                    );
                } else {
                    transport.assert_original(&error);
                }
            } else {
                let response = response?;
                assert_eq!(response.status, 200);
                assert!(response.headers.contains_key("Set-Cookie"));
                let descriptor = response
                    .body
                    .field_value()?
                    .model_property(property)?
                    .model_property("0")?;
                assert_eq!(
                    descriptor
                        .enumerable_fields()?
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    ["id", "transports", "type"]
                );
                assert_eq!(
                    descriptor.model_property("id")?,
                    passkey.credential_id.field_value()
                );
                assert_eq!(descriptor.model_property("type")?, "public-key".into());
                assert!(
                    descriptor
                        .model_property("transports")?
                        .strict_equals(&transport.result)
                );
                transport.assert_calls(name);
                if name == "unread-result" {
                    let error = response
                        .body
                        .bytes()
                        .err()
                        .ok_or("Serialization must read toJSON")?;
                    transport.assert_original(&error);
                    assert_eq!(
                        *transport.events.lock().unwrap(),
                        ["split:get", "split:call", "result:read"]
                    );
                } else {
                    let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
                    let serialized = body
                        .get(property)
                        .and_then(|value| value.get(0))
                        .ok_or("Missing descriptor")?;
                    let mut expected =
                        json!({"id": passkey.credential_id.typed()?, "type": "public-key"});
                    if let Some(value) = transport.result.json()? {
                        let _ = expected
                            .as_object_mut()
                            .ok_or("Expected descriptor object")?
                            .insert("transports".into(), value);
                    }
                    assert_eq!(*serialized, expected);
                    transport.assert_calls(name);
                }
            }
            assert_eq!(
                raw.get_passkey_by_id(passkey.id.typed()?).await?,
                Some(passkey.clone())
            );
            assert_eq!(
                raw.get_user_by_id(owner.id.typed()?).await?,
                Some(owner.clone())
            );
            assert_eq!(raw.get_user_sessions(owner.id.typed()?).await?, sessions);
        }
    }
    drop(raw);
    fixture.close().await?;
    std::fs::remove_file(path)?;
    Ok(())
}

#[tokio::test]
async fn native_authentication_invokes_split_without_consuming_its_result() -> TestResult {
    let path = std::env::temp_dir().join(format!(
        "better-auth-passkey-split-authentication-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    drop(std::fs::File::create_new(&path)?);
    let mut fixture = Fixture::create(&path).await?;
    let raw = fixture.ctx.database.clone();
    let owner = raw
        .create_user(
            CreateUser::new()
                .with_name("Owner")
                .with_email("split-authentication@passkey.example"),
        )
        .await?;
    let authenticator = Authenticator::new()?;
    let wrong_key = Authenticator::new()?;
    let passkey = seed_native(&fixture, &owner, &authenticator).await?;
    for name in CASES {
        let transport = Transport::new(name)?;
        let logs = Arc::new(Mutex::new(Vec::new()));
        let logger: better_auth_core::FieldObject = FieldMap::from([
            ("level".into(), "error".into()),
            (
                "log".into(),
                FieldFunction::contextual({
                    let logs = logs.clone();
                    move |_, arguments| {
                        assert_eq!(arguments.len(), 3);
                        assert_eq!(arguments.first(), Some(&FieldValue::from("error")));
                        assert_eq!(
                            arguments.get(1),
                            Some(&FieldValue::from("Failed to verify authentication"))
                        );
                        logs.lock()
                            .unwrap()
                            .push(arguments.get(2).cloned().unwrap());
                        Ok(FieldValue::Undefined)
                    }
                })
                .into(),
            ),
        ])
        .into();
        let mut config = fixture.ctx.config.as_ref().clone();
        config.logger = logger.into();
        config.initialize_logger()?;
        transport.install(&mut fixture, raw.clone(), config).await?;
        for valid_signature in [false, true] {
            raw.update_passkey_authentication(
                &passkey.id,
                UpdatePasskeyAuthentication::Native { counter: 0 },
            )
            .await?;
            let sessions = raw.get_user_sessions(owner.id.typed()?).await?;
            transport.events.lock().unwrap().clear();
            logs.lock().unwrap().clear();
            let signer = if valid_signature {
                &authenticator
            } else {
                &wrong_key
            };
            let input = authentication_request(&fixture, signer, owner.id.typed()?).await?;
            let response = fixture
                .ctx
                .with_native_context(Default::default(), |context| async move {
                    route(&context, &input).await
                })
                .await;
            transport.assert_calls(name);
            let succeeded = valid_signature && !Transport::fails(name);
            if name == "api-error" {
                let error = response.err().ok_or("Expected APIError from split")?;
                transport.assert_original(&error);
                assert_eq!(error.status_code()?, 409);
            } else if Transport::fails(name) {
                assert_authentication_error(response)?;
                let logged = logs.lock().unwrap();
                assert_eq!(logged.len(), 1);
                let error = logged.first().ok_or("Missing original split log")?;
                if name == "noncallable" {
                    assert_eq!(error.model_property("name")?, "TypeError".into());
                    assert_eq!(
                        error.model_property("message")?,
                        "passkey.transports?.split is not a function. (In 'passkey.transports?.split(\",\")', 'passkey.transports?.split' is 17)".into()
                    );
                } else {
                    assert!(error.strict_equals(&transport.original));
                }
            } else if valid_signature {
                assert_login(response?, owner.id.typed()?)?;
            } else {
                assert_verification_error(
                    response,
                    "UNAUTHORIZED",
                    401,
                    FieldMap::from([
                        ("message".into(), "Authentication failed".into()),
                        ("code".into(), "AUTHENTICATION_FAILED".into()),
                    ]),
                )?;
            }
            if !Transport::fails(name) || name == "api-error" {
                assert!(logs.lock().unwrap().is_empty());
            }
            let stored = raw
                .get_passkey_by_id(passkey.id.typed()?)
                .await?
                .ok_or("Missing passkey")?;
            let mut expected = passkey.clone();
            expected.counter = u64::from(succeeded).into();
            assert_eq!(stored, expected);
            assert_eq!(
                raw.get_user_by_id(owner.id.typed()?).await?,
                Some(owner.clone())
            );
            let after = raw.get_user_sessions(owner.id.typed()?).await?;
            if succeeded {
                assert_eq!(after.len(), sessions.len() + 1);
                assert!(sessions.iter().all(|session| after.contains(session)));
            } else {
                assert_eq!(after, sessions);
            }
        }
    }
    drop(raw);
    fixture.close().await?;
    std::fs::remove_file(path)?;
    Ok(())
}
