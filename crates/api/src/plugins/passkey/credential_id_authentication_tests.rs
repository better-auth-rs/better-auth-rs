use super::*;
use crate::plugins::passkey::{
    PasskeyAuthenticationHook, PasskeyAuthenticationOptions, PasskeyAuthenticationVerification,
    PasskeyEndpoint,
};

#[derive(Default)]
struct VerificationTrace {
    sessions: Arc<SessionTrace>,
    verifications: Mutex<Vec<PasskeyAuthenticationVerification>>,
}

#[async_trait::async_trait]
impl PasskeyAuthenticationHook for VerificationTrace {
    async fn after_verification(
        &self,
        _: PasskeyEndpoint<'_>,
        verification: &PasskeyAuthenticationVerification,
        _: &Value,
    ) -> AuthResult<()> {
        self.sessions
            .events
            .lock()
            .unwrap()
            .push("verification".into());
        self.verifications
            .lock()
            .unwrap()
            .push(verification.clone());
        Ok(())
    }
}

// SimpleWebAuthn verifies the selected public key and returns the projected credential ID without decoding that ID.
#[tokio::test]
async fn authentication_preserves_projected_credential_ids_without_changing_signature_or_owner_checks()
-> TestResult {
    let path = std::env::temp_dir().join(format!(
        "better-auth-passkey-credential-id-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    drop(std::fs::File::create_new(&path)?);
    let mut fixture = Fixture::create(&path).await?;
    let raw = fixture.ctx.database.clone();
    let owner = raw
        .create_user(
            CreateUser::new()
                .with_name("Credential owner")
                .with_email("credential-id@passkey.example"),
        )
        .await?;
    let authenticator = Authenticator::new()?;
    let wrong_key = Authenticator::new()?;
    let passkey = seed_native(&fixture, &owner, &authenticator).await?;
    let trace = Arc::new(VerificationTrace::default());
    let plugin = PasskeyPlugin::new()
        .rp_id(RP_ID)
        .rp_name("Passkey credential ID")
        .origin(ORIGIN)
        .authentication(PasskeyAuthenticationOptions {
            after_verification: Some(trace.clone()),
            ..Default::default()
        });
    for projected in [
        URL_SAFE_NO_PAD.encode(b"different-credential").into(),
        FieldValue::Null,
        7.0.into(),
        FieldValue::Undefined,
        Utf16String::from_units(vec![0xd800]).into(),
        vec![FieldValue::from(7.0)].into(),
        FieldMap::from([("id".into(), 7.0.into())]).into(),
    ] {
        raw.update_passkey_authentication(
            &passkey.id,
            UpdatePasskeyAuthentication::Native { counter: 0 },
        )
        .await?;
        let replacement = projected.clone();
        let counter_trace = trace.clone();
        let config = fixture.ctx.config.as_ref().clone();
        install_fields(
            &mut fixture,
            raw.clone(),
            config,
            UserConfig {
                additional_fields: Some(
                    [
                        (
                            "credentialID".into(),
                            output(UserFieldTransform::new(move |_| Ok(replacement.clone()))),
                        ),
                        (
                            "counter".into(),
                            output(UserFieldTransform::new(move |value| {
                                counter_trace
                                    .sessions
                                    .events
                                    .lock()
                                    .unwrap()
                                    .push(format!("counter:{}", value.stringify()?.unwrap()));
                                Ok(value)
                            })),
                        ),
                    ]
                    .into(),
                ),
            },
            vec![trace.sessions.clone()],
        )
        .await?;
        for (signer, allowed) in [(&wrong_key, false), (&authenticator, true)] {
            trace.sessions.events.lock().unwrap().clear();
            trace.sessions.owners.lock().unwrap().clear();
            trace.verifications.lock().unwrap().clear();
            let sessions_before = raw.get_user_sessions(owner.id.typed()?).await?;
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
            let signed =
                signer.authenticate(&challenge(&pending)?, 1, owner.id.typed()?.as_bytes())?;
            let request = request(
                "/passkey/verify-authentication",
                None,
                Some(json!({"response": signed})),
                Some(&cookie),
            );
            let context = fixture.ctx.initialize_request_context().await?;
            let response = plugin
                .handle_verify_authentication(&request, &context)
                .await?;
            let mut expected = passkey.clone();
            if allowed {
                assert_login(response, owner.id.typed()?)?;
                expected.counter = 1.into();
                assert_eq!(
                    *trace.sessions.events.lock().unwrap(),
                    [
                        "counter:0",
                        "verification",
                        "counter:1",
                        "session:before",
                        "session:after"
                    ]
                );
                assert_eq!(
                    *trace.sessions.owners.lock().unwrap(),
                    [owner.id.field_value()]
                );
                let verifications = trace.verifications.lock().unwrap();
                assert_eq!(verifications.len(), 1);
                let verification = &verifications[0];
                assert!(verification.verified);
                assert_eq!(verification.authentication_info.new_counter, 1);
                assert!(
                    verification
                        .authentication_info
                        .credential_id
                        .field_value()
                        .same_value_zero(&projected)
                );
                let encoded = FieldValue::parse_json(&serde_json::to_string(verification)?)?;
                let info = field(&encoded, "authenticationInfo")?
                    .as_object()
                    .ok_or("Expected serialized authentication information")?;
                if projected.is_undefined() {
                    assert!(!info.contains_key("credentialID"));
                } else {
                    assert_eq!(info.get("credentialID"), Some(&projected));
                }
            } else {
                assert_error(response, "AUTHENTICATION_FAILED")?;
                assert_eq!(*trace.sessions.events.lock().unwrap(), ["counter:0"]);
                assert!(trace.sessions.owners.lock().unwrap().is_empty());
                assert!(trace.verifications.lock().unwrap().is_empty());
            }
            let stored = raw
                .get_passkey_by_id(passkey.id.typed()?)
                .await?
                .ok_or("Missing selected passkey")?;
            assert_eq!(stored, expected);
            let sessions_after = raw.get_user_sessions(owner.id.typed()?).await?;
            assert_eq!(
                sessions_after.len(),
                sessions_before.len() + usize::from(allowed)
            );
            assert!(
                sessions_after
                    .iter()
                    .all(|session| session.user_id == owner.id)
            );
            if !allowed {
                assert_eq!(sessions_after, sessions_before);
            }
        }
    }
    drop(raw);
    fixture.close().await?;
    std::fs::remove_file(path)?;
    Ok(())
}
