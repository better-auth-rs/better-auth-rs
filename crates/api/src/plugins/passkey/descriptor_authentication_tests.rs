use super::*;
use better_auth_core::{
    AuthInitContext, CreatePasskey, FieldValue, PasskeyCredentialState,
    UpdatePasskeyAuthentication, Utf16String,
    store::schema::EntityRole,
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};

// Source-derived contract: transports are split before verification and are not used to verify signatures.
#[tokio::test]
async fn native_authentication_accepts_utf16_transport_hints_and_rejects_non_string_transports()
-> TestResult {
    let path = std::env::temp_dir().join(format!(
        "better-auth-passkey-transports-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    drop(std::fs::File::create_new(&path)?);
    let mut fixture = Fixture::create(&path).await?;
    let raw = fixture.ctx.database.clone();
    let owner = raw
        .create_user(
            CreateUser::new()
                .with_name("Transport owner")
                .with_email("transport@passkey.example"),
        )
        .await?;
    let authenticator = Authenticator::new()?;
    let passkey = raw
        .create_passkey(CreatePasskey {
            additional_fields: Default::default(),
            user_id: owner.id.typed()?.clone(),
            name: None.into(),
            public_key: STANDARD.encode(&authenticator.cose),
            credential_id: URL_SAFE_NO_PAD.encode(CREDENTIAL_ID),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: Some("internal,hybrid".into()),
            credential: PasskeyCredentialState::Native,
            aaguid: None.into(),
        })
        .await?;
    let mut transport_units = "internal,".encode_utf16().collect::<Vec<_>>();
    transport_units.push(0xd800);
    transport_units.extend(",hybrid".encode_utf16());
    for (transports, allowed) in [
        (
            FieldValue::from(Utf16String::from_units(transport_units)),
            true,
        ),
        (FieldValue::Null, true),
        (FieldValue::Undefined, true),
        (FieldValue::Bool(false), false),
        (FieldValue::from(vec![FieldValue::from("internal")]), false),
    ] {
        raw.update_passkey_authentication(
            &passkey.id,
            UpdatePasskeyAuthentication::Native { counter: 0 },
        )
        .await?;
        let mut init = AuthInitContext::new(fixture.ctx.config.clone(), raw.clone());
        better_auth_core::AuthPlugin::on_init(&PasskeyPlugin::new(), &mut init).await?;
        init.register_model_fields(
            EntityRole::Passkey,
            UserConfig {
                additional_fields: Some(
                    [(
                        "transports".into(),
                        UserFieldConfig {
                            required: Some(false),
                            transform: Some(FieldTransforms {
                                input: None,
                                output: Some(UserFieldTransform::new(move |_| {
                                    Ok(transports.clone())
                                })),
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        )?;
        fixture.ctx.database = raw.with_runtime(
            fixture.ctx.config.clone(),
            Vec::new(),
            init.into_parts().plugin_fields,
        )?;
        let (options, cookie) = options(
            fixture
                .route(&request(
                    "/passkey/generate-authenticate-options",
                    None,
                    None,
                    None,
                ))
                .await?,
        )?;
        let response =
            authenticator.authenticate(&challenge(&options)?, 1, owner.id.typed()?.as_bytes())?;
        let response = fixture
            .route(&request(
                "/passkey/verify-authentication",
                None,
                Some(json!({"response":response})),
                Some(&cookie),
            ))
            .await?;
        if allowed {
            assert_login(response, owner.id.typed()?)?;
        } else {
            assert_error(response, "AUTHENTICATION_FAILED")?;
        }
        let stored = raw
            .get_passkey_by_id(passkey.id.typed()?)
            .await?
            .ok_or("Passkey disappeared")?;
        assert_eq!(stored.counter, u64::from(allowed));
        assert_eq!(stored.transports, passkey.transports);
    }
    drop(raw);
    fixture.close().await?;
    std::fs::remove_file(path)?;
    Ok(())
}
