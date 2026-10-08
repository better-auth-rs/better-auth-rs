use super::*;
use better_auth_core::{
    AuthInitContext, FieldValue, Utf16String,
    store::schema::EntityRole,
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};

// Source-derived contract: Better Auth 1.7.6 and SimpleWebAuthn option generation; upstream capture is pending.
#[tokio::test]
async fn options_consume_native_descriptors_without_utf16_loss_or_stricter_base64_validation() {
    let plugin = passkey_plugin();
    let (mut ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("descriptor@example.com")
            .with_name("Descriptor owner"),
        Duration::hours(1),
    )
    .await;
    let raw = ctx.database.clone();
    let passkey = raw
        .create_passkey(CreatePasskey {
            additional_fields: Default::default(),
            user_id: user.id.typed().unwrap().clone(),
            name: None.into(),
            credential_id: credential_id("existing"),
            public_key: "unused by options".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: Some("internal".into()),
            credential: "unused by options".into(),
            aaguid: None.into(),
        })
        .await
        .unwrap();
    let utf16 = Utf16String::from_units(vec![
        b'u'.into(),
        b's'.into(),
        b'b'.into(),
        b','.into(),
        0xd800,
        b','.into(),
    ]);
    for (id, transports, expected_id, expected_transports) in [
        (
            FieldValue::from("Y=WI==="),
            FieldValue::from(utf16),
            Some("YWI"),
            vec![
                FieldValue::from("usb"),
                Utf16String::from_units(vec![0xd800]).into(),
                "".into(),
            ]
            .into(),
        ),
        (
            "A".into(),
            FieldValue::Null,
            Some("A"),
            FieldValue::Undefined,
        ),
        (
            "".into(),
            FieldValue::Undefined,
            Some(""),
            FieldValue::Undefined,
        ),
        (
            "AB".into(),
            "".into(),
            Some("AB"),
            vec![FieldValue::from("")].into(),
        ),
        (
            "bad+id".into(),
            FieldValue::Null,
            None,
            FieldValue::Undefined,
        ),
        (
            FieldValue::Number(17.0),
            FieldValue::Null,
            None,
            FieldValue::Undefined,
        ),
        (
            FieldValue::Undefined,
            FieldValue::Null,
            None,
            FieldValue::Undefined,
        ),
        (
            Utf16String::from_units(vec![0xd800]).into(),
            FieldValue::Null,
            None,
            FieldValue::Undefined,
        ),
        (
            "valid".into(),
            FieldValue::Bool(false),
            None,
            FieldValue::Undefined,
        ),
    ] {
        let mut init = AuthInitContext::new(ctx.config.clone(), raw.clone());
        better_auth_core::AuthPlugin::on_init(&plugin, &mut init)
            .await
            .unwrap();
        init.register_model_fields(
            EntityRole::Passkey,
            UserConfig {
                additional_fields: Some(
                    [
                        ("credentialID".into(), id),
                        ("transports".into(), transports),
                    ]
                    .into_iter()
                    .map(|(name, value)| {
                        (
                            name,
                            UserFieldConfig {
                                required: Some(false),
                                transform: Some(FieldTransforms {
                                    input: None,
                                    output: Some(UserFieldTransform::new(move |_| {
                                        Ok(value.clone())
                                    })),
                                }),
                                ..Default::default()
                            },
                        )
                    })
                    .collect(),
                ),
            },
        )
        .unwrap();
        ctx.database = raw
            .with_runtime(
                ctx.config.clone(),
                Vec::new(),
                init.into_parts().plugin_fields,
            )
            .unwrap();
        for (path, property) in [
            ("/passkey/generate-register-options", "excludeCredentials"),
            ("/passkey/generate-authenticate-options", "allowCredentials"),
        ] {
            let req = test_helpers::create_auth_request_no_query(
                HttpMethod::Get,
                path,
                Some(session.token.typed().unwrap()),
                None,
            );
            let response = if property == "excludeCredentials" {
                plugin.handle_generate_register_options(&req, &ctx).await
            } else {
                plugin
                    .handle_generate_authenticate_options(&req, &ctx)
                    .await
            };
            let Some(expected_id) = expected_id else {
                assert_eq!(response.unwrap_err().status_code(), 500);
                continue;
            };
            let response = response.unwrap();
            assert_eq!(response.status, 200);
            assert!(cookie_header(&response).contains("better-auth-passkey="));
            let body = response.body.field_value().unwrap();
            let descriptor = body.as_object().unwrap()[property].as_array().unwrap()[0]
                .as_object()
                .unwrap();
            assert_eq!(descriptor["id"], FieldValue::from(expected_id));
            assert_eq!(descriptor["transports"], expected_transports);
            assert_eq!(descriptor["type"], FieldValue::from("public-key"));
            let bytes = response.body.bytes().unwrap();
            let serialized = FieldValue::parse_json(std::str::from_utf8(&bytes).unwrap()).unwrap();
            let descriptor = serialized.as_object().unwrap()[property]
                .as_array()
                .unwrap()[0]
                .as_object()
                .unwrap();
            assert_eq!(
                descriptor.get("transports"),
                (!expected_transports.is_undefined()).then_some(&expected_transports)
            );
        }
        let stored = raw
            .get_passkey_by_id(passkey.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.credential_id, passkey.credential_id);
        assert_eq!(stored.transports, passkey.transports);
    }
}
