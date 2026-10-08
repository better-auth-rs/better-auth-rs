use super::*;
use better_auth_core::{
    AuthInitContext, AuthPlugin, AuthSchema, CreatePasskey, FieldMap, FieldValue,
    PasskeyCredentialState, SchemaValue,
    store::{
        EphemeralStore, MemoryCacheAdapter, SecondaryStorage, StatelessSchema, schema::EntityRole,
        secondary::SecondaryStore,
    },
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
    wire::PasskeyView,
};

#[path = "owner_operation_tests.rs"]
mod owner_operation_tests;

fn cases() -> AuthResult<Vec<FieldMap>> {
    let values = FieldValue::parse_json(include_str!(
        "../../../../../tests/fixtures/passkey-user-id-cases.json"
    ))?;
    values
        .as_array()
        .ok_or_else(|| AuthError::internal("Passkey owner cases must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_object()
                .cloned()
                .ok_or_else(|| AuthError::internal("Passkey owner case must be an object"))
        })
        .collect()
}

fn replacement(sample: &FieldMap) -> FieldValue {
    let value = sample.get("value").unwrap().clone();
    if value
        .as_object()
        .is_some_and(|value| value.get("type").and_then(FieldValue::as_str) == Some("undefined"))
    {
        FieldValue::Undefined
    } else {
        value
    }
}

fn memory() -> AuthContext<StatelessSchema> {
    let mut config = test_helpers::create_test_config().base_url(ORIGIN);
    config.telemetry.enabled = false;
    let config = Arc::new(config);
    AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))
}

async fn project<S: AuthSchema>(
    ctx: &AuthContext<S>,
    id: FieldValue,
    token: &str,
    passkey_owner: Option<FieldValue>,
) -> TestResult<(AuthContext<S>, String)> {
    let mut config = ctx.config.as_ref().clone();
    config.session.store_session_in_database = Some(true);
    let config = Arc::new(config);
    let mut init = AuthInitContext::new(config.clone(), ctx.database.clone());
    AuthPlugin::on_init(&PasskeyPlugin::new(), &mut init).await?;
    if let Some(owner) = passkey_owner {
        init.register_model_fields(
            EntityRole::Passkey,
            UserConfig {
                additional_fields: Some(
                    [(
                        "userId".into(),
                        UserFieldConfig {
                            transform: Some(FieldTransforms {
                                output: Some(UserFieldTransform::new(move |_| Ok(owner.clone()))),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        )?;
    }
    let database =
        ctx.database
            .with_runtime(config.clone(), Vec::new(), init.into_parts().plugin_fields)?;
    let cache = Arc::new(MemoryCacheAdapter::new());
    let database =
        SecondaryStore::new(database, cache.clone(), config.clone(), Default::default())?;
    let mut projected = AuthContext::new(config, Arc::new(database));
    projected.secondary_storage = Some(cache.clone());
    let mut user = ctx
        .database
        .get_user_by_id("7")
        .await?
        .ok_or("Missing owner")?;
    user.id = SchemaValue::from_field(id);
    let session = ctx
        .database
        .get_session(token)
        .await?
        .ok_or("Missing session")?;
    let data = projected
        .session_manager()
        .internal_data(&user, &session)
        .await?;
    let mut session = FieldMap::from(data.session);
    let _ = session.insert("expiresAt".into(), "2100-01-01T00:00:00.000Z".into());
    let envelope = FieldValue::from(FieldMap::from([
        ("session".into(), session.into()),
        ("user".into(), FieldMap::from(data.user).into()),
    ]));
    cache
        .set(token, &envelope.stringify()?.unwrap(), None)
        .await?;
    let cookie =
        better_auth_core::utils::cookie_utils::create_session_cookie(token, &projected.config)?;
    Ok((projected, cookie.split(';').next().unwrap().to_owned()))
}

async fn owner_session<S: AuthSchema>(ctx: &AuthContext<S>) -> TestResult<String> {
    let _ = ctx
        .database
        .create_user(CreateUser {
            id: Some("7".into()),
            ..CreateUser::new()
                .with_email("owner@passkey.example")
                .with_name("Owner")
        })
        .await?;
    let session = ctx
        .session_manager()
        .create_session_for_id_with_lifetime("7".into(), None, None, chrono::Duration::hours(1))
        .await?;
    Ok(session.token.typed()?.clone())
}

async fn response<S: AuthSchema>(ctx: &AuthContext<S>, request: &AuthRequest) -> AuthResponse {
    match route(ctx, request).await {
        Ok(response) => response,
        Err(error) => test_helpers::finalize_response(ctx, request, error.to_auth_response()),
    }
}

async fn existing_passkey<S: AuthSchema>(ctx: &AuthContext<S>) -> TestResult<Passkey> {
    Ok(ctx
        .database
        .create_passkey(CreatePasskey {
            additional_fields: Default::default(),
            user_id: "7".into(),
            name: Some("Existing".into()).into(),
            credential_id: URL_SAFE_NO_PAD.encode(CREDENTIAL_ID),
            public_key: "unused by options".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: Some("internal,hybrid".into()),
            credential: PasskeyCredentialState::Legacy("unused by options".into()),
            aaguid: None.into(),
        })
        .await?)
}

async fn option_queries<S: AuthSchema>(ctx: AuthContext<S>, sqlite: bool) -> TestResult {
    let token = owner_session(&ctx).await?;
    let passkey = existing_passkey(&ctx).await?;
    for sample in cases()? {
        let Some(matches) = sample.get(if sqlite {
            "sqliteMatches"
        } else {
            "memoryMatches"
        }) else {
            continue;
        };
        let selected = matches.strict_equals(&1.0.into());
        let (projected, session_cookie) = project(&ctx, replacement(&sample), &token, None).await?;
        let list = response(
            &projected,
            &request(
                "/passkey/list-user-passkeys",
                None,
                None,
                Some(&session_cookie),
            ),
        )
        .await;
        assert_eq!(list.status, 200, "{sample:?}");
        let expected = if selected {
            vec![PasskeyView::from(&passkey)]
        } else {
            Vec::new()
        };
        assert_eq!(
            serde_json::from_slice::<Value>(&list.body.bytes()?)?,
            serde_json::to_value(expected)?,
            "{sample:?}"
        );
        let authentication = response(
            &projected,
            &request(
                "/passkey/generate-authenticate-options",
                None,
                None,
                Some(&session_cookie),
            ),
        )
        .await;
        let (authentication, _) = options(authentication)?;
        let descriptors = if selected {
            json!([{"id": URL_SAFE_NO_PAD.encode(CREDENTIAL_ID), "type": "public-key", "transports": TRANSPORTS}])
        } else {
            json!([])
        };
        assert_eq!(
            authentication.get("allowCredentials"),
            selected.then_some(&descriptors),
            "{sample:?}"
        );
        let registration = response(
            &projected,
            &request(
                "/passkey/generate-register-options",
                None,
                None,
                Some(&session_cookie),
            ),
        )
        .await;
        if sample
            .get("registration")
            .unwrap()
            .strict_equals(&401.0.into())
        {
            assert_eq!(registration.status, 401, "{sample:?}");
            assert_eq!(
                serde_json::from_slice::<Value>(&registration.body.bytes()?)?,
                json!({
                    "code": "SESSION_REQUIRED", "message": "Passkey registration requires an authenticated session"
                })
            );
        } else {
            let (registration, _) = options(registration)?;
            assert_eq!(
                registration["excludeCredentials"], descriptors,
                "{sample:?}"
            );
            let handle = URL_SAFE_NO_PAD.decode(registration["user"]["id"].as_str().unwrap())?;
            assert_eq!(handle.len(), 32);
            assert!(
                handle
                    .iter()
                    .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit())
            );
        }
    }
    assert_eq!(
        ctx.database.get_passkey_by_id(passkey.id.typed()?).await?,
        Some(passkey)
    );
    Ok(())
}

#[tokio::test]
async fn memory_options_and_lists_query_native_user_ids() -> TestResult {
    option_queries(memory(), false).await
}

#[tokio::test]
async fn sqlite_options_and_lists_apply_native_owner_binding() -> TestResult {
    option_queries(
        test_helpers::create_test_context_with_config(
            test_helpers::create_test_config().base_url(ORIGIN),
        )
        .await,
        true,
    )
    .await
}

#[tokio::test]
async fn signed_registration_retains_native_owners_and_rejects_json_changed_identity() -> TestResult
{
    for create_session in [false, true] {
        for sample in cases()? {
            let Some(expected) = sample.get(if create_session {
                "sessionVerification"
            } else {
                "verification"
            }) else {
                continue;
            };
            let ctx = memory();
            let token = owner_session(&ctx).await?;
            let value = replacement(&sample);
            let (projected, session_cookie) = project(&ctx, value.clone(), &token, None).await?;
            let (generated, cookie) = options(
                response(
                    &projected,
                    &request(
                        "/passkey/generate-register-options",
                        None,
                        None,
                        Some(&session_cookie),
                    ),
                )
                .await,
            )?;
            let authenticator = Authenticator::new()?;
            let signed = authenticator.register(&challenge(&generated)?, Some(TRANSPORTS))?;
            let body = json!({"response": signed, "name": "Native owner", "createSession": create_session});
            let cookies = format!("{session_cookie}; {cookie}");
            let verify = request(
                "/passkey/verify-registration",
                None,
                Some(body.clone()),
                Some(&cookies),
            );
            let verified = response(&projected, &verify).await;
            let success = expected.strict_equals(&200.0.into());
            assert_eq!(
                verified.status,
                if success {
                    200
                } else if expected.strict_equals(&500.0.into()) {
                    500
                } else {
                    401
                },
                "{sample:?}"
            );
            let stored = ctx
                .database
                .get_passkey_by_credential_id(&URL_SAFE_NO_PAD.encode(CREDENTIAL_ID))
                .await?;
            if success {
                let stored = stored.ok_or("Missing registered native owner")?;
                let output_id = FieldValue::from(value.display_utf16()?);
                assert!(
                    stored.user_id.field_value().strict_equals(&output_id),
                    "{sample:?}"
                );
                assert!(
                    verified
                        .body
                        .field_value()?
                        .as_object()
                        .unwrap()
                        .get("userId")
                        .unwrap()
                        .strict_equals(&output_id)
                );
                assert_eq!(
                    ctx.database
                        .list_passkeys_by_user_value(&value)
                        .await?
                        .len(),
                    1
                );
                if !value.strict_equals(&output_id) {
                    assert!(
                        ctx.database
                            .list_passkeys_by_user_value(&output_id)
                            .await?
                            .is_empty()
                    );
                }
                assert_eq!(stored.counter, 0);
                if create_session {
                    let result = verified.body.field_value()?;
                    let result = result.as_object().unwrap();
                    for name in ["user", "session"] {
                        let record = result.get(name).unwrap().as_object().unwrap();
                        assert_eq!(
                            record.get(if name == "user" { "id" } else { "userId" }),
                            Some(&FieldValue::from("7"))
                        );
                    }
                }
            } else {
                assert!(stored.is_none());
                assert_eq!(
                    serde_json::from_slice::<Value>(&verified.body.bytes()?)?,
                    if expected.strict_equals(&500.0.into()) {
                        json!({"code": "USER_NOT_FOUND", "message": "User not found"})
                    } else {
                        json!({
                            "code": "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
                            "message": "You are not allowed to register this passkey"
                        })
                    }
                );
            }
            let replay = response(&projected, &verify).await;
            assert_eq!(replay.status, 400);
            assert_eq!(
                serde_json::from_slice::<Value>(&replay.body.bytes()?)?,
                json!({
                    "code": "CHALLENGE_NOT_FOUND", "message": "Challenge not found"
                })
            );
            assert_eq!(
                ctx.database.get_user_sessions("7").await?.len(),
                if create_session && success { 2 } else { 1 }
            );
        }
    }
    Ok(())
}
