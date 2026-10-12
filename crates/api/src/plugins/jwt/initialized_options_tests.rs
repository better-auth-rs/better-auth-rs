#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "JWT ownership regressions compare native identities, original errors, and real signing results."
)]

use super::*;
use better_auth_core::{
    FieldFunction,
    session::NativeSessionData,
    store::{AuthStore, EphemeralStore, StatelessSchema as S},
};
use std::sync::{Arc, Mutex};

async fn context(plugin: &dyn AuthPlugin<S>) -> AuthResult<AuthContext<S>> {
    let config = Arc::new(crate::plugins::test_helpers::create_test_config());
    let store: Arc<dyn AuthStore<S>> = Arc::new(EphemeralStore::new(config.clone()));
    let mut context =
        crate::plugins::test_helpers::initialize_test_context(config, store, &[plugin]).await?;
    context.extensions.insert(Arc::new(
        better_auth_core::endpoint_dispatch::EndpointDispatcher::<S>::new(
            Arc::new(Vec::new()),
            better_auth_core::observability::EndpointHooks::default(),
            [],
        ),
    ));
    Ok(context)
}

fn echo() -> JwtNativeCustomSign {
    Arc::new(|payload, _, _| Box::pin(async move { Ok(payload) }))
}

#[tokio::test]
async fn registered_facades_share_options_and_direct_helpers_keep_their_own_config()
-> AuthResult<()> {
    let plugin = JwtPlugin::with_config(JwtPluginConfig {
        custom_sign: Some(echo()),
        ..Default::default()
    })
    .algorithm(JwtAlgorithm::EdDsa)
    .remote_url("https://keys.example.test".into())
    .issuer("configured".into())
    .audience(vec!["first".into(), "second".into()].into())
    .expiration_time(Duration::seconds(30));
    let context = context(&plugin).await?;
    let cloned_context = context.clone();
    let api = JwtApi::from_context(&context)?;
    let cloned_api = JwtApi::from_context(&cloned_context)?;
    let options = overrides::NativeOptions::registered(&context)?;
    assert!(plugin.options.0.strict_equals(&options.0));
    assert!(
        options
            .0
            .strict_equals(&overrides::NativeOptions::registered(&cloned_context)?.0)
    );
    let jwt = options.0.model_property("jwt")?;
    let original_sign = jwt.model_property("sign")?;
    let endpoint = EndpointContext::native(None, None, FieldValue::Undefined, &context);
    let original = plugin
        .sign_value_in_endpoint(
            FieldMap::from([("iat".into(), 100.into())]).into(),
            None,
            &endpoint,
        )
        .await?;
    assert_eq!(original.model_property("iss")?, "configured".into());
    assert_eq!(original.model_property("exp")?, 130.into());
    assert_eq!(
        original.model_property("aud")?,
        vec![FieldValue::from("first"), "second".into()].into()
    );
    assert!(jwt.model_property("sign")?.strict_equals(&original_sign));

    jwt.set_model_property("issuer", "mutated".into())?;
    jwt.set_model_property(
        "sign",
        FieldFunction::contextual(|receiver, arguments| {
            let count = better_auth_core::query::field_number(&receiver.model_property("calls")?)?;
            receiver.set_model_property("calls", (count + 1.0).into())?;
            Ok(arguments.first().cloned().unwrap_or_default())
        })
        .into(),
    )?;
    jwt.set_model_property("calls", 0.into())?;
    for api in [&api, &cloned_api] {
        let signed = api.sign_value(FieldMap::new().into()).await?;
        assert_eq!(signed.model_property("iss")?, "mutated".into());
    }
    assert_eq!(jwt.model_property("calls")?, 2.into());
    let isolated = plugin.clone().issuer("independent".into());
    assert!(!isolated.options.0.strict_equals(&options.0));
    let direct = isolated
        .sign_value_in_endpoint(FieldMap::new().into(), None, &endpoint)
        .await?;
    assert_eq!(direct.model_property("iss")?, "independent".into());
    assert_eq!(jwt.model_property("calls")?, 2.into());
    assert!(context.database.list_jwk_records().await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn retained_options_drive_signing_verification_adapter_writes_and_shallow_overrides()
-> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let reads = events.clone();
    let writes = events.clone();
    let plugin = JwtPlugin::new().callbacks(
        JwtCallbacks::<S>::default()
            .get_jwks(move |endpoint| {
                reads.lock().unwrap().push("read");
                Box::pin(async move { endpoint.auth.database.list_jwks().await.map(Some) })
            })
            .create_jwk(move |key, endpoint| {
                writes.lock().unwrap().push("create");
                Box::pin(async move { endpoint.auth.database.create_jwk(key).await.map(Some) })
            }),
    );
    let context = context(&plugin).await?;
    let options = overrides::NativeOptions::registered(&context)?;
    let jwt = options.0.model_property("jwt")?;
    let jwks = options.0.model_property("jwks")?;
    let adapter = options.0.model_property("adapter")?;
    let read_callback = adapter.model_property("getJwks")?;
    jwt.set_model_property("issuer", "first".into())?;
    jwt.set_model_property("audience", "machine".into())?;
    jwks.set_model_property("rotationInterval", "3600".into())?;
    jwks.set_model_property("disablePrivateKeyEncryption", true.into())?;
    let api = JwtApi::from_context(&context)?;
    let payload = || FieldMap::from([("sub".into(), "owner".into())]).into();
    let token: String = api.sign_value(payload()).await?.decode()?;
    assert_eq!(
        api.verify(&token, None).await?.unwrap().get("sub"),
        Some(&Value::from("owner"))
    );
    let rows = context.database.list_jwk_records().await?;
    assert_eq!(rows.len(), 1);
    let key: FieldValue = rows.first().unwrap().clone().into();
    assert!(keys::parse_json(&key.model_property("privateKey")?)?.has_property("d")?);
    assert!(key.model_property("expiresAt")?.as_date().is_some());

    jwt.set_model_property("issuer", "second".into())?;
    assert!(api.verify(&token, None).await?.is_none());
    let override_jwt: FieldValue = FieldMap::from([
        ("issuer".into(), "first".into()),
        ("audience".into(), "machine".into()),
    ])
    .into();
    let override_token: String = api
        .sign_value_with_overrides(
            payload(),
            FieldMap::from([("jwt".into(), override_jwt)]).into(),
        )
        .await?
        .decode()?;
    assert!(api.verify(&override_token, Some("first")).await?.is_some());
    assert_eq!(jwt.model_property("issuer")?, "second".into());
    assert!(options.0.model_property("jwks")?.strict_equals(&jwks));
    assert!(options.0.model_property("adapter")?.strict_equals(&adapter));
    assert!(
        adapter
            .model_property("getJwks")?
            .strict_equals(&read_callback)
    );
    assert_eq!(context.database.list_jwk_records().await?.len(), 1);
    assert_eq!(
        *events.lock().unwrap(),
        ["read", "read", "create", "read", "read", "read", "read"]
    );
    Ok(())
}

#[tokio::test]
async fn retained_session_callbacks_keep_receiver_mutations_and_original_failures() -> AuthResult<()>
{
    let plugin = JwtPlugin::new()
        .algorithm(JwtAlgorithm::EdDsa)
        .remote_url("https://keys.example.test".into())
        .custom_sign_native(echo());
    let context = context(&plugin).await?;
    let jwt = plugin.options.0.model_property("jwt")?;
    let failure: FieldValue = FieldMap::from([("failure".into(), "subject".into())]).into();
    let original = failure.clone();
    jwt.set_model_property(
        "definePayload",
        FieldFunction::contextual(|receiver, arguments| {
            receiver.set_model_property("payloadSeen", arguments.first().unwrap().clone())?;
            Ok(FieldMap::from([("kept".into(), true.into())]).into())
        })
        .into(),
    )?;
    jwt.set_model_property(
        "getSubject",
        FieldFunction::contextual(move |receiver, arguments| {
            assert!(
                receiver
                    .model_property("payloadSeen")?
                    .strict_equals(arguments.first().unwrap())
            );
            receiver.set_model_property("subjectSeen", true.into())?;
            Err(AuthError::from_thrown(original.clone()))
        })
        .into(),
    )?;
    let session = NativeSessionData::from_native(
        FieldMap::from([
            (
                "user".into(),
                FieldMap::from([("id".into(), "owner".into())]).into(),
            ),
            ("session".into(), FieldMap::new().into()),
        ])
        .into(),
        true,
    );
    let endpoint = EndpointContext::native(None, None, FieldValue::Undefined, &context);
    assert!(
        plugin
            .sign_session(Some(session.clone()), &endpoint)
            .await
            .unwrap_err()
            .into_thrown_value()?
            .strict_equals(&failure)
    );
    assert_eq!(jwt.model_property("subjectSeen")?, true.into());
    jwt.set_model_property(
        "getSubject",
        FieldFunction::contextual(|receiver, _| {
            assert_eq!(receiver.model_property("subjectSeen")?, true.into());
            Ok("replacement-subject".into())
        })
        .into(),
    )?;
    let signed = plugin
        .clone()
        .sign_session(Some(session), &endpoint)
        .await?;
    assert_eq!(signed.model_property("sub")?, "replacement-subject".into());
    assert_eq!(signed.model_property("kept")?, true.into());
    assert!(context.database.list_jwk_records().await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn verifier_consumes_native_option_methods_after_signature_verification() -> AuthResult<()> {
    let plugin = JwtPlugin::new().disable_private_key_encryption(true);
    let context = context(&plugin).await?;
    let api = JwtApi::from_context(&context)?;
    let token: String = api
        .sign_value(
            FieldMap::from([
                ("sub".into(), "owner".into()),
                ("aud".into(), vec![FieldValue::from("team")].into()),
            ])
            .into(),
        )
        .await?
        .decode()?;
    let jwt = plugin.options.0.model_property("jwt")?;
    let issuer: FieldValue = vec![
        FieldValue::from("other"),
        FieldValue::from("http://localhost:3000"),
    ]
    .into();
    let issuer_calls = Arc::new(Mutex::new(0));
    let observed_issuer = issuer_calls.clone();
    issuer.set_model_property(
        "includes",
        FieldFunction::contextual(move |receiver, arguments| {
            assert!(receiver.is_array());
            *observed_issuer.lock().unwrap() += 1;
            Ok(arguments
                .first()
                .unwrap()
                .strict_equals(&"http://localhost:3000".into())
                .into())
        })
        .into(),
    )?;
    jwt.set_model_property("issuer", issuer)?;
    let calls = Arc::new(Mutex::new(0));
    let observed = calls.clone();
    let audience: FieldValue = FieldMap::from([
        ("marker".into(), "original receiver".into()),
        (
            "some".into(),
            FieldFunction::contextual(move |receiver, arguments| {
                assert_eq!(
                    receiver.model_property("marker")?,
                    "original receiver".into()
                );
                *observed.lock().unwrap() += 1;
                let FieldValue::Function(predicate) = arguments.first().unwrap() else {
                    return Err(AuthError::internal("Audience predicate is missing"));
                };
                predicate.call_with(&FieldValue::Undefined, &["team".into()])
            })
            .into(),
        ),
    ])
    .into();
    jwt.set_model_property("audience", audience)?;
    let (signed, _) = token.rsplit_once('.').unwrap();
    assert!(api.verify(&format!("{signed}.AA"), None).await?.is_none());
    assert_eq!(*calls.lock().unwrap(), 0);
    assert_eq!(*issuer_calls.lock().unwrap(), 0);
    let records = context.database.list_jwk_records().await?;
    let key: FieldValue = records.first().unwrap().clone().into();
    let private: String = key.model_property("privateKey")?.decode()?;
    let private = Jwk::from_bytes(private.as_bytes()).map_err(jose_error)?;
    let signer = jws::EdDSA.signer_from_jwk(&private).map_err(jose_error)?;
    let missing_audience = jose::sign(
        FieldMap::from([
            ("sub".into(), "owner".into()),
            ("iss".into(), "http://localhost:3000".into()),
        ]),
        FieldMap::from([
            ("alg".into(), "EdDSA".into()),
            ("kid".into(), key.model_property("id")?),
        ]),
        &signer,
    )?;
    assert!(api.verify(&missing_audience, None).await?.is_none());
    assert_eq!(*issuer_calls.lock().unwrap(), 0);
    assert_eq!(*calls.lock().unwrap(), 0);
    assert!(api.verify(&token, None).await?.is_some());
    assert_eq!(*issuer_calls.lock().unwrap(), 1);
    assert_eq!(*calls.lock().unwrap(), 1);
    let sparse: FieldValue = better_auth_core::FieldArray::with_length(3).into();
    sparse.set_model_property("2", "team".into())?;
    jwt.set_model_property("audience", sparse)?;
    assert!(api.verify(&token, None).await?.is_some());
    assert_eq!(context.database.list_jwk_records().await?.len(), 1);
    Ok(())
}
