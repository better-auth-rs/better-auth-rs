use super::*;
use chrono::TimeZone as _;

#[tokio::test]
async fn keyring_reads_live_configuration_after_the_bound_adapter_returns() -> AuthResult<()> {
    let trace = Arc::new(Trace::default());
    let jwks = ObservedFields::new(
        FieldMap::from([(
            "keyPairConfig".into(),
            FieldMap::from([("alg".into(), "EdDSA".into())]).into(),
        )]),
        trace.clone(),
        None,
    );
    let legacy: FieldValue = FieldMap::from([
        ("id".into(), "legacy".into()),
        ("alg".into(), FieldValue::Null),
        (
            "createdAt".into(),
            FieldDate::from_milliseconds(20.0).into(),
        ),
    ])
    .into();
    let older: FieldValue = FieldMap::from([
        ("id".into(), "older".into()),
        ("alg".into(), "ES256".into()),
        (
            "createdAt".into(),
            FieldDate::from_milliseconds(10.0).into(),
        ),
    ])
    .into();
    let expected = legacy.clone();
    let current = jwks.value();
    let events = trace.clone();
    let callbacks = JwtCallbacks::<S>::default().get_jwks_native(move |endpoint| {
        assert_eq!(endpoint.auth.config.base_url.as_static(), Some(BASE));
        events.record("getJwks");
        let result = current.set_model_property(
            "keyPairConfig",
            FieldMap::from([("alg".into(), "ES256".into())]).into(),
        );
        let keys = vec![older.clone(), legacy.clone()];
        Box::pin(async move {
            result?;
            Ok(keys.into())
        })
    });
    let options = overrides::NativeOptions(
        FieldMap::from([
            ("jwks".into(), jwks.value()),
            ("adapter".into(), callbacks.into_native()),
        ])
        .into(),
    );
    let plugin = JwtPlugin::new();
    let context = context(&plugin, JwtCallbacks::default()).await?;
    let endpoint = EndpointContext::native(None, None, FieldValue::Null, &context);
    let keyring = adapter::Keyring::new(adapter::store(&endpoint), &options, &endpoint);
    assert!(
        keyring
            .latest(Some("ES256".into()))
            .await?
            .strict_equals(&expected)
    );
    assert_eq!(
        *trace.events.lock().unwrap(),
        ["getJwks", "get:keyPairConfig"]
    );
    Ok(())
}

#[tokio::test]
async fn custom_sign_does_not_read_unused_jwks_or_serialize_nested_options() -> AuthResult<()> {
    for to_json in [false, true] {
        let trace = Arc::new(Trace::default());
        let failure: FieldValue = FieldMap::from([("unused".into(), true.into())]).into();
        let returned: FieldValue = FieldMap::from([("signed".into(), true.into())]).into();
        let token = returned.clone();
        let jwt: FieldValue = FieldMap::from([(
            "sign".into(),
            FieldFunction::contextual(move |_, _| Ok(token.clone())).into(),
        )])
        .into();
        let original = failure.clone();
        let jwks: FieldValue = FieldMap::from([(
            "toJSON".into(),
            FieldFunction::contextual(move |_, _| Err(AuthError::from_thrown(original.clone())))
                .into(),
        )])
        .into();
        let options = ObservedFields::new(
            FieldMap::from([("jwt".into(), jwt), ("jwks".into(), jwks)]),
            trace.clone(),
            (!to_json).then_some(("jwks", failure)),
        );
        let plugin = JwtPlugin::new();
        let context = context(&plugin, JwtCallbacks::default()).await?;
        let endpoint = EndpointContext::native(None, None, FieldValue::Null, &context);
        assert!(
            plugin
                .sign_native_options(
                    claims(),
                    None,
                    &overrides::NativeOptions(options.value()),
                    &endpoint
                )
                .await?
                .strict_equals(&returned)
        );
        assert_eq!(*trace.events.lock().unwrap(), vec!["get:jwt"; 5]);
        assert!(context.database.list_jwk_records().await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn generated_keys_keep_rotation_truthiness_repeated_reads_and_failure_identity()
-> AuthResult<()> {
    for mode in [
        "zero",
        "nan",
        "string-zero",
        "object",
        "negative",
        "failure",
    ] {
        let trace = Arc::new(Trace::default());
        let failure: FieldValue = FieldMap::from([("rotation".into(), true.into())]).into();
        let original = failure.clone();
        let events = trace.clone();
        let interval = match mode {
            "zero" => 0.0.into(),
            "nan" => f64::NAN.into(),
            "string-zero" => "0".into(),
            "negative" => (-2.0).into(),
            _ => FieldMap::from([(
                "valueOf".into(),
                FieldFunction::contextual(move |_, _| {
                    events.record("rotation.valueOf");
                    if mode == "failure" {
                        return Err(AuthError::from_thrown(original.clone()));
                    }
                    Ok("2".into())
                })
                .into(),
            )])
            .into(),
        };
        let jwks = ObservedFields::new(
            FieldMap::from([
                (
                    "keyPairConfig".into(),
                    FieldMap::from([
                        ("alg".into(), "EdDSA".into()),
                        ("crv".into(), "Ed25519".into()),
                    ])
                    .into(),
                ),
                ("disablePrivateKeyEncryption".into(), true.into()),
                ("rotationInterval".into(), interval),
            ]),
            trace.clone(),
            None,
        );
        let captured = Arc::new(Mutex::new(None::<FieldValue>));
        let saved = captured.clone();
        let events = trace.clone();
        let returned: FieldValue = FieldMap::from([("created".into(), true.into())]).into();
        let token = returned.clone();
        let callbacks = JwtCallbacks::<S>::default().create_jwk_value(move |key, endpoint| {
            assert_eq!(endpoint.auth.config.base_url.as_static(), Some(BASE));
            events.record("createJwk");
            *saved.lock().unwrap() = Some(key);
            let token = token.clone();
            Box::pin(async move { Ok(token) })
        });
        let options = overrides::NativeOptions(
            FieldMap::from([
                ("jwks".into(), jwks.value()),
                ("adapter".into(), callbacks.into_native()),
            ])
            .into(),
        );
        let plugin = JwtPlugin::new();
        let clock_trace = trace.clone();
        let context = context(&plugin, JwtCallbacks::default())
            .await?
            .with_clock(move || {
                clock_trace.record("clock");
                Utc.timestamp_millis_opt(1000).single().unwrap()
            });
        let endpoint = EndpointContext::native(None, None, FieldValue::Null, &context);
        let result = plugin.create_key_native(&options, &endpoint).await;
        let mut expected = vec![
            "get:keyPairConfig",
            "get:disablePrivateKeyEncryption",
            "get:rotationInterval",
        ];
        if !matches!(mode, "zero" | "nan") {
            expected.push("clock");
            expected.push("get:rotationInterval");
        }
        if matches!(mode, "object" | "failure") {
            expected.push("rotation.valueOf");
        }
        if mode == "failure" {
            assert!(
                result
                    .unwrap_err()
                    .into_thrown_value()?
                    .strict_equals(&failure)
            );
            assert!(captured.lock().unwrap().is_none());
        } else {
            expected.push("createJwk");
            assert!(result?.strict_equals(&returned));
            let key = captured.lock().unwrap().clone().unwrap();
            let expiring = !matches!(mode, "zero" | "nan");
            let mut names = vec!["alg", "crv", "publicKey", "privateKey", "createdAt"];
            if expiring {
                names.push("expiresAt");
            }
            assert_eq!(
                key.enumerable_fields()?
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                names
            );
            assert!(key.model_property("createdAt")?.as_date().is_some());
            if expiring {
                let shift = if mode == "negative" {
                    -2000.0
                } else if mode == "string-zero" {
                    0.0
                } else {
                    2000.0
                };
                let expiry = key
                    .model_property("expiresAt")?
                    .as_date()
                    .unwrap()
                    .milliseconds();
                assert_eq!(expiry, 1000.0 + shift);
            }
        }
        assert_eq!(*trace.events.lock().unwrap(), expected);
        assert!(context.database.list_jwk_records().await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn unbound_native_adapter_requires_the_shared_endpoint_context_boundary() -> AuthResult<()> {
    let plugin = JwtPlugin::new();
    let mut context = context(&plugin, JwtCallbacks::default()).await?;
    context
        .extensions
        .insert(Arc::new(EndpointDispatcher::<S>::new(
            Arc::new(Vec::new()),
            EndpointHooks::default(),
            [],
        )));
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let options: FieldValue = FieldMap::from([(
        "adapter".into(),
        FieldMap::from([(
            "getJwks".into(),
            FieldFunction::contextual(move |_, _| {
                let _ = count.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::<FieldValue>::new().into())
            })
            .into(),
        )])
        .into(),
    )])
    .into();
    let error = JwtApi::from_context(&context)?
        .sign_value_with_overrides(claims(), options)
        .await
        .unwrap_err();
    assert_eq!(
        error.message_value()?,
        "Native JWT adapter callbacks require a bound EndpointContext callback".into()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(context.database.list_jwk_records().await?.is_empty());
    Ok(())
}
