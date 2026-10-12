use super::*;

fn function(
    awaited: bool,
    callback: impl Fn(&FieldValue, &[FieldValue]) -> AuthResult<FieldValue> + Send + Sync + 'static,
) -> FieldFunction {
    if awaited {
        FieldFunction::asynchronous_contextual(move |receiver, arguments| {
            let result = callback(&receiver, &arguments);
            async move {
                tokio::task::yield_now().await;
                result
            }
        })
    } else {
        FieldFunction::contextual(callback)
    }
}

async fn registered(adapter: FieldValue) -> AuthResult<(JwtPlugin, AuthContext<S>)> {
    let options = JwtPluginConfig {
        disable_private_key_encryption: true,
        ..Default::default()
    };
    let registered = JwtPlugin::with_config(options.clone()).native_callbacks::<S>(adapter);
    let mut config = crate::plugins::test_helpers::create_test_config();
    config.base_url = BASE.into();
    config.telemetry.enabled = false;
    let config = Arc::new(config);
    let store: Arc<dyn AuthStore<S>> = Arc::new(EphemeralStore::new(config.clone()));
    let context =
        crate::plugins::test_helpers::initialize_test_context(config, store, &[&registered])
            .await?;
    Ok((JwtPlugin::with_config(options), context))
}

#[tokio::test]
async fn public_endpoint_helpers_preserve_native_adapter_receiver_root_and_key_handles()
-> AuthResult<()> {
    for awaited in [false, true] {
        let root_trace = Arc::new(Trace::default());
        let root = ObservedFields::new(FieldMap::new(), root_trace.clone(), None);
        let receiver = ObservedFields::new(FieldMap::new(), Arc::new(Trace::default()), None);
        let keys = Arc::new(Mutex::new(Vec::<FieldValue>::new()));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let read_receiver = Arc::downgrade(&receiver);
        let read_root = root.value();
        let read_keys = keys.clone();
        let read_calls = calls.clone();
        let _ = receiver.fields.set(
            "getJwks",
            function(awaited, move |receiver, arguments| {
                assert!(receiver.strict_equals(&read_receiver.upgrade().unwrap().value()));
                assert_eq!(arguments.len(), 1);
                assert!(arguments.first().unwrap().strict_equals(&read_root));
                read_calls.lock().unwrap().push("get");
                Ok(read_keys.lock().unwrap().clone().into())
            })
            .into(),
        )?;
        let create_receiver = Arc::downgrade(&receiver);
        let create_root = root.value();
        let create_keys = keys.clone();
        let create_calls = calls.clone();
        let _ = receiver.fields.set(
            "createJwk",
            function(awaited, move |receiver, arguments| {
                assert!(receiver.strict_equals(&create_receiver.upgrade().unwrap().value()));
                assert_eq!(arguments.len(), 2);
                assert!(arguments.get(1).unwrap().strict_equals(&create_root));
                let data = arguments.first().unwrap();
                data.set_model_property("id", "native-key".into())?;
                create_calls.lock().unwrap().push("create");
                create_keys.lock().unwrap().push(data.clone());
                Ok(data.clone())
            })
            .into(),
        )?;
        let (plugin, context) = registered(receiver.value()).await?;
        let callbacks = context.extensions.get::<Arc<JwtCallbacks<S>>>().unwrap();
        let first = overrides::NativeOptions::registered(&plugin.config, &context)?
            .0
            .model_property("adapter")?;
        let second = overrides::NativeOptions::registered(&plugin.config, &context)?
            .0
            .model_property("adapter")?;
        assert!(callbacks.to_native().strict_equals(&receiver.value()));
        assert!(first.strict_equals(&second));
        for name in ["getJwks", "createJwk"] {
            assert!(
                first
                    .model_property(name)?
                    .strict_equals(&second.model_property(name)?)
            );
        }
        let endpoint = EndpointContext::native(None, None, "different body".into(), &context)
            .with_native_root(root.value());
        let retained = endpoint.to_owned();
        let retained = retained.as_endpoint();
        assert!(retained.native_root().unwrap().strict_equals(&root.value()));
        let created = plugin
            .create_key_pair_in_endpoint(JwtKeyPairConfig::new(JwtAlgorithm::EdDsa), &retained)
            .await?
            .unwrap();
        assert_eq!(created.id, "native-key");
        let payload = claims();
        payload.set_model_property("sub", "native-owner".into())?;
        let token: String = plugin
            .sign_value_in_endpoint(payload, None, &retained)
            .await?
            .decode()?;
        assert!(
            plugin
                .verify_in_endpoint(&token, None, &retained)
                .await?
                .is_some()
        );
        assert_eq!(*calls.lock().unwrap(), ["create", "get", "get"]);
        assert!(root_trace.events.lock().unwrap().is_empty());
        assert!(context.database.list_jwk_records().await?.is_empty());
        assert_eq!(keys.lock().unwrap().len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn native_adapter_failures_retain_the_original_thrown_value() -> AuthResult<()> {
    for awaited in [false, true] {
        let original: FieldValue = FieldMap::from([("adapter-error".into(), true.into())]).into();
        let thrown = original.clone();
        let failure = function(awaited, move |_, _| {
            Err(AuthError::from_thrown(thrown.clone()))
        });
        let (plugin, context) = registered(
            FieldMap::from([
                ("getJwks".into(), failure.clone().into()),
                ("createJwk".into(), failure.into()),
            ])
            .into(),
        )
        .await?;
        let endpoint = EndpointContext::native(None, None, FieldValue::Null, &context)
            .with_native_root(FieldMap::new().into());
        let get_error = plugin
            .sign_value_in_endpoint(claims(), None, &endpoint)
            .await
            .unwrap_err();
        assert!(get_error.into_thrown_value()?.strict_equals(&original));
        let Err(create_error) = plugin
            .create_key_pair_in_endpoint(JwtKeyPairConfig::new(JwtAlgorithm::EdDsa), &endpoint)
            .await
        else {
            panic!("Native key creation must preserve the callback failure");
        };
        assert!(create_error.into_thrown_value()?.strict_equals(&original));
        assert!(context.database.list_jwk_records().await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn explicit_nullish_and_primitive_roots_reach_native_callbacks() -> AuthResult<()> {
    for root in [
        FieldValue::Undefined,
        FieldValue::Null,
        false.into(),
        7.into(),
        "native".into(),
    ] {
        let expected = root.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let (plugin, context) = registered(
            FieldMap::from([(
                "createJwk".into(),
                FieldFunction::contextual(move |_, arguments| {
                    assert_eq!(arguments.len(), 2);
                    assert!(arguments.get(1).unwrap().strict_equals(&expected));
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(FieldValue::Null)
                })
                .into(),
            )])
            .into(),
        )
        .await?;
        let absent = EndpointContext::native(None, None, root.clone(), &context);
        let Err(error) = plugin
            .create_key_pair_in_endpoint(JwtKeyPairConfig::new(JwtAlgorithm::EdDsa), &absent)
            .await
        else {
            panic!("Native key creation must reject an absent endpoint root");
        };
        assert_eq!(
            error.message_value()?,
            "Native JWT adapter callbacks require an explicit native endpoint root".into()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let explicit = absent.with_native_root(root);
        assert!(
            plugin
                .create_key_pair_in_endpoint(JwtKeyPairConfig::new(JwtAlgorithm::EdDsa), &explicit)
                .await?
                .is_none()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(context.database.list_jwk_records().await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn registered_groups_retain_falsy_defaults_and_typed_callback_identity() -> AuthResult<()> {
    for group in [
        FieldValue::Undefined,
        FieldValue::Null,
        false.into(),
        0.into(),
        "".into(),
    ] {
        let (plugin, context) = registered(group.clone()).await?;
        let options = overrides::NativeOptions::registered(&plugin.config, &context)?;
        assert!(options.0.has_property("adapter")?);
        assert!(options.0.model_property("adapter")?.strict_equals(&group));
        let endpoint = EndpointContext::native(None, None, FieldValue::Null, &context);
        assert!(
            plugin
                .create_key_pair_in_endpoint(JwtKeyPairConfig::new(JwtAlgorithm::EdDsa), &endpoint)
                .await?
                .is_some()
        );
        assert_eq!(context.database.list_jwk_records().await?.len(), 1);
    }
    let plugin = JwtPlugin::new();
    let pointer = Arc::new(AtomicUsize::new(0));
    let expected_pointer = pointer.clone();
    let root: FieldValue = FieldMap::new().into();
    let expected_root = root.clone();
    let context = context(
        &plugin,
        JwtCallbacks::default().get_jwks_native(move |endpoint| {
            assert_eq!(
                std::ptr::from_ref(endpoint) as usize,
                expected_pointer.load(Ordering::SeqCst)
            );
            assert!(
                endpoint
                    .native_root()
                    .unwrap()
                    .strict_equals(&expected_root)
            );
            Box::pin(async { Ok(Vec::<FieldValue>::new().into()) })
        }),
    )
    .await?;
    let first = overrides::NativeOptions::registered(&plugin.config, &context)?
        .0
        .model_property("adapter")?;
    let second = overrides::NativeOptions::registered(&plugin.config, &context)?
        .0
        .model_property("adapter")?;
    assert!(first.strict_equals(&second));
    assert!(
        first
            .model_property("getJwks")?
            .strict_equals(&second.model_property("getJwks")?)
    );
    let endpoint =
        EndpointContext::native(None, None, FieldValue::Null, &context).with_native_root(root);
    pointer.store(std::ptr::from_ref(&endpoint) as usize, Ordering::SeqCst);
    let options = overrides::NativeOptions::registered(&plugin.config, &context)?;
    assert!(
        adapter::Keyring::new(adapter::store(&endpoint), &options, &endpoint)
            .latest(None)
            .await?
            .is_undefined()
    );
    Ok(())
}
