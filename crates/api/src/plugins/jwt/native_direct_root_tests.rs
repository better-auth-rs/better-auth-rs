use super::*;
use better_auth_core::{CreateUser, NativeRequest, session::NativeSessionData, store::transaction};

#[tokio::test]
async fn direct_facade_preserves_native_roots_and_keeps_standalone_calls_explicit() -> AuthResult<()>
{
    for root in [
        FieldValue::Undefined,
        FieldValue::Null,
        false.into(),
        FieldMap::from([("native".into(), true.into())]).into(),
    ] {
        let expected = root.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let (_, context) = registered(
            FieldMap::from([(
                "createJwk".into(),
                FieldFunction::contextual(move |_, arguments| {
                    assert_eq!(arguments.len(), 2);
                    assert!(arguments[1].strict_equals(&expected));
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(FieldValue::Null)
                })
                .into(),
            )])
            .into(),
        )
        .await?;
        let request = AuthRequest::new(HttpMethod::Post, "/parent");
        let endpoint = EndpointContext::native(
            Some(&request),
            Some(&request),
            "parent-body".into(),
            &context,
        )
        .with_native_root(root);
        let source = AuthRequest::new(HttpMethod::Post, "/child-source");
        let parameters = JwtKeyPairConfig::new(JwtAlgorithm::EdDsa);
        assert!(
            endpoint
                .jwt()?
                .with_request(NativeRequest {
                    request: Some(&source),
                    headers: source.endpoint_headers(),
                })
                .create_key_pair(parameters)
                .await?
                .is_none()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let Err(error) = JwtApi::from_context(&context)?
            .create_key_pair(parameters)
            .await
        else {
            panic!("Standalone provisioning must not invent a native endpoint root");
        };
        assert_eq!(
            error.message_value()?,
            "Native JWT adapter callbacks require an explicit native endpoint root".into()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(context.database.list_jwk_records().await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn direct_facade_retains_the_borrowed_endpoint_and_transaction_across_nested_dispatch()
-> AuthResult<()> {
    for rollback in [false, true] {
        let endpoint_address = Arc::new(AtomicUsize::new(0));
        let transaction_address = Arc::new(AtomicUsize::new(0));
        let root: FieldValue = FieldMap::from([("root".into(), true.into())]).into();
        let body: FieldValue = FieldMap::from([("body".into(), true.into())]).into();
        let session: FieldValue = FieldMap::from([("session".into(), true.into())]).into();
        let events = Arc::new(Mutex::new(Vec::new()));
        let create_endpoint_address = endpoint_address.clone();
        let create_transaction_address = transaction_address.clone();
        let create_root = root.clone();
        let create_body = body.clone();
        let create_session = session.clone();
        let create_events = events.clone();
        let read_endpoint_address = endpoint_address.clone();
        let read_transaction_address = transaction_address.clone();
        let read_root = root.clone();
        let read_events = events.clone();
        let callbacks = JwtCallbacks::<S>::default()
            .create_jwk(move |key, endpoint| {
                let root = create_root.clone();
                let body = create_body.clone();
                let session = create_session.clone();
                let endpoint_address = create_endpoint_address.clone();
                let transaction_address = create_transaction_address.clone();
                let events = create_events.clone();
                Box::pin(async move {
                    assert_eq!(
                        std::ptr::from_ref(endpoint) as usize,
                        endpoint_address.load(Ordering::SeqCst)
                    );
                    assert!(endpoint.native_root().unwrap().strict_equals(&root));
                    assert!(endpoint.body.strict_equals(&body));
                    assert!(
                        endpoint
                            .session
                            .as_ref()
                            .unwrap()
                            .field_value()
                            .strict_equals(&session)
                    );
                    assert_eq!(endpoint.path, Some("/parent"));
                    assert_eq!(
                        endpoint.params.get("id").map(String::as_str),
                        Some("parent")
                    );
                    assert_eq!(endpoint.request.unwrap().path(), "/original");
                    assert_eq!(endpoint.response.unwrap().status, 202);
                    let tx = endpoint.transaction.unwrap();
                    assert_eq!(
                        std::ptr::from_ref(tx) as *const () as usize,
                        transaction_address.load(Ordering::SeqCst)
                    );
                    assert!(
                        tx.get_user_by_email("direct-helper@test.example")
                            .await?
                            .is_some()
                    );
                    events.lock().unwrap().push("create");
                    tx.create_jwk(key).await.map(Some)
                })
            })
            .get_jwks(move |endpoint| {
                let endpoint_address = read_endpoint_address.clone();
                let transaction_address = read_transaction_address.clone();
                let root = read_root.clone();
                let events = read_events.clone();
                Box::pin(async move {
                    assert_ne!(
                        std::ptr::from_ref(endpoint) as usize,
                        endpoint_address.load(Ordering::SeqCst)
                    );
                    assert!(
                        endpoint
                            .native_root()
                            .is_none_or(|value| !value.strict_equals(&root))
                    );
                    assert!(endpoint.request.is_none());
                    assert!(endpoint.session.is_none());
                    assert!(endpoint.response.is_none());
                    assert_eq!(endpoint.path, Some("virtual:"));
                    let tx = endpoint.transaction.unwrap();
                    assert_eq!(
                        std::ptr::from_ref(tx) as *const () as usize,
                        transaction_address.load(Ordering::SeqCst)
                    );
                    let phase = if endpoint.body.has_property("payload")? {
                        "sign"
                    } else {
                        assert!(endpoint.body.has_property("token")?);
                        "verify"
                    };
                    events.lock().unwrap().push(phase);
                    tx.list_jwks().await.map(Some)
                })
            });
        let plugin = JwtPlugin::new().disable_private_key_encryption(true);
        let context = context(&plugin, callbacks).await?;
        let in_transaction = context.clone();
        let result: AuthResult<()> = transaction(context.database.as_ref(), move |tx| {
            Box::pin(async move {
                let _ = tx
                    .create_user(
                        CreateUser::new()
                            .with_email("direct-helper@test.example")
                            .with_name("Direct helper"),
                    )
                    .await?;
                let input = AuthRequest::new(HttpMethod::Post, "/parent");
                let original = AuthRequest::new(HttpMethod::Post, "/original");
                let response = AuthResponse::new(202);
                let mut endpoint =
                    EndpointContext::native(Some(&input), Some(&original), body, &in_transaction)
                        .with_native_root(root);
                let _ = endpoint.params.insert("id".into(), "parent".into());
                endpoint.session = Some(NativeSessionData::from_native(session, false));
                endpoint.response = Some(&response);
                endpoint.transaction = Some(tx);
                endpoint_address.store(std::ptr::from_ref(&endpoint) as usize, Ordering::SeqCst);
                transaction_address.store(
                    std::ptr::from_ref(tx) as *const () as usize,
                    Ordering::SeqCst,
                );
                let api = JwtApi::from_endpoint(&endpoint)?;
                let key = api
                    .create_key_pair(JwtKeyPairConfig::new(JwtAlgorithm::EdDsa))
                    .await?
                    .unwrap();
                let payload = claims();
                payload.set_model_property("sub", "direct-helper".into())?;
                let token = api.sign_value(payload).await?.decode::<String>()?;
                assert!(api.verify(&token, None).await?.is_some());
                assert_eq!(tx.list_jwks().await?.len(), 1);
                assert!(tx.get_jwk_record(&key.id).await?.is_some());
                if rollback {
                    Err(AuthError::bad_request("Roll back direct helper"))
                } else {
                    Ok(())
                }
            })
        })
        .await;
        assert_eq!(result.is_err(), rollback);
        assert_eq!(*events.lock().unwrap(), ["create", "sign", "verify"]);
        assert_eq!(
            context.database.list_jwk_records().await?.len(),
            usize::from(!rollback)
        );
        assert_eq!(
            context
                .database
                .get_user_by_email("direct-helper@test.example")
                .await?
                .is_some(),
            !rollback
        );
    }
    Ok(())
}
