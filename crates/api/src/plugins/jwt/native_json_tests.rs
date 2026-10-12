#![expect(
    clippy::indexing_slicing,
    reason = "Fixture indexing must fail when an expected record or property is missing."
)]

use super::*;

#[tokio::test]
async fn native_claims_reach_jose_setters_before_json_conversion() -> AuthResult<()> {
    let plugin = JwtPlugin::new().disable_private_key_encryption(true);
    let (ctx, reads) = context(&plugin, vec![key(JwtAlgorithm::EdDsa)?]).await?;
    let unpaired = better_auth_core::Utf16String::from_units(vec![0xd800]);
    let user = FieldMap::from([
        ("id".into(), "owner".into()),
        (
            "iat".into(),
            better_auth_core::FieldDate::from_milliseconds(1_700_000_000_999.0).into(),
        ),
        (
            "exp".into(),
            better_auth_core::FieldDate::from_milliseconds(1_900_000_000_999.0).into(),
        ),
        (
            "nbf".into(),
            better_auth_core::FieldDate::from_milliseconds(-1.0).into(),
        ),
        ("jti".into(), 0.0.into()),
        ("nativeString".into(), unpaired.clone().into()),
    ]);
    let session =
        better_auth_core::session::NativeSessionData::new(Default::default(), user.into());
    let token = plugin
        .sign_session(
            Some(session),
            &EndpointContext::native(None, None, FieldValue::Null, &ctx),
        )
        .await?
        .decode::<String>()?;
    let bytes = URL_SAFE_NO_PAD
        .decode(token.split('.').nth(1).unwrap())
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let source =
        String::from_utf8(bytes).map_err(|error| AuthError::internal(error.to_string()))?;
    let claims = keys::parse_json(&source.into())?;
    assert_eq!(claims.model_property("iat")?, 1_700_000_000.0.into());
    assert_eq!(claims.model_property("exp")?, 1_900_000_000.0.into());
    assert_eq!(claims.model_property("nbf")?, (-1.0).into());
    assert_eq!(claims.model_property("jti")?, 0.0.into());
    assert_eq!(claims.model_property("sub")?, "owner".into());
    assert_eq!(claims.model_property("nativeString")?, unpaired.into());
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn native_signing_resolves_keys_before_clone_errors_without_calling_to_json() -> AuthResult<()>
{
    for cookie in [false, true] {
        let plugin = JwtPlugin::new()
            .disable_private_key_encryption(true)
            .session_cookie_cache(cookie);
        let (ctx, reads) = context(&plugin, vec![key(JwtAlgorithm::EdDsa)?]).await?;
        let calls = Arc::new(AtomicUsize::new(0));
        let native = FieldMap::from([(
            "toJSON".into(),
            better_auth_core::FieldFunction::contextual({
                let calls = calls.clone();
                move |_, _| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok("converted".into())
                }
            })
            .into(),
        )]);
        let session = better_auth_core::session::NativeSessionData::new(
            Default::default(),
            FieldMap::from([
                ("id".into(), "owner".into()),
                ("native".into(), native.into()),
            ])
            .into(),
        );
        let request = AuthRequest::new(HttpMethod::Get, "/token");
        let result = if cookie {
            let signer = ctx
                .extensions
                .get::<Arc<dyn better_auth_core::session::SessionCookieSigner<StatelessSchema>>>()
                .unwrap();
            signer
                .sign(
                    session.field_value().enumerable_fields()?,
                    60.0,
                    better_auth_core::session::SessionCookieContext {
                        request: &request,
                        config: &ctx.config,
                        transaction: None,
                    },
                )
                .await
        } else {
            plugin
                .sign_session(
                    Some(session),
                    &EndpointContext::native(None, None, FieldValue::Null, &ctx),
                )
                .await
                .and_then(|token| token.decode::<String>())
        };
        assert!(matches!(result, Err(AuthError::DataClone)), "{cookie}");
        assert_eq!(reads.load(Ordering::SeqCst), 1, "{cookie}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "{cookie}");
    }
    Ok(())
}

#[tokio::test]
async fn cookie_subject_checks_native_type_and_keeps_unset_sid_and_untouched_claims()
-> AuthResult<()> {
    use better_auth_core::session::{SessionCookieContext, SessionCookieSigner};
    let plugin = JwtPlugin::new()
        .disable_private_key_encryption(true)
        .session_cookie_cache(true);
    let (ctx, reads) = context(&plugin, vec![key(JwtAlgorithm::EdDsa)?]).await?;
    let signer = ctx
        .extensions
        .get::<Arc<dyn SessionCookieSigner<StatelessSchema>>>()
        .unwrap();
    let request = AuthRequest::new(HttpMethod::Get, "/get-session");
    let cookie_context = || SessionCookieContext {
        request: &request,
        config: &ctx.config,
        transaction: None,
    };
    let mut payload = FieldMap::from([
        ("session".into(), FieldMap::new().into()),
        (
            "user".into(),
            FieldMap::from([(
                "id".into(),
                better_auth_core::FieldDate::from_milliseconds(0.0).into(),
            )])
            .into(),
        ),
        ("nbf".into(), "untouched".into()),
        ("jti".into(), 17.0.into()),
    ]);
    assert!(matches!(
        signer.sign(payload.clone(), 60.0, cookie_context()).await,
        Err(AuthError::TypeError(message)) if message == "\"sub\" claim must be a string"
    ));
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    let _ = payload.insert(
        "user".into(),
        FieldMap::from([("id".into(), "owner".into())]).into(),
    );
    let token = signer.sign(payload, 60.0, cookie_context()).await?;
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .map_err(|error| AuthError::internal(error.to_string()))?,
    )?;
    assert!(claims.get("sid").is_none());
    assert_eq!(claims["sub"], "owner");
    assert_eq!(claims["nbf"], "untouched");
    assert_eq!(claims["jti"], 17);
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn native_numeric_dates_fail_at_setter_or_final_encoding_after_key_resolution()
-> AuthResult<()> {
    for (name, value, expected) in [
        (
            "exp",
            FieldValue::from(f64::INFINITY),
            "Invalid setExpirationTime input",
        ),
        (
            "iat",
            FieldValue::from(f64::NAN),
            "\"iat\" claim must be a finite number",
        ),
        (
            "nbf",
            better_auth_core::FieldDate::invalid().into(),
            "Invalid setNotBefore input",
        ),
    ] {
        let plugin = JwtPlugin::new().disable_private_key_encryption(true);
        let (ctx, reads) = context(&plugin, vec![key(JwtAlgorithm::EdDsa)?]).await?;
        let mut user = FieldMap::from([
            ("id".into(), "owner".into()),
            ("exp".into(), 1_900_000_000.0.into()),
        ]);
        let _ = user.insert(name.into(), value);
        let result = plugin
            .sign_session(
                Some(better_auth_core::session::NativeSessionData::new(
                    Default::default(),
                    user.into(),
                )),
                &EndpointContext::native(None, None, FieldValue::Null, &ctx),
            )
            .await;
        assert!(
            matches!(result, Err(AuthError::TypeError(message)) if message == expected),
            "{name}"
        );
        assert_eq!(reads.load(Ordering::SeqCst), 1, "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn custom_sign_json_callback_projects_once_without_entering_local_jose_clone()
-> AuthResult<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let native = FieldMap::from([(
        "toJSON".into(),
        better_auth_core::FieldFunction::contextual({
            let calls = calls.clone();
            move |_, arguments| {
                assert_eq!(arguments, &[FieldValue::from("native")]);
                calls.fetch_add(1, Ordering::SeqCst);
                Ok("converted".into())
            }
        })
        .into(),
    )]);
    let plugin = JwtPlugin::new()
        .remote_url("http://http-json.test/jwks".into())
        .algorithm(JwtAlgorithm::EdDsa)
        .custom_sign(Arc::new(|payload, _| {
            Box::pin(async move {
                assert_eq!(payload["native"], "converted");
                assert_eq!(payload["sub"], "owner");
                assert!(payload.contains_key("exp"));
                Ok("custom-signature".into())
            })
        }));
    let (ctx, reads) = context(&plugin, Vec::new()).await?;
    let token = plugin
        .sign_session(
            Some(better_auth_core::session::NativeSessionData::new(
                Default::default(),
                FieldMap::from([
                    ("id".into(), "owner".into()),
                    ("native".into(), native.into()),
                ])
                .into(),
            )),
            &EndpointContext::native(None, None, FieldValue::Null, &ctx),
        )
        .await?;
    assert_eq!(token, FieldValue::from("custom-signature"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn invalid_claims_precede_native_key_id_json_without_losing_receiver() -> AuthResult<()> {
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let native_id: FieldValue = FieldMap::from([(
        "toJSON".into(),
        better_auth_core::FieldFunction::contextual({
            let calls = calls.clone();
            move |receiver, arguments| {
                calls
                    .lock()
                    .unwrap()
                    .push((receiver.clone(), arguments.to_vec()));
                Ok("encoded-key".into())
            }
        })
        .into(),
    )])
    .into();
    let mut stored = key(JwtAlgorithm::EdDsa)?;
    stored.id = SchemaValue::from_field(native_id.clone());
    let plugin = JwtPlugin::new().disable_private_key_encryption(true);
    let (ctx, reads) = context(&plugin, vec![stored]).await?;
    for issued in [f64::NAN, 1_700_000_000.0] {
        let result = plugin
            .sign_session(
                Some(better_auth_core::session::NativeSessionData::new(
                    Default::default(),
                    FieldMap::from([
                        ("id".into(), "owner".into()),
                        ("iat".into(), issued.into()),
                        ("exp".into(), 1_900_000_000.0.into()),
                    ])
                    .into(),
                )),
                &EndpointContext::native(None, None, FieldValue::Null, &ctx),
            )
            .await;
        if issued.is_nan() {
            assert!(matches!(result, Err(AuthError::TypeError(message))
                if message == "\"iat\" claim must be a finite number"));
            assert!(calls.lock().unwrap().is_empty());
            assert_eq!(reads.load(Ordering::SeqCst), 1);
        } else {
            let token = result?.decode::<String>()?;
            assert_eq!(
                tests::header(&token),
                json!({"alg":"EdDSA", "kid":"encoded-key"})
            );
            let claims: Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(token.split('.').nth(1).unwrap())
                    .map_err(|error| AuthError::internal(error.to_string()))?,
            )?;
            assert_eq!(
                claims,
                json!({
                    "iat": 1_700_000_000, "id":"owner", "exp":1_900_000_000,
                    "sub":"owner", "iss":ctx.base_url(), "aud":ctx.base_url()
                })
            );
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert!(calls[0].0.strict_equals(&native_id));
            assert_eq!(calls[0].1, [FieldValue::from("kid")]);
            assert_eq!(reads.load(Ordering::SeqCst), 2);
        }
    }
    Ok(())
}
