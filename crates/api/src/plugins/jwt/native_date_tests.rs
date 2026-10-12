#![expect(
    clippy::indexing_slicing,
    reason = "Fixture indexing must fail when an expected record or property is missing."
)]

use super::*;
use better_auth_core::{FieldDate, FieldFunction};
use std::sync::Mutex;

type Events = Arc<Mutex<Vec<(&'static str, &'static str)>>>;

fn returned_number(
    label: &'static str,
    number: f64,
    failure: Option<FieldValue>,
    events: &Events,
) -> FieldValue {
    let events = events.clone();
    FieldMap::from([
        ("label".into(), label.into()),
        (
            "valueOf".into(),
            FieldFunction::contextual(move |receiver, arguments| {
                assert_eq!(receiver.model_property("label")?, label.into());
                assert!(arguments.is_empty());
                events.lock().unwrap().push((label, "valueOf"));
                if let Some(failure) = &failure {
                    return Err(AuthError::from_thrown(failure.clone()));
                }
                Ok(number.into())
            })
            .into(),
        ),
    ])
    .into()
}

fn time_method(label: &'static str, result: FieldValue, events: &Events) -> FieldValue {
    let events = events.clone();
    FieldMap::from([
        ("label".into(), label.into()),
        (
            "getTime".into(),
            FieldFunction::contextual(move |receiver, arguments| {
                assert_eq!(receiver.model_property("label")?, label.into());
                assert!(arguments.is_empty());
                events.lock().unwrap().push((label, "getTime"));
                Ok(result.clone())
            })
            .into(),
        ),
    ])
    .into()
}

fn assert_subtraction(events: &Events, fails: bool) {
    let events = events.lock().unwrap();
    let expected: &[&str] = if fails {
        &["getTime", "getTime", "valueOf"]
    } else {
        &["getTime", "getTime", "valueOf", "valueOf"]
    };
    assert_eq!(
        events.iter().map(|(_, method)| *method).collect::<Vec<_>>(),
        expected
    );
    let mut events = events.iter();
    let first = events.next().unwrap().0;
    let second = events.next().unwrap().0;
    assert_ne!(first, second);
    assert_eq!(events.next().unwrap().0, first);
    if !fails {
        assert_eq!(events.next().unwrap().0, second);
    }
}

#[tokio::test]
async fn signing_gets_both_native_times_before_numeric_subtraction() -> AuthResult<()> {
    for algorithm in [None, Some(JwtAlgorithm::EdDsa)] {
        let events = Events::default();
        let mut older = key(JwtAlgorithm::EdDsa)?;
        older.id = "older".to_owned().into();
        older.created_at = SchemaValue::from_field(time_method(
            "older",
            returned_number("older", 1.0, None, &events),
            &events,
        ));
        let mut newer = older.clone();
        newer.id = "newer".to_owned().into();
        newer.created_at = SchemaValue::from_field(time_method(
            "newer",
            returned_number("newer", 2.0, None, &events),
            &events,
        ));
        let plugin = JwtPlugin::new().disable_private_key_encryption(true);
        let (ctx, reads) = context(&plugin, vec![older, newer]).await?;
        let token = plugin
            .sign_with_options(
                serde_json::from_value(json!({"sub":"owner"}))?,
                &JwtSigningOptions {
                    algorithm,
                    ..Default::default()
                },
                &ctx,
            )
            .await?;
        assert_eq!(tests::header(&token), json!({"alg":"EdDSA", "kid":"newer"}));
        assert_subtraction(&events, false);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            plugin.verify(&token, None, &ctx).await?.unwrap()["sub"],
            "owner"
        );
    }
    Ok(())
}

#[test]
fn selection_defers_failed_coercion_until_both_methods_return() -> AuthResult<()> {
    for algorithm in [None, Some("EdDSA")] {
        let events = Events::default();
        let failure = AuthError::type_error("JWK time conversion failed").into_thrown_value()?;
        let mut older = key(JwtAlgorithm::EdDsa)?;
        older.created_at = SchemaValue::from_field(time_method(
            "older",
            returned_number("older", 1.0, Some(failure.clone()), &events),
            &events,
        ));
        let mut newer = older.clone();
        newer.created_at = SchemaValue::from_field(time_method(
            "newer",
            returned_number("newer", 2.0, Some(failure.clone()), &events),
            &events,
        ));
        let rows = [older, newer]
            .iter()
            .map(|key| better_auth_core::AuthRecordFields::field_values(key).map(FieldValue::from))
            .collect::<AuthResult<Vec<_>>>()?;
        let error = keys::latest(
            rows.into(),
            algorithm.map(FieldValue::from),
            "EdDSA".into(),
            (Utc::now().timestamp_millis() as f64).into(),
        )
        .err()
        .expect("Native time conversion must fail");
        assert_eq!(error.message_value()?, "JWK time conversion failed".into());
        assert!(error.into_thrown_value()?.strict_equals(&failure));
        assert_subtraction(&events, true);
    }
    Ok(())
}

#[tokio::test]
async fn discovery_preserves_get_time_string_addition_and_shadowed_date_methods() -> AuthResult<()>
{
    let events = Events::default();
    let mut string = key(JwtAlgorithm::EdDsa)?;
    string.id = "string".to_owned().into();
    string.expires_at = SchemaValue::from_field(time_method("string", "2000".into(), &events));
    let mut numeric = string.clone();
    numeric.id = "numeric".to_owned().into();
    numeric.expires_at = SchemaValue::from_field(time_method("numeric", 2000.0.into(), &events));
    let plugin = JwtPlugin::new();
    let (ctx, reads) = context(&plugin, vec![string.clone(), numeric]).await?;
    let response = plugin
        .jwks(&EndpointContext::native(None, None, FieldValue::Null, &ctx))
        .await?;
    let mut expected = FieldMap::from([
        ("alg".into(), "EdDSA".into()),
        ("crv".into(), FieldValue::Undefined),
    ]);
    expected.extend(keys::parse_json(&string.public_key.field_value())?.enumerable_fields()?);
    let _ = expected.insert("kid".into(), "string".into());
    assert_eq!(
        response.body.field_value()?,
        FieldMap::from([("keys".into(), vec![FieldValue::from(expected)].into())]).into()
    );
    assert_eq!(
        *events.lock().unwrap(),
        [("string", "getTime"), ("numeric", "getTime")]
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);

    let expiry: FieldValue = FieldDate::from_milliseconds(4_102_444_800_000.0).into();
    expiry.set_model_property("getTime", false.into())?;
    string.expires_at = SchemaValue::from_field(expiry);
    let (ctx, reads) = context(&plugin, vec![string]).await?;
    let error = plugin
        .jwks(&EndpointContext::native(None, None, FieldValue::Null, &ctx))
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuthError::TypeError(message) if message == "key.expiresAt.getTime is not a function")
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn discovery_finishes_expiry_filter_before_public_key_conversion() -> AuthResult<()> {
    for fails in [false, true] {
        let events = Events::default();
        let conversion_error =
            AuthError::type_error("public key conversion failed").into_thrown_value()?;
        let expiry_error = AuthError::type_error("expiry method failed").into_thrown_value()?;
        let observed = events.clone();
        let public_key: FieldValue = FieldMap::from([
            ("source".into(), "{\"marker\":\"before\"}".into()),
            (
                "toString".into(),
                FieldFunction::contextual(move |receiver, arguments| {
                    assert!(arguments.is_empty());
                    observed.lock().unwrap().push(("first", "toString"));
                    if fails {
                        return Err(AuthError::from_thrown(conversion_error.clone()));
                    }
                    receiver.model_property("source")
                })
                .into(),
            ),
        ])
        .into();
        let mut first = key(JwtAlgorithm::EdDsa)?;
        first.id = "first".to_owned().into();
        first.public_key = SchemaValue::from_field(public_key.clone());
        let mut second = first.clone();
        second.id = "second".to_owned().into();
        second.public_key = "{\"marker\":\"second\"}".to_owned().into();
        let observed = events.clone();
        let failure = expiry_error.clone();
        let source = public_key.clone();
        second.expires_at = SchemaValue::from_field(
            FieldMap::from([
                ("label".into(), "second".into()),
                (
                    "getTime".into(),
                    FieldFunction::contextual(move |receiver, arguments| {
                        assert_eq!(receiver.model_property("label")?, "second".into());
                        assert!(arguments.is_empty());
                        observed.lock().unwrap().push(("second", "getTime"));
                        if fails {
                            return Err(AuthError::from_thrown(failure.clone()));
                        }
                        source.set_model_property("source", "{\"marker\":\"after\"}".into())?;
                        Ok(4_102_444_800_000.0.into())
                    })
                    .into(),
                ),
            ])
            .into(),
        );
        let plugin = JwtPlugin::new();
        let (ctx, reads) = context(&plugin, vec![first, second]).await?;
        let result = plugin
            .jwks(&EndpointContext::native(None, None, FieldValue::Null, &ctx))
            .await;
        if fails {
            assert!(
                result
                    .unwrap_err()
                    .into_thrown_value()?
                    .strict_equals(&expiry_error)
            );
            assert_eq!(*events.lock().unwrap(), [("second", "getTime")]);
        } else {
            let expected = ["first", "second"].map(|id| {
                FieldValue::from(FieldMap::from([
                    ("alg".into(), "EdDSA".into()),
                    ("crv".into(), FieldValue::Undefined),
                    (
                        "marker".into(),
                        if id == "first" { "after" } else { "second" }.into(),
                    ),
                    ("kid".into(), id.into()),
                ]))
            });
            assert_eq!(
                result?.body.field_value()?,
                FieldMap::from([("keys".into(), expected.to_vec().into())]).into(),
            );
            assert_eq!(
                *events.lock().unwrap(),
                [("second", "getTime"), ("first", "toString")],
            );
        }
        assert_eq!(
            public_key.model_property("source")?,
            if fails {
                "{\"marker\":\"before\"}"
            } else {
                "{\"marker\":\"after\"}"
            }
            .into(),
        );
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert!(ctx.database.list_jwks().await?.is_empty());
    }
    Ok(())
}
