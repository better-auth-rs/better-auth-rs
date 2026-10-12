#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "The paired native JWT contract asserts exact object identity, callback order, and failure propagation."
)]

use super::native_test_support::{ObservedFields, Trace};
use super::*;
use better_auth_core::{FieldFunction, session::NativeSessionData};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const BASE: &str = "http://jwt-native-callbacks.test";

#[tokio::test]
async fn callbacks_retain_one_root_and_sample_both_clock_boundaries() -> AuthResult<()> {
    let trace = Arc::new(Trace::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let clock_calls = calls.clone();
    let clock_trace = trace.clone();
    let mut context = crate::plugins::test_helpers::create_test_context()
        .await
        .with_clock(move || {
            clock_trace.record("clock");
            Utc.timestamp_millis_opt(
                *[1_700_000_000_123, 1_700_000_005_999]
                    .get(clock_calls.fetch_add(1, Ordering::SeqCst))
                    .unwrap(),
            )
            .single()
            .unwrap()
        });
    let mut config = (*context.config).clone();
    config.base_url = BASE.into();
    context.config = Arc::new(config);
    let old_user: FieldValue = FieldMap::from([("id".into(), "old".into())]).into();
    let child: FieldValue = FieldMap::from([("retained".into(), true.into())]).into();
    let user: FieldValue = FieldMap::from([
        ("id".into(), "replacement".into()),
        ("child".into(), child.clone()),
        ("iat".into(), FieldValue::Undefined),
    ])
    .into();
    let root: FieldValue = FieldMap::from([
        (
            "session".into(),
            FieldMap::from([("token".into(), "before".into())]).into(),
        ),
        ("user".into(), old_user.clone()),
        ("extra".into(), child.clone()),
    ])
    .into();
    let returned: FieldValue = FieldMap::from([("signed".into(), true.into())]).into();
    let payload_root = root.clone();
    let payload_child = child.clone();
    let replacement = user.clone();
    let payload_trace = trace.clone();
    let subject_root = root.clone();
    let subject_user = user.clone();
    let subject_trace = trace.clone();
    let signed = returned.clone();
    let sign_trace = trace.clone();
    let plugin = JwtPlugin::new()
        .define_payload_native(Arc::new(move |data| {
            let root = payload_root.clone();
            let child = payload_child.clone();
            let user = replacement.clone();
            let trace = payload_trace.clone();
            Box::pin(async move {
                trace.record("payload");
                assert!(data.strict_equals(&root));
                assert!(data.model_property("extra")?.strict_equals(&child));
                data.model_property("session")?
                    .as_object()
                    .unwrap()
                    .set("token", "after".into())?;
                data.as_object().unwrap().set("user", user.clone())?;
                Ok(user)
            })
        }))
        .get_subject_native(Arc::new(move |data| {
            let root = subject_root.clone();
            let user = subject_user.clone();
            let trace = subject_trace.clone();
            Box::pin(async move {
                trace.record("subject");
                assert!(data.strict_equals(&root));
                assert!(data.model_property("user")?.strict_equals(&user));
                user.as_object().unwrap().set("id", "final".into())?;
                Ok(FieldValue::Null)
            })
        }))
        .custom_sign_native(Arc::new(move |payload, header, selection| {
            let child = child.clone();
            let returned = signed.clone();
            let trace = sign_trace.clone();
            Box::pin(async move {
                trace.record("sign");
                assert_eq!(
                    payload.enumerable_fields()?,
                    FieldMap::from([
                        ("id".into(), "replacement".into()),
                        ("child".into(), child.clone()),
                        ("iat".into(), FieldValue::Undefined),
                        ("sub".into(), "final".into()),
                        ("exp".into(), 1_700_000_905_i64.into()),
                        ("nbf".into(), FieldValue::Undefined),
                        ("iss".into(), BASE.into()),
                        ("aud".into(), BASE.into()),
                    ])
                );
                assert!(payload.model_property("child")?.strict_equals(&child));
                assert_eq!(
                    payload.as_object().unwrap().own_keys()?,
                    ["iat", "id", "child", "sub", "exp", "nbf", "iss", "aud"]
                );
                assert!(header.is_undefined());
                assert_eq!(
                    selection.as_object().unwrap().own_keys()?,
                    ["signingKeyId", "signingAlgorithm"]
                );
                assert_eq!(
                    selection.enumerable_fields()?,
                    FieldMap::from([
                        ("signingKeyId".into(), FieldValue::Undefined),
                        ("signingAlgorithm".into(), FieldValue::Undefined),
                    ])
                );
                Ok(returned)
            })
        }));
    let data = NativeSessionData::from_native(root.clone(), true);
    let mut endpoint = EndpointContext::new(None, FieldValue::Null, &context);
    endpoint.session = Some(data.clone());
    let token = plugin.sign_session(Some(data), &endpoint).await?;
    assert!(token.strict_equals(&returned));
    assert_eq!(
        root.model_property("session")?.model_property("token")?,
        "after".into()
    );
    assert!(root.model_property("user")?.strict_equals(&user));
    assert_eq!(old_user.model_property("id")?, "old".into());
    assert_eq!(
        *trace.events.lock().unwrap(),
        ["payload", "clock", "subject", "clock", "sign"]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn subject_only_falls_back_for_nullish_values() -> AuthResult<()> {
    let context = crate::plugins::test_helpers::create_test_context().await;
    for subject in [
        FieldValue::Undefined,
        FieldValue::Null,
        false.into(),
        0.into(),
        "".into(),
    ] {
        let expected = if subject.is_null() || subject.is_undefined() {
            "owner".into()
        } else {
            subject.clone()
        };
        let root: FieldValue = FieldMap::from([
            ("session".into(), FieldMap::new().into()),
            (
                "user".into(),
                FieldMap::from([("id".into(), "owner".into())]).into(),
            ),
        ])
        .into();
        let subject_root = root.clone();
        let plugin = JwtPlugin::new()
            .get_subject_native(Arc::new(move |data| {
                assert!(data.strict_equals(&subject_root));
                let subject = subject.clone();
                Box::pin(async move { Ok(subject) })
            }))
            .custom_sign_native(Arc::new(|payload, _, _| {
                Box::pin(async move { payload.model_property("sub") })
            }));
        let endpoint = EndpointContext::new(None, FieldValue::Null, &context);
        assert_eq!(
            plugin
                .sign_session(Some(NativeSessionData::from_native(root, true)), &endpoint)
                .await?,
            expected
        );
    }
    Ok(())
}

#[tokio::test]
async fn callback_failures_keep_identity_order_and_completed_mutations() -> AuthResult<()> {
    for phase in ["payload", "spread", "subject", "sign"] {
        let trace = Arc::new(Trace::default());
        let clock_trace = trace.clone();
        let context = crate::plugins::test_helpers::create_test_context()
            .await
            .with_clock(move || {
                clock_trace.record("clock");
                Utc.timestamp_millis_opt(1_700_000_000_000)
                    .single()
                    .unwrap()
            });
        let failure: FieldValue = FieldMap::from([("phase".into(), phase.into())]).into();
        let root: FieldValue = FieldMap::from([
            ("session".into(), FieldMap::new().into()),
            (
                "user".into(),
                FieldMap::from([("id".into(), "owner".into())]).into(),
            ),
            ("changed".into(), false.into()),
        ])
        .into();
        let payload = ObservedFields::new(
            FieldMap::from([("value".into(), true.into())]),
            trace.clone(),
            (phase == "spread").then(|| ("value", failure.clone())),
        );
        let payload_failure = failure.clone();
        let payload_trace = trace.clone();
        let subject_failure = failure.clone();
        let subject_trace = trace.clone();
        let sign_failure = failure.clone();
        let sign_trace = trace.clone();
        let plugin = JwtPlugin::new()
            .define_payload_native(Arc::new(move |data| {
                let failure = payload_failure.clone();
                let payload = payload.value();
                let trace = payload_trace.clone();
                Box::pin(async move {
                    trace.record("payload");
                    data.as_object().unwrap().set("changed", true.into())?;
                    if phase == "payload" {
                        return Err(AuthError::from_thrown(failure));
                    }
                    Ok(payload)
                })
            }))
            .get_subject_native(Arc::new(move |_| {
                let trace = subject_trace.clone();
                let failure = subject_failure.clone();
                Box::pin(async move {
                    trace.record("subject");
                    if phase == "subject" {
                        return Err(AuthError::from_thrown(failure));
                    }
                    Ok("owner".into())
                })
            }))
            .custom_sign_native(Arc::new(move |_, _, _| {
                let trace = sign_trace.clone();
                let failure = sign_failure.clone();
                Box::pin(async move {
                    trace.record("sign");
                    Err(AuthError::from_thrown(failure))
                })
            }));
        let endpoint = EndpointContext::new(None, FieldValue::Null, &context);
        let error = plugin
            .sign_session(
                Some(NativeSessionData::from_native(root.clone(), true)),
                &endpoint,
            )
            .await
            .unwrap_err();
        assert!(error.raw_value().unwrap().strict_equals(&failure));
        assert_eq!(root.model_property("changed")?, true.into());
        let expected = ["payload", "clock", "get:value", "subject", "clock", "sign"];
        let last = if phase == "spread" {
            "get:value"
        } else {
            phase
        };
        let length = expected.iter().position(|event| *event == last).unwrap() + 1;
        assert_eq!(
            *trace.events.lock().unwrap(),
            expected.get(..length).unwrap()
        );
    }
    Ok(())
}

#[tokio::test]
async fn signing_caches_default_reads_before_spread_and_preserves_native_leaves() -> AuthResult<()>
{
    let trace = Arc::new(Trace::default());
    let child: FieldValue = FieldMap::from([("leaf".into(), true.into())]).into();
    let source = ObservedFields::new(
        FieldMap::from([
            ("iat".into(), 10.into()),
            ("exp".into(), FieldValue::Null),
            ("nbf".into(), FieldValue::Undefined),
            ("iss".into(), FieldValue::Null),
            ("aud".into(), FieldValue::Undefined),
            ("child".into(), child.clone()),
        ]),
        trace.clone(),
        None,
    );
    let reads = Arc::new(AtomicUsize::new(0));
    source.getter(
        "iat",
        FieldFunction::contextual(move |_, _| {
            Ok(if reads.fetch_add(1, Ordering::SeqCst) == 0 {
                10.into()
            } else {
                20.into()
            })
        }),
    )?;
    let returned: FieldValue = FieldMap::from([("signed".into(), true.into())]).into();
    let signed = returned.clone();
    let plugin = JwtPlugin::new()
        .issuer(BASE.to_owned())
        .audience(BASE.into())
        .custom_sign_native(Arc::new(move |payload, _, _| {
            let child = child.clone();
            let returned = signed.clone();
            Box::pin(async move {
                assert_eq!(
                    payload.enumerable_fields()?,
                    FieldMap::from([
                        ("iat".into(), 10.into()),
                        ("exp".into(), 910.into()),
                        ("nbf".into(), FieldValue::Undefined),
                        ("iss".into(), BASE.into()),
                        ("aud".into(), BASE.into()),
                        ("child".into(), child.clone()),
                    ])
                );
                assert!(payload.model_property("child")?.strict_equals(&child));
                Ok(returned)
            })
        }));
    let context = crate::plugins::test_helpers::create_test_context().await;
    let endpoint = EndpointContext::new(None, FieldValue::Null, &context);
    let token = plugin
        .sign_value_in_endpoint(source.value(), None, &endpoint)
        .await?;
    assert!(token.strict_equals(&returned));
    assert_eq!(
        *trace.events.lock().unwrap(),
        [
            "get:iat",
            "get:exp",
            "get:nbf",
            "get:iss",
            "get:aud",
            "get:iat",
            "get:exp",
            "get:nbf",
            "get:iss",
            "get:aud",
            "get:child"
        ]
    );
    Ok(())
}

use chrono::TimeZone as _;
