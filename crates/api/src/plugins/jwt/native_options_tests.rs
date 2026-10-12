#![expect(
    clippy::indexing_slicing,
    clippy::panic,
    reason = "Fixture indexing must fail when an expected record or property is missing. Unexpected fixture variants and deliberate callback panics must fail or exercise the recorded unwind path."
)]
#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Paired JWT option contracts assert exact native identities, callback order, and stored records."
)]

use super::native_test_support::{ObservedFields, Trace};
use super::*;
use better_auth_core::{
    BeforeRequestAction, FieldDate, FieldFunction,
    endpoint_dispatch::EndpointDispatcher,
    observability::{BeforeEndpointHook, EndpointHooks},
    store::{AuthStore, EphemeralStore, StatelessSchema as S},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

const BASE: &str = "http://jwt-native-options.test";

async fn context(plugin: &JwtPlugin, callbacks: JwtCallbacks<S>) -> AuthResult<AuthContext<S>> {
    let mut config = crate::plugins::test_helpers::create_test_config();
    config.base_url = BASE.into();
    config.telemetry.enabled = false;
    let config = Arc::new(config);
    let store: Arc<dyn AuthStore<S>> = Arc::new(EphemeralStore::new(config.clone()));
    plugin
        .options
        .0
        .set_model_property("adapter", callbacks.to_native())?;
    let mut context =
        crate::plugins::test_helpers::initialize_test_context(config, store, &[plugin]).await?;
    context.extensions.insert(Arc::new(callbacks));
    Ok(context)
}

struct Replace(FieldValue);
#[async_trait::async_trait]
impl BeforeEndpointHook<S> for Replace {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        request
            .input_field_value()?
            .set_model_property("overrideOptions", self.0.clone())?;
        Ok(None)
    }
}

fn replace(context: &mut AuthContext<S>, options: FieldValue) {
    context.extensions.insert(Arc::new(EndpointDispatcher::new(
        Arc::new(Vec::new()),
        EndpointHooks {
            before: Some(Arc::new(Replace(options))),
            after: None,
        },
        [],
    )));
}

fn claims() -> FieldValue {
    FieldMap::from([
        ("iat".into(), 10.0.into()),
        ("exp".into(), 2_000_000_000.0.into()),
    ])
    .into()
}

#[tokio::test]
async fn before_hook_group_replacement_cannot_restore_the_original_signer() -> AuthResult<()> {
    for mode in [
        "empty",
        "undefined",
        "null",
        "false",
        "zero",
        "empty-string",
        "sign-undefined",
        "replacement",
    ] {
        let retired = Arc::new(AtomicUsize::new(0));
        let count = retired.clone();
        let callback: JwtNativeCustomSign = Arc::new(move |_, _, _| {
            let _ = count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok("retired".into()) })
        });
        let plugin = JwtPlugin::new()
            .algorithm(JwtAlgorithm::EdDsa)
            .remote_url(format!("{BASE}/keys"))
            .custom_sign_native(callback.clone());
        let fallback: FieldValue = FieldMap::from([("fallback".into(), true.into())]).into();
        let failure = fallback.clone();
        let callbacks = JwtCallbacks::<S>::default().get_jwks_native(move |_| {
            let failure = failure.clone();
            Box::pin(async move { Err(AuthError::from_thrown(failure)) })
        });
        let mut context = context(&plugin, callbacks).await?;
        let token: FieldValue = FieldMap::from([("replacement".into(), true.into())]).into();
        let replacement: FieldValue = FieldMap::new().into();
        let expected_receiver = replacement.clone();
        let returned = token.clone();
        replacement.set_model_property(
            "sign",
            FieldFunction::contextual(move |receiver, arguments| {
                assert!(receiver.strict_equals(&expected_receiver));
                assert_eq!(
                    arguments[0],
                    FieldMap::from([
                        ("iat".into(), 10.0.into()),
                        ("exp".into(), 2_000_000_000.0.into()),
                        ("nbf".into(), FieldValue::Undefined),
                        ("iss".into(), BASE.into()),
                        ("aud".into(), BASE.into()),
                    ])
                    .into()
                );
                Ok(returned.clone())
            })
            .into(),
        )?;
        let group = match mode {
            "empty" => FieldMap::new().into(),
            "undefined" => FieldValue::Undefined,
            "null" => FieldValue::Null,
            "false" => false.into(),
            "zero" => 0.0.into(),
            "empty-string" => "".into(),
            "sign-undefined" => FieldMap::from([("sign".into(), FieldValue::Undefined)]).into(),
            _ => replacement,
        };
        replace(&mut context, FieldMap::from([("jwt".into(), group)]).into());
        let original = JwtCallOverrides::<S> {
            jwt: Some(JwtTokenOptions {
                custom_sign: Some(callback),
                ..Default::default()
            }),
            ..Default::default()
        }
        .into_native();
        let result = JwtApi::from_context(&context)?
            .sign_value_with_overrides(claims(), original)
            .await;
        if mode == "replacement" {
            assert!(result?.strict_equals(&token));
        } else {
            assert!(
                result
                    .unwrap_err()
                    .into_thrown_value()?
                    .strict_equals(&fallback)
            );
        }
        assert_eq!(retired.load(Ordering::SeqCst), 0, "{mode}");
        assert!(context.database.list_jwk_records().await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn before_hook_adapter_replacement_keeps_bound_endpoints_and_default_persistence()
-> AuthResult<()> {
    for mode in ["empty", "undefined", "callbacks-undefined", "replacement"] {
        let retired = Arc::new(AtomicUsize::new(0));
        let count = retired.clone();
        let original = JwtCallbacks::<S>::default()
            .get_jwks_native(move |_| {
                let _ = count.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Err(AuthError::internal("Replaced getJwks must not run")) })
            })
            .create_jwk_value(|_, _| {
                Box::pin(async { Err(AuthError::internal("Replaced createJwk must not run")) })
            });
        let plugin = JwtPlugin::new().disable_private_key_encryption(true);
        let mut context = context(&plugin, JwtCallbacks::default()).await?;
        let events = Arc::new(Mutex::new(Vec::new()));
        let created = Arc::new(Mutex::new(None::<FieldValue>));
        let reads = events.clone();
        let writes = events.clone();
        let saved = created.clone();
        let callbacks = JwtCallbacks::<S>::default()
            .get_jwks_native(move |endpoint| {
                assert_eq!(endpoint.auth.config.base_url.as_static(), Some(BASE));
                reads.lock().unwrap().push("getJwks");
                Box::pin(async { Ok(Vec::<FieldValue>::new().into()) })
            })
            .create_jwk_value(move |key, endpoint| {
                let result = (|| {
                    assert_eq!(endpoint.auth.config.base_url.as_static(), Some(BASE));
                    assert_eq!(
                        key.enumerable_fields()?
                            .keys()
                            .map(String::as_str)
                            .collect::<Vec<_>>(),
                        ["alg", "crv", "publicKey", "privateKey", "createdAt"]
                    );
                    writes.lock().unwrap().push("createJwk");
                    key.set_model_property("id", "replacement-key".into())?;
                    *saved.lock().unwrap() = Some(key.clone());
                    Ok(key)
                })();
                Box::pin(async move { result })
            });
        let group = match mode {
            "empty" => FieldMap::new().into(),
            "undefined" => FieldValue::Undefined,
            "callbacks-undefined" => FieldMap::from([
                ("getJwks".into(), FieldValue::Undefined),
                ("createJwk".into(), FieldValue::Undefined),
            ])
            .into(),
            _ => callbacks.into_native(),
        };
        replace(
            &mut context,
            FieldMap::from([("adapter".into(), group)]).into(),
        );
        let token = JwtApi::from_context(&context)?
            .sign_value_with_overrides(
                claims(),
                JwtCallOverrides::<S> {
                    adapter: Some(original),
                    ..Default::default()
                }
                .into_native(),
            )
            .await?
            .decode::<String>()?;
        let stored = context.database.list_jwk_records().await?;
        let key: FieldValue = if mode == "replacement" {
            assert!(stored.is_empty());
            created.lock().unwrap().clone().unwrap()
        } else {
            assert_eq!(stored.len(), 1);
            stored[0].clone().into()
        };
        assert_eq!(
            tests::header(&token),
            json!({"alg":"EdDSA", "kid":key.model_property("id")?.json()?})
        );
        assert_eq!(
            verification::verify_local(
                &token,
                keys::parse_json(&key.model_property("publicKey")?)?,
                &"EdDSA".into(),
                Some(BASE),
                Some(&[BASE]),
                0
            )?,
            Some(serde_json::from_value(
                json!({"iat":10,"exp":2_000_000_000,"iss":BASE,"aud":BASE})
            )?)
        );
        assert_eq!(
            *events.lock().unwrap(),
            if mode == "replacement" {
                vec!["getJwks", "getJwks", "createJwk"]
            } else {
                vec![]
            }
        );
        assert_eq!(retired.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn defaults_read_populated_claims_and_reacquire_the_sign_receiver_after_spread()
-> AuthResult<()> {
    let trace = Arc::new(Trace::default());
    let child: FieldValue = FieldMap::from([("retained".into(), true.into())]).into();
    let values = FieldMap::from([
        ("iat".into(), 10.0.into()),
        ("exp".into(), 70.0.into()),
        ("nbf".into(), FieldValue::Undefined),
        ("iss".into(), "payload-issuer".into()),
        ("aud".into(), child.clone()),
        ("child".into(), child.clone()),
    ]);
    let payload = ObservedFields::new(values.clone(), trace.clone(), None);
    let replacement = ObservedFields::new(
        FieldMap::from([("sign".into(), FieldValue::Undefined)]),
        trace.clone(),
        None,
    );
    let current = ObservedFields::new(
        FieldMap::from([
            ("expirationTime".into(), 999.0.into()),
            ("issuer".into(), "unused-issuer".into()),
            ("audience".into(), "unused-audience".into()),
            ("sign".into(), FieldValue::Undefined),
        ]),
        trace.clone(),
        None,
    );
    let root = ObservedFields::new(
        FieldMap::from([("jwt".into(), current.value())]),
        trace.clone(),
        None,
    );
    let root_value = root.value();
    let new_group = replacement.value();
    current.getter(
        "sign",
        FieldFunction::contextual(move |_, _| {
            root_value.set_model_property("jwt", new_group.clone())?;
            Ok(FieldFunction::contextual(|_, _| {
                Err(AuthError::internal("First sign getter must not be called"))
            })
            .into())
        }),
    )?;
    let returned: FieldValue = FieldMap::from([("signed".into(), child.clone())]).into();
    let token = returned.clone();
    let receiver = replacement.value();
    let callback_trace = trace.clone();
    replacement.getter(
        "sign",
        FieldFunction::contextual(move |_, _| {
            let values = values.clone();
            let token = token.clone();
            let receiver = receiver.clone();
            let trace = callback_trace.clone();
            let child = child.clone();
            Ok(FieldFunction::contextual(move |actual, arguments| {
                trace.record("sign.call");
                assert!(actual.strict_equals(&receiver));
                assert_eq!(arguments[0], values.clone().into());
                assert!(arguments[0].model_property("aud")?.strict_equals(&child));
                assert!(arguments[1].is_undefined());
                assert_eq!(
                    arguments[2],
                    FieldMap::from([
                        ("signingKeyId".into(), FieldValue::Undefined),
                        ("signingAlgorithm".into(), FieldValue::Undefined)
                    ])
                    .into()
                );
                Ok(token.clone())
            })
            .into())
        }),
    )?;
    let plugin = JwtPlugin::new();
    let context = context(&plugin, JwtCallbacks::default()).await?;
    let endpoint = EndpointContext::native(None, None, FieldValue::Null, &context);
    assert!(
        plugin
            .sign_native_options(
                payload.value(),
                None,
                &overrides::NativeOptions(root.value()),
                &endpoint
            )
            .await?
            .strict_equals(&returned)
    );
    assert_eq!(
        *trace.events.lock().unwrap(),
        [
            "get:iat",
            "get:exp",
            "get:jwt",
            "get:expirationTime",
            "get:nbf",
            "get:iss",
            "get:jwt",
            "get:issuer",
            "get:aud",
            "get:jwt",
            "get:audience",
            "get:jwt",
            "get:sign",
            "get:iat",
            "get:exp",
            "get:nbf",
            "get:iss",
            "get:aud",
            "get:child",
            "get:jwt",
            "get:sign",
            "sign.call",
        ]
    );
    Ok(())
}

#[test]
fn expiration_preserves_dynamic_numbers_dates_coercion_and_original_errors() -> AuthResult<()> {
    for number in [0.0, -1.0, f64::NAN, f64::INFINITY] {
        assert!(
            claims::default_expiration(&number.into(), &10.0.into(), 100)?
                .same_value_zero(&number.into())
        );
    }
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = events.clone();
    let date: FieldValue = FieldDate::from_milliseconds(0.0).into();
    let expected = date.clone();
    date.set_model_property(
        "getTime",
        FieldFunction::contextual(move |receiver, _| {
            assert!(receiver.strict_equals(&expected));
            observed.lock().unwrap().push("getTime");
            let observed = observed.clone();
            Ok(FieldMap::from([(
                "valueOf".into(),
                FieldFunction::contextual(move |_, _| {
                    observed.lock().unwrap().push("valueOf");
                    Ok("12345".into())
                })
                .into(),
            )])
            .into())
        })
        .into(),
    )?;
    assert_eq!(
        claims::default_expiration(&date, &10.0.into(), 100)?,
        12.0.into()
    );
    assert_eq!(*events.lock().unwrap(), ["getTime", "valueOf"]);
    let duration: FieldValue = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual(|_, _| Ok("2 seconds".into())).into(),
    )])
    .into();
    assert_eq!(
        claims::default_expiration(&duration, &"10".into(), 100)?,
        "102".into()
    );
    let negative_zero = claims::default_expiration(&"-0.1s".into(), &(-0.0).into(), 100)?
        .as_f64()
        .unwrap();
    assert!(negative_zero == 0.0 && negative_zero.is_sign_negative());
    let overflowing = format!("{}s", "1".to_owned() + &"0".repeat(306));
    assert_eq!(
        claims::default_expiration(&overflowing.into(), &10.0.into(), 100)?,
        f64::INFINITY.into()
    );
    let failure: FieldValue = FieldMap::from([("conversion".into(), true.into())]).into();
    let original = failure.clone();
    let calls = AtomicUsize::new(0);
    let duration: FieldValue = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual(move |_, _| {
            if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                return Err(AuthError::from_thrown(original.clone()));
            }
            Ok("invalid-duration".into())
        })
        .into(),
    )])
    .into();
    assert!(
        claims::default_expiration(&duration, &10.0.into(), 100)
            .unwrap_err()
            .into_thrown_value()?
            .strict_equals(&failure)
    );
    let invalid: FieldValue = better_auth_core::Utf16String::from_units(vec![0xd800]).into();
    let error = claims::default_expiration(&invalid, &10.0.into(), 100).unwrap_err();
    let mut message = "Invalid time string format: \""
        .encode_utf16()
        .collect::<Vec<_>>();
    message.push(0xd800);
    message.extend("\". Use formats like \"7d\", \"30m\", \"1 hour\", etc.".encode_utf16());
    assert_eq!(
        error.message_value()?,
        better_auth_core::Utf16String::from_units(message).into()
    );
    Ok(())
}

#[path = "native_options_key_tests.rs"]
mod key_tests;

#[tokio::test]
async fn owned_callback_builders_invalidate_the_shared_registered_adapter() -> AuthResult<()> {
    for replace_read in [false, true] {
        let callbacks = Arc::new(
            JwtCallbacks::<S>::default()
                .get_jwks_native(|_| Box::pin(async { Ok("original-read".into()) }))
                .create_jwk_value(|_, _| Box::pin(async { Ok("original-write".into()) })),
        );
        let original = callbacks.to_native();
        assert!(original.strict_equals(&callbacks.to_native()));
        let Ok(callbacks) = Arc::try_unwrap(callbacks) else {
            panic!("The callback owner must remain recoverable after native projection");
        };
        let callbacks = if replace_read {
            callbacks.get_jwks_native(|_| Box::pin(async { Ok("replacement-read".into()) }))
        } else {
            callbacks.create_jwk_value(|_, _| Box::pin(async { Ok("replacement-write".into()) }))
        };
        let replacement = callbacks.to_native();
        assert!(!replacement.strict_equals(&original));
        let plugin = JwtPlugin::new();
        let context = context(&plugin, callbacks).await?;
        let first = overrides::NativeOptions::registered(&context)?;
        let second = overrides::NativeOptions::registered(&context)?;
        let first_adapter = first.0.model_property("adapter")?;
        let second_adapter = second.0.model_property("adapter")?;
        assert!(first_adapter.strict_equals(&replacement));
        assert!(first_adapter.strict_equals(&second_adapter));
        for name in ["getJwks", "createJwk"] {
            assert!(
                first_adapter
                    .model_property(name)?
                    .strict_equals(&second_adapter.model_property(name)?)
            );
        }
        let endpoint = EndpointContext::native(None, None, FieldValue::Null, &context);
        assert_eq!(
            plugin.read_keys(&endpoint).await?,
            FieldValue::from(if replace_read {
                "replacement-read"
            } else {
                "original-read"
            })
        );
        assert_eq!(
            adapter::Keyring::new(adapter::store(&endpoint), &first, &endpoint)
                .create(FieldMap::new().into())
                .await?,
            FieldValue::from(if replace_read {
                "original-write"
            } else {
                "replacement-write"
            })
        );
        assert!(context.database.list_jwk_records().await?.is_empty());
    }
    Ok(())
}

#[path = "native_adapter_tests.rs"]
mod adapter_tests;
