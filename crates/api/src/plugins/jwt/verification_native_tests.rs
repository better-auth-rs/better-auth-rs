#![expect(
    clippy::indexing_slicing,
    reason = "Fixture indexing must fail when an expected record or property is missing."
)]
#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "JWT consumer contracts assert complete access order, receiver identity, and original logged errors."
)]

use super::super::native_test_support::{ObservedFields, Trace};
use super::*;
use better_auth_core::{
    FieldFunction, LoggerConfig,
    observability::LogLevel,
    session::{SessionCookieContext, SessionCookieSigner},
    store::{AuthStore, EphemeralStore, StatelessSchema},
};
use std::sync::Arc;

fn signed_key() -> AuthResult<(FieldMap, String)> {
    let private = JwtAlgorithm::EdDsa.generate(2048).map_err(jose_error)?;
    let public = private.to_public_key().map_err(jose_error)?.to_string();
    let signer = jws::EdDSA.signer_from_jwk(&private).map_err(jose_error)?;
    let now = Utc::now().timestamp();
    let token = jose::sign(
        FieldMap::from_json(serde_json::from_value(json!({
            "sub":"owner", "sid":"session-token", "user":{"id":"owner"},
            "session":{"token":"session-token"}, "iss":"http://localhost:3000",
            "aud":"better-auth:session-cache", "iat":now, "exp":now + 60
        }))?)?,
        FieldMap::from([
            ("alg".into(), "EdDSA".into()),
            ("kid".into(), "selected".into()),
            ("typ".into(), "better-auth.session-cache+jwt".into()),
        ]),
        &signer,
    )?;
    Ok((
        FieldMap::from([
            ("id".into(), "selected".into()),
            ("publicKey".into(), public.into()),
            ("alg".into(), "EdDSA".into()),
        ]),
        token,
    ))
}

async fn verify(
    token: &str,
    keyring: FieldValue,
    trace: Arc<Trace>,
    cookie: bool,
) -> AuthResult<Option<Map<String, Value>>> {
    let mut config = crate::plugins::test_helpers::create_test_config();
    config.telemetry.enabled = false;
    config.logger = LoggerConfig {
        level: Some(LogLevel::Debug),
        log: Some(trace.clone()),
        ..Default::default()
    }
    .into();
    let config = Arc::new(config);
    let store: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::new(config.clone()));
    let mut context = AuthContext::new(config, store)?;
    context.extensions.insert(Arc::new(
        JwtCallbacks::<StatelessSchema>::default().get_jwks_native(move |_| {
            trace.record("callback");
            let keyring = keyring.clone();
            Box::pin(async move { Ok(keyring) })
        }),
    ));
    let context = Arc::new(context);
    let plugin = JwtPlugin::with_config(JwtPluginConfig {
        audience: Some("better-auth:session-cache".into()),
        ..Default::default()
    });
    if !cookie {
        return plugin.verify(token, None, &context).await;
    }
    let init = AuthInitContext::new(context.config.clone(), context.database.clone())?;
    let runtime = init.runtime();
    runtime.bind(&context)?;
    let signer = cache::CookieSigner { plugin, runtime };
    context
        .with_native_context(Default::default(), |active| async move {
            let request = AuthRequest::new(HttpMethod::Get, "/get-session");
            signer
                .verify(
                    token,
                    SessionCookieContext {
                        request: &request,
                        config: &active.config,
                        transaction: None,
                    },
                )
                .await
        })
        .await
}

#[tokio::test]
async fn verification_reads_native_key_fields_in_each_consumers_source_order() -> AuthResult<()> {
    let (fields, token) = signed_key()?;
    for cookie in [false, true] {
        let trace = Arc::new(Trace::default());
        let key = ObservedFields::new(fields.clone(), trace.clone(), None);
        let payload = verify(&token, vec![key.value()].into(), trace.clone(), cookie)
            .await?
            .unwrap();
        assert_eq!(payload["sub"], "owner");
        assert_eq!(
            *trace.events.lock().unwrap(),
            if cookie {
                ["callback", "get:id", "get:alg", "get:publicKey"]
            } else {
                ["callback", "get:id", "get:publicKey", "get:alg"]
            }
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_getter_errors_reach_each_logger_and_logger_failures_escape() -> AuthResult<()> {
    let (fields, token) = signed_key()?;
    for cookie in [false, true] {
        for property in ["id", "publicKey", "alg"] {
            for logger_fails in [false, true] {
                let original: FieldValue =
                    FieldMap::from([("error".into(), property.into())]).into();
                let logger_error: FieldValue =
                    FieldMap::from([("logger".into(), true.into())]).into();
                let trace = Arc::new(Trace {
                    logger_failure: logger_fails.then(|| logger_error.clone()),
                    ..Default::default()
                });
                let key = ObservedFields::new(
                    fields.clone(),
                    trace.clone(),
                    Some((property, original.clone())),
                );
                let result = verify(&token, vec![key.value()].into(), trace.clone(), cookie).await;
                if logger_fails {
                    assert!(
                        result
                            .unwrap_err()
                            .into_thrown_value()?
                            .strict_equals(&logger_error)
                    );
                } else {
                    assert!(result?.is_none());
                }
                let logged = trace.errors.lock().unwrap();
                assert_eq!(logged.len(), 1);
                assert!(logged[0].strict_equals(&original));
                let order = if cookie {
                    ["id", "alg", "publicKey"]
                } else {
                    ["id", "publicKey", "alg"]
                };
                let mut expected = vec!["callback".to_owned()];
                for name in order {
                    expected.push(format!("get:{name}"));
                    if name == property {
                        break;
                    }
                }
                expected.push(
                    if cookie {
                        "log:Cookie-cache JWT verification failed"
                    } else {
                        "log:JWT verification failed"
                    }
                    .into(),
                );
                assert_eq!(*trace.events.lock().unwrap(), expected);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_keyring_methods_keep_the_receiver_and_consumer_specific_length_checks()
-> AuthResult<()> {
    let (fields, token) = signed_key()?;
    for cookie in [false, true] {
        for length in [
            FieldValue::Undefined,
            FieldValue::Null,
            false.into(),
            0.into(),
            "0".into(),
            1.into(),
        ] {
            let trace = Arc::new(Trace::default());
            let key = ObservedFields::new(fields.clone(), trace.clone(), None);
            let keyring = ObservedFields::new(
                FieldMap::from([("length".into(), length.clone())]),
                trace.clone(),
                None,
            );
            let owner = Arc::downgrade(&keyring);
            let selected = key.value();
            let events = trace.clone();
            keyring.fields.set(
                "find",
                FieldFunction::contextual(move |receiver, arguments| {
                    assert!(receiver.strict_equals(&owner.upgrade().unwrap().value()));
                    events.record("find");
                    let FieldValue::Function(predicate) = &arguments[0] else {
                        return Err(AuthError::internal("Native find requires its predicate"));
                    };
                    assert!(
                        predicate
                            .call_with(
                                &FieldValue::Undefined,
                                &[selected.clone(), 0.into(), receiver.clone()]
                            )?
                            .is_truthy()
                    );
                    Ok(selected.clone())
                })
                .into(),
            )?;
            let expected = if cookie {
                length.is_truthy()
            } else {
                !length.strict_equals(&0.into())
            };
            let result = verify(&token, keyring.value(), trace.clone(), cookie).await?;
            assert_eq!(result.is_some(), expected);
            let mut events = vec!["callback", "get:length"];
            if expected {
                events.extend(["get:find", "find", "get:id"]);
                events.extend(if cookie {
                    ["get:alg", "get:publicKey"]
                } else {
                    ["get:publicKey", "get:alg"]
                });
            }
            assert_eq!(*trace.events.lock().unwrap(), events);
        }
    }
    Ok(())
}
