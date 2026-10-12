#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Cookie signing regressions compare exact getter order, receiver identity, and original errors."
)]

use super::native_test_support::{ObservedFields, Trace};
use super::*;
use better_auth_core::{
    FieldFunction,
    config::{CookieCacheConfig, CookieCacheStrategy},
    session::{SessionCookieContext, SessionCookieSigner},
    store::{AuthStore, EphemeralStore, StatelessSchema as S},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn cookie_signing_reads_the_retained_sign_getter_once_and_maps_absence_at_the_caller()
-> AuthResult<()> {
    let trace = Arc::new(Trace::default());
    let reads = trace.clone();
    let writes = trace.clone();
    let plugin = JwtPlugin::new()
        .session_cookie_cache(true)
        .disable_private_key_encryption(true)
        .callbacks(
            JwtCallbacks::<S>::default()
                .get_jwks(move |endpoint| {
                    reads.record("read");
                    Box::pin(async move { endpoint.auth.database.list_jwks().await.map(Some) })
                })
                .create_jwk(move |key, endpoint| {
                    writes.record("create");
                    Box::pin(async move { endpoint.auth.database.create_jwk(key).await.map(Some) })
                }),
        );
    let mut config = crate::plugins::test_helpers::create_test_config();
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        strategy: Some(CookieCacheStrategy::Jwt),
        ..Default::default()
    });
    let config = Arc::new(config);
    let store: Arc<dyn AuthStore<S>> = Arc::new(EphemeralStore::new(config.clone()));
    let context =
        crate::plugins::test_helpers::initialize_bound_test_context(config, store, &[&plugin])
            .await?;
    let plugin = JwtPlugin {
        config: context.extensions.get::<JwtPluginConfig>().unwrap().clone(),
        options: overrides::NativeOptions::registered(&context)?,
    };
    let signer = context
        .extensions
        .get::<Arc<dyn SessionCookieSigner<S>>>()
        .unwrap();
    let jwt = ObservedFields::new(FieldMap::new(), trace.clone(), None);
    plugin.options.0.set_model_property("jwt", jwt.value())?;
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    jwt.getter(
        "sign",
        FieldFunction::contextual(move |_, _| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(FieldValue::Undefined)
            } else {
                Err(AuthError::internal("Cookie signing read jwt.sign twice"))
            }
        }),
    )?;
    let request = AuthRequest::new(HttpMethod::Get, "/get-session");
    let cookie_context = || SessionCookieContext {
        request: &request,
        config: &context.config,
        transaction: None,
    };
    let payload = FieldMap::from([
        (
            "session".into(),
            FieldMap::from([("token".into(), "session-token".into())]).into(),
        ),
        (
            "user".into(),
            FieldMap::from([("id".into(), "owner".into())]).into(),
        ),
    ]);
    let token = signer.sign(payload.clone(), 60.0, cookie_context()).await?;
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(
        *trace.events.lock().unwrap(),
        ["get:sign", "read", "read", "create"]
    );
    assert_eq!(context.database.list_jwk_records().await?.len(), 1);
    let verified = signer.verify(&token, cookie_context()).await?.unwrap();
    assert_eq!(verified.get("sub"), Some(&Value::from("owner")));
    assert_eq!(verified.get("sid"), Some(&Value::from("session-token")));

    trace.events.lock().unwrap().clear();
    jwt.getter("sign", FieldFunction::contextual(|_, _| Ok(true.into())))?;
    let error = signer
        .sign(payload.clone(), 60.0, cookie_context())
        .await
        .unwrap_err()
        .into_thrown_value()?;
    assert_eq!(error.model_property("name")?, "BetterAuthError".into());
    assert_eq!(error.model_property("message")?, "`jwt({ sessionCookieCache: true })` requires locally managed JWT plugin keys and does not support `jwt.sign`.".into());
    assert_eq!(*trace.events.lock().unwrap(), ["get:sign"]);

    trace.events.lock().unwrap().clear();
    count.store(0, Ordering::SeqCst);
    let calls = count.clone();
    jwt.getter(
        "sign",
        FieldFunction::contextual(move |_, _| {
            Ok((calls.fetch_add(1, Ordering::SeqCst) != 0).into())
        }),
    )?;
    let endpoint = EndpointContext::native(None, None, FieldValue::Undefined, &context);
    let error = plugin
        .sign_value_in_endpoint(FieldMap::new().into(), None, &endpoint)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuthError::TypeError(message) if message == "Cannot destructure property 'alg' from null or undefined value")
    );
    assert_eq!(
        *trace.events.lock().unwrap(),
        [
            "get:expirationTime",
            "get:issuer",
            "get:audience",
            "get:sign",
            "get:sign"
        ]
    );

    trace.events.lock().unwrap().clear();
    let failure: FieldValue = FieldMap::from([("failure".into(), "sign getter".into())]).into();
    let original = failure.clone();
    jwt.getter(
        "sign",
        FieldFunction::contextual(move |receiver, _| {
            receiver.set_model_property("progress", "getter".into())?;
            Err(AuthError::from_thrown(original.clone()))
        }),
    )?;
    let error = signer
        .sign(payload, 60.0, cookie_context())
        .await
        .unwrap_err();
    assert!(error.into_thrown_value()?.strict_equals(&failure));
    assert_eq!(*trace.events.lock().unwrap(), ["get:sign"]);
    assert_eq!(jwt.value().model_property("progress")?, "getter".into());
    assert_eq!(context.database.list_jwk_records().await?.len(), 1);
    Ok(())
}
