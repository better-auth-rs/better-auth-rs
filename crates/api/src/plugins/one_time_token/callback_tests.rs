#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Callback regressions assert complete endpoint values and preserve setup errors"
)]

use super::*;
use better_auth_core::{
    AuthPlugin, CreateSession, CreateUser, HttpMethod,
    hooks::{RequestHookContext, with_request_hook_context_value},
    store::{EphemeralStore, StatelessSchema},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::plugins::test_helpers::{create_test_config, initialize_test_context};

struct Observation {
    data: FieldMap,
    session: Option<FieldMap>,
    new_session: Option<FieldMap>,
    body: FieldValue,
    query: Option<Value>,
    headers: Option<HashMap<String, String>>,
    original_path: Option<String>,
    path: Option<String>,
    response: Option<AuthResponse>,
    transaction: bool,
}

type Observations = Arc<Mutex<Vec<Observation>>>;

fn callbacks(observations: Observations, fail: bool) -> OneTimeTokenCallbacks<StatelessSchema> {
    OneTimeTokenCallbacks::generate(move |data, endpoint| {
        let observations = observations.clone();
        Box::pin(async move {
            tokio::task::yield_now().await;
            observations.lock().unwrap().push(Observation {
                data: FieldMap::from(data.clone()),
                session: endpoint.session.clone().map(FieldMap::from),
                new_session: endpoint.new_session()?.map(FieldMap::from),
                body: endpoint.body.clone(),
                query: endpoint.query().cloned(),
                headers: endpoint.headers().cloned(),
                original_path: endpoint.request.map(|request| request.path().to_owned()),
                path: endpoint.path.map(str::to_owned),
                response: endpoint.response.cloned(),
                transaction: endpoint.transaction.is_some(),
            });
            if endpoint.input_request().is_some() {
                endpoint.set_header("x-ott-callback", "retained")?;
                endpoint.set_header("set-ott", "callback-token")?;
                endpoint.set_header("access-control-expose-headers", "callback-exposed")?;
            }
            if fail {
                Err(AuthError::bad_request("Generator rejected"))
            } else {
                Ok("typed-token".into())
            }
        })
    })
}

fn options(legacy_calls: Arc<AtomicUsize>, hash_calls: Arc<AtomicUsize>) -> OneTimeTokenPlugin {
    OneTimeTokenPlugin::new()
        .generate_token(Arc::new(move |_| {
            let _ = legacy_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(AuthError::internal("Legacy generator must not run")) })
        }))
        .store_token(TokenStorage::Custom(Arc::new(move |token| {
            let _ = hash_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(format!("stored:{token}")) })
        })))
}

async fn context(
    plugin: &dyn AuthPlugin<StatelessSchema>,
) -> AuthResult<(AuthContext<StatelessSchema>, NativeSessionData)> {
    let mut config = create_test_config();
    config.session.disable_session_refresh = Some(true);
    let config = Arc::new(config);
    let ctx = initialize_test_context(
        config.clone(),
        Arc::new(EphemeralStore::new(config)),
        &[plugin],
    )
    .await?;
    let user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("owner@ott-callback.test")
                .with_name("OTT Owner"),
        )
        .await?;
    let session = ctx
        .database
        .create_session(CreateSession {
            user_id: user.id.clone(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    Ok((ctx, (user, session).into()))
}

fn request(
    ctx: &AuthContext<StatelessSchema>,
    data: &NativeSessionData,
    path: &str,
) -> AuthResult<AuthRequest> {
    let mut request = AuthRequest::new(HttpMethod::Get, path);
    request.body = Some(serde_json::to_vec(
        &json!({"purpose":"transfer", "extra":[1,null]}),
    )?);
    request.query = Some(json!({"target":"another-device", "raw":[true,7]}));
    let _ = request
        .headers
        .insert("x-ott-source".into(), "callback-regression".into());
    let _ = request
        .headers
        .insert("content-type".into(), "application/json".into());
    let _ = request.headers.insert(
        "cookie".into(),
        format!(
            "{}={}",
            ctx.config
                .auth_cookie("session_token", Default::default())
                .name,
            better_auth_core::utils::cookie_utils::sign_cookie_value(
                data.session.token.typed()?,
                ctx.config.signing_secret()
            )
        ),
    );
    Ok(request)
}

#[tokio::test]
async fn generator_retains_http_and_native_input_and_typed_precedence() -> AuthResult<()> {
    for is_http in [false, true] {
        let observations = Observations::default();
        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let hash_calls = Arc::new(AtomicUsize::new(0));
        let plugin = options(legacy_calls.clone(), hash_calls.clone())
            .callbacks(callbacks(observations.clone(), false));
        let (ctx, data) = context(&plugin).await?;
        let request = request(&ctx, &data, "/one-time-token/generate")?;
        let mut scope = RequestHookContext::from_request(&request)?;
        scope.is_http = is_http;
        let response = with_request_hook_context_value(scope, plugin.on_request(&request, &ctx))
            .await?
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body.json()?, Some(json!({"token":"typed-token"})));
        let selected = FieldMap::from(request.native_session_snapshot()?.unwrap());
        {
            let observations = observations.lock().unwrap();
            assert_eq!(observations.len(), 1);
            let observation = observations.first().unwrap();
            assert_eq!(observation.data, selected);
            assert_eq!(observation.session.as_ref(), Some(&selected));
            assert!(observation.new_session.is_none());
            assert_eq!(observation.body, request.input_field_value()?);
            assert_eq!(observation.query, request.query);
            assert_eq!(observation.headers.as_ref(), Some(&request.headers));
            assert_eq!(
                observation.original_path.as_deref(),
                is_http.then_some("/one-time-token/generate")
            );
            assert_eq!(
                observation.path.as_deref(),
                Some("/one-time-token/generate")
            );
            assert!(observation.response.is_none());
            assert!(!observation.transaction);
        }
        let proof = ctx
            .database
            .get_verification_including_expired("one-time-token:stored:typed-token")
            .await?
            .unwrap();
        assert_eq!(proof.value, data.session.token);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
        assert_eq!(hash_calls.load(Ordering::SeqCst), 1);

        assert_eq!(
            OneTimeTokenPlugin::new()
                .generate_native(&ctx, data.clone())
                .await?,
            "typed-token"
        );
        let observations = observations.lock().unwrap();
        assert_eq!(observations.len(), 2);
        let observation = observations.last().unwrap();
        assert_eq!(observation.data, FieldMap::from(data));
        assert_eq!(observation.session.as_ref(), Some(&observation.data));
        assert!(observation.new_session.is_none());
        assert!(observation.body.is_undefined());
        assert!(observation.query.is_none());
        assert!(observation.headers.is_none());
        assert!(observation.original_path.is_none());
        assert!(observation.path.is_none());
        assert!(observation.response.is_none());
        assert!(!observation.transaction);
    }
    Ok(())
}

#[tokio::test]
async fn after_hook_keeps_current_and_new_sessions_distinct_and_overwrites_callback_headers()
-> AuthResult<()> {
    let observations = Observations::default();
    let legacy_calls = Arc::new(AtomicUsize::new(0));
    let hash_calls = Arc::new(AtomicUsize::new(0));
    let plugin = options(legacy_calls.clone(), hash_calls.clone())
        .set_ott_header_on_new_session(true)
        .callbacks(callbacks(observations.clone(), false));
    let (ctx, current) = context(&plugin).await?;
    let request = request(&ctx, &current, "/native-session-replacement")?;
    let selected = ctx.require_native_session(&request).await?;
    let mut new = current.clone();
    new.session.token = better_auth_core::SchemaValue::from_field(19.0.into());
    new.user = vec![FieldValue::from(FieldMap::from([
        ("id".into(), 7.0.into()),
        ("hidden".into(), "retained".into()),
    ]))]
    .into();
    ctx.session_manager()
        .publish_session(&request, new.clone())?;
    ctx.database
        .delete_session(current.session.token.typed()?)
        .await?;
    let mut response = AuthResponse::json(202, &json!({"accepted":true}))?;
    let _ = response
        .headers
        .insert("access-control-expose-headers", "X-A, X-A, set-ott");
    plugin.after_request(&request, &mut response, &ctx).await?;
    response.headers.merge(request.take_response_headers()?);
    assert_eq!(
        response.headers.get("set-ott").map(String::as_str),
        Some("typed-token")
    );
    assert_eq!(
        response
            .headers
            .get("access-control-expose-headers")
            .map(String::as_str),
        Some("X-A, set-ott")
    );
    assert_eq!(
        response.headers.get("x-ott-callback").map(String::as_str),
        Some("retained")
    );
    let proof = ctx
        .database
        .get_verification_including_expired("one-time-token:stored:typed-token")
        .await?
        .unwrap();
    assert_eq!(proof.value.field_value(), 19.0.into());
    assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
    assert_eq!(hash_calls.load(Ordering::SeqCst), 1);
    let observations = observations.lock().unwrap();
    assert_eq!(observations.len(), 1);
    let observation = observations.first().unwrap();
    assert_eq!(observation.data, FieldMap::from(new.clone()));
    assert_eq!(observation.new_session, Some(FieldMap::from(new)));
    assert_eq!(observation.session, Some(FieldMap::from(selected)));
    assert_eq!(observation.body, request.input_field_value()?);
    assert_eq!(observation.query, request.query);
    assert_eq!(observation.headers.as_ref(), Some(&request.headers));
    assert_eq!(
        observation.path.as_deref(),
        Some("/native-session-replacement")
    );
    assert_eq!(
        observation.original_path.as_deref(),
        Some("/native-session-replacement")
    );
    let response = observation.response.as_ref().unwrap();
    assert_eq!(response.status, 202);
    assert_eq!(response.body.json()?, Some(json!({"accepted":true})));
    assert_eq!(
        response
            .headers
            .get("access-control-expose-headers")
            .map(String::as_str),
        Some("X-A, X-A, set-ott")
    );
    Ok(())
}

#[tokio::test]
async fn generation_error_keeps_callback_effects_without_hashing_persisting_or_final_headers()
-> AuthResult<()> {
    let observations = Observations::default();
    let legacy_calls = Arc::new(AtomicUsize::new(0));
    let hash_calls = Arc::new(AtomicUsize::new(0));
    let plugin = options(legacy_calls.clone(), hash_calls.clone())
        .set_ott_header_on_new_session(true)
        .callbacks(callbacks(observations.clone(), true));
    let (ctx, data) = context(&plugin).await?;
    let request = request(&ctx, &data, "/failed-generation")?;
    ctx.session_manager()
        .publish_session(&request, data.clone())?;
    let mut response = AuthResponse::new(200);
    let _ = response
        .headers
        .insert("access-control-expose-headers", "original");
    let error = plugin
        .after_request(&request, &mut response, &ctx)
        .await
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "Generator rejected");
    assert_eq!(observations.lock().unwrap().len(), 1);
    assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
    assert_eq!(hash_calls.load(Ordering::SeqCst), 0);
    assert!(
        ctx.database
            .get_verification_including_expired("one-time-token:stored:typed-token")
            .await?
            .is_none()
    );
    assert!(response.headers.get("set-ott").is_none());
    assert_eq!(
        response
            .headers
            .get("access-control-expose-headers")
            .map(String::as_str),
        Some("original")
    );
    let pending = request.take_response_headers()?;
    assert_eq!(
        pending.get("set-ott").map(String::as_str),
        Some("callback-token")
    );
    assert_eq!(
        pending
            .get("access-control-expose-headers")
            .map(String::as_str),
        Some("callback-exposed")
    );
    assert_eq!(
        pending.get("x-ott-callback").map(String::as_str),
        Some("retained")
    );
    assert_eq!(
        FieldMap::from(request.new_session()?.unwrap()),
        FieldMap::from(data)
    );
    Ok(())
}

#[tokio::test]
async fn generation_requires_session_before_client_policy_and_skips_both_generators()
-> AuthResult<()> {
    let observations = Observations::default();
    let legacy_calls = Arc::new(AtomicUsize::new(0));
    let hash_calls = Arc::new(AtomicUsize::new(0));
    let plugin = options(legacy_calls.clone(), hash_calls.clone())
        .disable_client_request(true)
        .callbacks(callbacks(observations.clone(), false));
    let (ctx, data) = context(&plugin).await?;
    let anonymous = AuthRequest::new(HttpMethod::Get, "/one-time-token/generate");
    assert!(matches!(
        plugin.on_request(&anonymous, &ctx).await,
        Err(AuthError::Upstream {
            status: 401,
            code: "UNAUTHORIZED",
            ..
        })
    ));
    let request = request(&ctx, &data, "/one-time-token/generate")?;
    let response = plugin.on_request(&request, &ctx).await?.unwrap();
    assert_eq!(response.status, 400);
    assert_eq!(
        response.body.json()?,
        Some(json!({"message":"Client requests are disabled"}))
    );
    assert!(observations.lock().unwrap().is_empty());
    assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
    assert_eq!(hash_calls.load(Ordering::SeqCst), 0);
    let scope = RequestHookContext::from_request(&request)?;
    let response = with_request_hook_context_value(scope, plugin.on_request(&request, &ctx))
        .await?
        .unwrap();
    assert_eq!(response.body.json()?, Some(json!({"token":"typed-token"})));
    assert_eq!(observations.lock().unwrap().len(), 1);
    assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
    assert_eq!(hash_calls.load(Ordering::SeqCst), 1);
    let explicit =
        request.with_original_request(AuthRequest::new(HttpMethod::Get, "/original-request"));
    let scope = RequestHookContext::from_request(&explicit)?;
    let response = with_request_hook_context_value(scope, plugin.on_request(&explicit, &ctx))
        .await?
        .unwrap();
    assert_eq!(response.status, 400);
    assert_eq!(
        response.body.json()?,
        Some(json!({"message":"Client requests are disabled"}))
    );
    assert_eq!(observations.lock().unwrap().len(), 1);
    assert_eq!(hash_calls.load(Ordering::SeqCst), 1);
    Ok(())
}
