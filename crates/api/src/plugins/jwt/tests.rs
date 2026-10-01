use super::*;
use crate::plugins::test_helpers::create_test_context;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::Arc;

fn header(token: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn pinned_algorithms_verify_and_reject_wrong_identity() {
    let ctx = create_test_context().await;
    let plugin = JwtPlugin::new().key_pair_configs(vec![
        JwtKeyPairConfig::new(JwtAlgorithm::Ps256),
        JwtKeyPairConfig::new(JwtAlgorithm::Es512),
    ]);
    for algorithm in [
        JwtAlgorithm::EdDsa,
        JwtAlgorithm::Ps256,
        JwtAlgorithm::Es512,
    ] {
        let options = JwtSigningOptions {
            algorithm: Some(algorithm),
            ..Default::default()
        };
        let payload = serde_json::from_value(json!({"sub": "owner", "scope": "read"})).unwrap();
        let token = plugin
            .sign_with_options(payload, &options, &ctx)
            .await
            .unwrap();
        assert_eq!(header(&token)["alg"], algorithm.name());
        assert_eq!(
            plugin.verify(&token, None, &ctx).await.unwrap().unwrap()["sub"],
            "owner"
        );
        assert!(
            plugin
                .verify(&token, Some("wrong-issuer"), &ctx)
                .await
                .unwrap()
                .is_none()
        );
        let pinned = JwtSigningOptions {
            key_id: header(&token)["kid"].as_str().map(str::to_owned),
            algorithm: Some(JwtAlgorithm::Rs256),
            ..Default::default()
        };
        assert!(
            plugin
                .sign_with_options(Map::new(), &pinned, &ctx)
                .await
                .is_err()
        );
    }
    let unconfigured = JwtSigningOptions {
        algorithm: Some(JwtAlgorithm::Rs256),
        ..Default::default()
    };
    assert!(
        plugin
            .sign_with_options(Map::new(), &unconfigured, &ctx)
            .await
            .is_err()
    );
    let missing = JwtSigningOptions {
        key_id: Some("missing".into()),
        ..Default::default()
    };
    assert!(
        plugin
            .sign_with_options(Map::new(), &missing, &ctx)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn concurrent_signing_retains_verifiable_keys_and_pins_never_replace_expired_keys() {
    let ctx = create_test_context().await;
    let plugin = JwtPlugin::new();
    let payload: Map<String, Value> = serde_json::from_value(json!({"sub": "owner"})).unwrap();
    let (first, second) = tokio::join!(
        plugin.sign(payload.clone(), &ctx),
        plugin.sign(payload.clone(), &ctx)
    );
    for token in [first.unwrap(), second.unwrap()] {
        assert!(plugin.verify(&token, None, &ctx).await.unwrap().is_some());
        let mut parts: Vec<_> = token.split('.').map(str::to_owned).collect();
        let replacement = if parts[2].starts_with('A') { "B" } else { "A" };
        parts[2].replace_range(..1, replacement);
        assert!(
            plugin
                .verify(&parts.join("."), None, &ctx)
                .await
                .unwrap()
                .is_none()
        );
        parts[0] = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"alg": "HS256", "kid": header(&token)["kid"]})).unwrap(),
        );
        assert!(
            plugin
                .verify(&parts.join("."), None, &ctx)
                .await
                .unwrap()
                .is_none()
        );
    }
    let expired = JwtPlugin::new()
        .rotation_interval(Duration::seconds(-1))
        .create_key_pair(JwtKeyPairConfig::new(JwtAlgorithm::EdDsa), &ctx)
        .await
        .unwrap();
    let count = ctx.database.list_jwks().await.unwrap().len();
    assert!(
        plugin
            .sign_with_options(
                payload,
                &JwtSigningOptions {
                    key_id: Some(expired.id),
                    ..Default::default()
                },
                &ctx
            )
            .await
            .is_err()
    );
    assert_eq!(ctx.database.list_jwks().await.unwrap().len(), count);
}

#[tokio::test]
async fn callbacks_receive_the_complete_session_and_custom_signing_options() {
    let ctx = create_test_context().await;
    let plugin = JwtPlugin::new()
        .remote_url("http://localhost/remote-jwks".into())
        .define_payload(Arc::new(|session| {
            Box::pin(async move {
                assert_eq!(session["session"]["token"], "session-token");
                Ok(serde_json::from_value(
                    json!({"sessionId": session["session"]["id"], "iat": 123}),
                )
                .unwrap())
            })
        }))
        .get_subject(Arc::new(|session| {
            Box::pin(async move { Ok(session["session"]["userId"].as_str().unwrap().to_owned()) })
        }))
        .custom_sign(Arc::new(|payload, options| {
            Box::pin(async move {
                assert!(options.key_id.is_none());
                Ok(serde_json::to_string(&payload)?)
            })
        }));
    let claims: Value = serde_json::from_str(&plugin.sign_session(json!({"user": {"id": "owner"}, "session": {"id": "sid", "userId": "owner", "token": "session-token"}}), &ctx).await.unwrap()).unwrap();
    assert_eq!(claims["sub"], "owner");
    assert_eq!(claims["sessionId"], "sid");
    assert_eq!(claims["iat"], 123);
    assert_eq!(claims["exp"], 1023);
    assert_eq!(claims["iss"], ctx.config.base_url);
}

#[tokio::test]
async fn cookie_signer_is_purpose_bound_and_cache_survives_store_revocation() {
    use crate::plugins::test_helpers::{
        create_test_config, create_test_context_with_config, create_user_and_session,
    };
    use better_auth_core::{
        CreateUser,
        config::{CookieCacheConfig, CookieCacheStrategy},
        session::{SessionCookieSigner, SessionData, SessionRead},
    };
    let mut config = create_test_config();
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        strategy: Some(CookieCacheStrategy::Jwt),
        ..Default::default()
    });
    let mut ctx = create_test_context_with_config(config).await;
    let plugin = JwtPlugin::new()
        .session_cookie_cache(true)
        .issuer("token-issuer".into())
        .audience("token-audience".into());
    let mut init = AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
    plugin.on_init(&mut init).await.unwrap();
    let runtime = init.runtime();
    ctx.extensions = init.extensions;
    let ctx = Arc::new(ctx);
    runtime.bind(&ctx).unwrap();
    let (user, session) = create_user_and_session(
        &ctx,
        CreateUser::new()
            .with_email("cache@example.com")
            .with_name("Cache"),
        Duration::hours(1),
    )
    .await;
    let data = SessionData { user, session };
    let manager = ctx.session_manager();
    let request = AuthRequest::new(HttpMethod::Get, "/get-session");
    manager.write_cache(&request, &data, false).await.unwrap();
    let headers = request.take_response_headers().unwrap();
    let cookie = headers
        .get_all("set-cookie")
        .next()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let cache_token = cookie.split_once('=').unwrap().1;
    assert_eq!(header(cache_token)["typ"], "better-auth.session-cache+jwt");
    let signer = ctx
        .extensions
        .get::<Arc<
            dyn SessionCookieSigner<
                better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema,
            >,
        >>()
        .unwrap();
    let signing_context = || better_auth_core::session::SessionCookieContext {
        request: &request,
        config: &ctx.config,
        transaction: None,
    };
    let claims = signer
        .verify(cache_token, signing_context())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claims["iss"], ctx.config.base_url);
    assert_eq!(claims["aud"], "better-auth:session-cache");
    assert!(
        plugin
            .verify(cache_token, None, &ctx)
            .await
            .unwrap()
            .is_none()
    );
    let ordinary = plugin.sign(claims.clone(), &ctx).await.unwrap();
    assert!(
        signer
            .verify(&ordinary, signing_context())
            .await
            .unwrap()
            .is_none()
    );
    let options = JwtSigningOptions {
        header: serde_json::from_value(json!({"typ": "better-auth.session-cache+jwt"})).unwrap(),
        ..Default::default()
    };
    for (field, value) in [
        ("sub", json!("wrong")),
        ("sid", json!("wrong")),
        ("iss", json!("wrong")),
        ("aud", json!("wrong")),
        ("exp", json!(1)),
    ] {
        let mut invalid = claims.clone();
        invalid.insert(field.into(), value);
        let token = plugin
            .sign_with_options(invalid, &options, &ctx)
            .await
            .unwrap();
        assert!(
            signer
                .verify(&token, signing_context())
                .await
                .unwrap()
                .is_none(),
            "{field}"
        );
    }
    ctx.database
        .delete_session(&data.session.token)
        .await
        .unwrap();
    let mut cached = AuthRequest::new(HttpMethod::Get, "/get-session");
    cached.headers.insert(
        "cookie".into(),
        format!(
            "{}={}; {cookie}",
            ctx.config.session.cookie_name,
            better_auth_core::utils::cookie_utils::sign_cookie_value(
                &data.session.token,
                &ctx.config.secret
            )
        ),
    );
    assert_eq!(
        manager
            .resolve(&cached, SessionRead::Cached)
            .await
            .unwrap()
            .data
            .unwrap()
            .session
            .id,
        data.session.id
    );
    assert!(
        manager
            .resolve(&cached, SessionRead::Authoritative)
            .await
            .unwrap()
            .data
            .is_none()
    );
}

#[tokio::test]
async fn expired_signing_keys_rotate_and_public_grace_does_not_reactivate_them() {
    let ctx = create_test_context().await;
    let plugin = JwtPlugin::new()
        .rotation_interval(Duration::seconds(-1))
        .grace_period(Duration::minutes(1));
    let first = plugin.sign(Map::new(), &ctx).await.unwrap();
    let second = plugin.sign(Map::new(), &ctx).await.unwrap();
    assert_ne!(header(&first)["kid"], header(&second)["kid"]);
    let stored = ctx.database.list_jwks().await.unwrap();
    assert_eq!(stored.len(), 2);
    for key in &stored {
        assert!(
            serde_json::from_str::<Value>(&key.private_key)
                .unwrap()
                .is_string()
        );
        assert!(
            serde_json::from_str::<Value>(&key.public_key)
                .unwrap()
                .get("d")
                .is_none()
        );
    }
    let discovery: Value = serde_json::from_slice(&plugin.jwks(&ctx).await.unwrap().body).unwrap();
    assert_eq!(discovery["keys"].as_array().unwrap().len(), 2);
    let expired: Value = serde_json::from_slice(
        &JwtPlugin::new()
            .grace_period(Duration::zero())
            .jwks(&ctx)
            .await
            .unwrap()
            .body,
    )
    .unwrap();
    assert_eq!(expired["keys"], json!([]));
    let current = JwtPlugin::new().sign(Map::new(), &ctx).await.unwrap();
    let reused = JwtPlugin::new().sign(Map::new(), &ctx).await.unwrap();
    assert_eq!(header(&current)["kid"], header(&reused)["kid"]);
    assert_ne!(header(&current)["kid"], header(&second)["kid"]);
    let defaults = JwtPlugin::new()
        .sign(
            serde_json::from_value(json!({ "iss": null, "aud": null, "exp": null })).unwrap(),
            &ctx,
        )
        .await
        .unwrap();
    let payload: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(defaults.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(payload["iss"], ctx.config.base_url);
    assert_eq!(payload["aud"], ctx.config.base_url);
    assert!(payload["exp"].as_i64().unwrap() > Utc::now().timestamp());
    assert!(payload.get("iat").is_none());
}
