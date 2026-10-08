#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Native JWT contracts fail immediately when a complete fixture or verified payload is missing."
)]

use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    Jwk as StoredJwk, SchemaValue,
    store::{AuthStore, EphemeralStore, StatelessSchema},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn key(algorithm: JwtAlgorithm) -> AuthResult<StoredJwk> {
    let private = algorithm.generate(2048).map_err(jose_error)?;
    Ok(StoredJwk {
        id: SchemaValue::from_field(17.0.into()),
        public_key: private
            .to_public_key()
            .map_err(jose_error)?
            .to_string()
            .into(),
        private_key: private.to_string().into(),
        created_at: better_auth_core::FieldDate::from(Utc::now()).into(),
        alg: Some(algorithm.name().to_owned()).into(),
        ..Default::default()
    })
}

#[test]
fn native_json_source_preserves_surrogates_without_repairing_invalid_escapes() -> AuthResult<()> {
    let valid = better_auth_core::Utf16String::from_units(vec![34, 0xd800, 34]);
    assert_eq!(
        keys::parse_json(&valid.into())?,
        better_auth_core::Utf16String::from_units(vec![0xd800]).into()
    );
    for source in [
        vec![34, 92, 0xd800, 34],
        vec![0xd800],
        vec![34, 92, 117, 0xd800, 34],
    ] {
        assert!(
            keys::parse_json(&better_auth_core::Utf16String::from_units(source).into()).is_err()
        );
    }
    Ok(())
}

async fn context(
    plugin: &JwtPlugin,
    rows: Vec<StoredJwk>,
) -> AuthResult<(Arc<AuthContext<StatelessSchema>>, Arc<AtomicUsize>)> {
    let mut config = crate::plugins::test_helpers::create_test_config();
    if plugin.config.session_cookie_cache {
        config.session.cookie_cache = Some(better_auth_core::config::CookieCacheConfig {
            enabled: Some(true),
            strategy: Some(better_auth_core::config::CookieCacheStrategy::Jwt),
            ..Default::default()
        });
    }
    let config = Arc::new(config);
    let store: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::new(config.clone()));
    let mut init = AuthInitContext::new(config.clone(), store.clone());
    plugin.on_init(&mut init).await?;
    let runtime = init.runtime();
    let parts = init.into_parts();
    let store = store.with_runtime(config.clone(), parts.database_hooks, parts.plugin_fields)?;
    let mut context = AuthContext::new(config, store);
    context.extensions = parts.extensions;
    let reads = Arc::new(AtomicUsize::new(0));
    let calls = reads.clone();
    context.extensions.insert(Arc::new(
        JwtCallbacks::<StatelessSchema>::default().get_jwks(move |_| {
            let rows = rows.clone();
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(Some(rows)) })
        }),
    ));
    let context = Arc::new(context);
    runtime.bind(&context)?;
    Ok((context, reads))
}

#[tokio::test]
async fn numeric_key_id_signs_and_verifies_without_weakening_header_or_signature_checks()
-> AuthResult<()> {
    let plugin = JwtPlugin::new().disable_private_key_encryption(true);
    let (ctx, _) = context(&plugin, vec![key(JwtAlgorithm::EdDsa)?]).await?;
    let payload = serde_json::from_value(json!({"sub":"owner"}))?;
    let token = plugin.sign(payload, &ctx).await?;
    assert_eq!(tests::header(&token)["kid"], 17.0);
    assert_eq!(
        plugin.verify(&token, None, &ctx).await?.unwrap()["sub"],
        "owner"
    );
    let (body, _) = token.rsplit_once('.').unwrap();
    assert!(
        plugin
            .verify(&format!("{body}.AA"), None, &ctx)
            .await?
            .is_none()
    );
    for header in [
        json!({"crit":["unsupported"],"unsupported":true}),
        json!({"crit":["b64"],"b64":false}),
        json!({"crit":["b64","b64"],"b64":true}),
        json!({"crit":["b64"]}),
    ] {
        let error = plugin
            .sign_with_options(
                Map::new(),
                &JwtSigningOptions {
                    header: serde_json::from_value(header)?,
                    ..Default::default()
                },
                &ctx,
            )
            .await;
        assert!(error.is_err());
    }
    let options = JwtSigningOptions {
        header: serde_json::from_value(json!({"b64":false}))?,
        ..Default::default()
    };
    let token = plugin
        .sign_with_options(
            serde_json::from_value(json!({"sub":"owner"}))?,
            &options,
            &ctx,
        )
        .await?;
    assert!(plugin.verify(&token, None, &ctx).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn unrelated_surrogate_property_names_and_object_kids_retain_adapter_reads() -> AuthResult<()>
{
    use better_auth_core::session::{SessionCookieContext, SessionCookieSigner};
    let plugin = JwtPlugin::new().session_cookie_cache(true);
    let (ctx, reads) = context(&plugin, vec![key(JwtAlgorithm::EdDsa)?]).await?;
    let request = AuthRequest::new(HttpMethod::Get, "/get-session");
    let verifier = ctx
        .extensions
        .get::<Arc<dyn SessionCookieSigner<StatelessSchema>>>()
        .unwrap();
    for source in [
        r#"{"alg":"EdDSA","typ":"better-auth.session-cache+jwt","kid":"missing","\ud800":7}"#,
        r#"{"alg":"EdDSA","typ":"better-auth.session-cache+jwt","kid":{"\ud800":7}}"#,
    ] {
        let token = format!("{}.e30.AA", URL_SAFE_NO_PAD.encode(source));
        let before = reads.load(Ordering::SeqCst);
        assert!(plugin.verify(&token, None, &ctx).await?.is_none());
        assert_eq!(reads.load(Ordering::SeqCst), before + 1);
        assert!(
            verifier
                .verify(
                    &token,
                    SessionCookieContext {
                        request: &request,
                        config: &ctx.config,
                        transaction: None
                    }
                )
                .await?
                .is_none()
        );
        assert_eq!(reads.load(Ordering::SeqCst), before + 2);
    }
    Ok(())
}

#[tokio::test]
async fn discovery_spreads_native_public_payload_and_overwrites_kid_even_when_undefined()
-> AuthResult<()> {
    let plugin = JwtPlugin::new();
    let mut row = key(JwtAlgorithm::EdDsa)?;
    row.alg = SchemaValue::from_field(vec![FieldValue::from("native")].into());
    row.crv = SchemaValue::from_field(12.0.into());
    row.public_key = "{\"alg\":\"public-alg\",\"crv\":null,\"kid\":\"public-id\"}"
        .to_owned()
        .into();
    row.id = SchemaValue::Undefined;
    let mut primitive = row.clone();
    primitive.id = SchemaValue::from_field(19.0.into());
    primitive.public_key = "[\"public-entry\"]".to_owned().into();
    let (ctx, _) = context(&plugin, vec![row, primitive]).await?;
    let response = plugin
        .jwks(&EndpointContext::native(None, None, FieldValue::Null, &ctx))
        .await?;
    let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
    assert_eq!(
        body,
        json!({"keys":[{"alg":"public-alg","crv":null},{"0":"public-entry","alg":["native"],"crv":12,"kid":19}]})
    );
    Ok(())
}

#[tokio::test]
async fn selection_filters_native_algorithm_before_dates_and_defers_single_row_created_at()
-> AuthResult<()> {
    let plugin = JwtPlugin::new().disable_private_key_encryption(true);
    let mut selected = key(JwtAlgorithm::EdDsa)?;
    selected.created_at = SchemaValue::from_field("not-a-date".into());
    selected.expires_at = SchemaValue::from_field("8640000000000000".into());
    let mut skipped = selected.clone();
    skipped.alg = SchemaValue::from_field(vec![FieldValue::from("EdDSA")].into());
    skipped.expires_at = SchemaValue::from_field(
        FieldMap::from([
            ("toString".into(), false.into()),
            ("valueOf".into(), false.into()),
        ])
        .into(),
    );
    let (ctx, reads) = context(&plugin, vec![skipped, selected.clone()]).await?;
    let token = plugin.sign(Map::new(), &ctx).await?;
    assert_eq!(tests::header(&token)["kid"], 17.0);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    let discovery = plugin
        .jwks(&EndpointContext::native(None, None, FieldValue::Null, &ctx))
        .await;
    assert!(
        matches!(discovery, Err(AuthError::Internal(message)) if message == "key.expiresAt.getTime is not a function")
    );
    let mut second = selected.clone();
    second.created_at = better_auth_core::FieldDate::from(Utc::now()).into();
    assert!(keys::latest(vec![selected, second], Some("EdDSA"), "EdDSA").is_err());
    Ok(())
}

#[tokio::test]
async fn native_algorithm_reaches_import_only_after_plain_or_encrypted_json_consumption()
-> AuthResult<()> {
    let mut row = key(JwtAlgorithm::EdDsa)?;
    row.alg = SchemaValue::from_field(vec![FieldValue::from("EdDSA")].into());
    row.crv = SchemaValue::from_field(FieldMap::new().into());
    let plugin = JwtPlugin::new().disable_private_key_encryption(true);
    let (ctx, reads) = context(&plugin, vec![row.clone()]).await?;
    let result = plugin.sign(Map::new(), &ctx).await;
    assert!(
        matches!(result, Err(AuthError::Internal(message)) if message == "Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value")
    );
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    for (private, decrypt_error) in [("invalid-json", false), ("null", true), ("17", true)] {
        row.private_key = private.to_owned().into();
        let plugin = JwtPlugin::new();
        let (ctx, _) = context(&plugin, vec![row.clone()]).await?;
        let error = plugin.sign(Map::new(), &ctx).await.unwrap_err();
        assert_eq!(
            error.to_string().contains("Failed to decrypt private key"),
            decrypt_error
        );
    }
    Ok(())
}

#[tokio::test]
async fn cookie_verification_uses_header_algorithm_only_when_configuration_and_row_omit_algorithm()
-> AuthResult<()> {
    use better_auth_core::session::{SessionCookieContext, SessionCookieSigner};
    let mut row = key(JwtAlgorithm::Es256)?;
    let plugin = JwtPlugin::new()
        .disable_private_key_encryption(true)
        .session_cookie_cache(true);
    let (signing_ctx, _) = context(&plugin, vec![row.clone()]).await?;
    let request = AuthRequest::new(HttpMethod::Get, "/get-session");
    let signer = signing_ctx
        .extensions
        .get::<Arc<dyn SessionCookieSigner<StatelessSchema>>>()
        .unwrap();
    let token = signer
        .sign(
            serde_json::from_value(
                json!({"user":{"id":"owner"},"session":{"token":"session-token"}}),
            )?,
            60.0,
            SessionCookieContext {
                request: &request,
                config: &signing_ctx.config,
                transaction: None,
            },
        )
        .await?;
    row.alg = SchemaValue::Undefined;
    for (configured, accepted) in [(None, true), (Some(JwtAlgorithm::EdDsa), false)] {
        let verify_plugin = JwtPlugin::with_config(JwtPluginConfig {
            algorithm: configured,
            session_cookie_cache: true,
            ..Default::default()
        });
        let (ctx, _) = context(&verify_plugin, vec![row.clone()]).await?;
        let verifier = ctx
            .extensions
            .get::<Arc<dyn SessionCookieSigner<StatelessSchema>>>()
            .unwrap();
        let verified = verifier
            .verify(
                &token,
                SessionCookieContext {
                    request: &request,
                    config: &ctx.config,
                    transaction: None,
                },
            )
            .await?;
        assert_eq!(verified.is_some(), accepted);
        assert!(verify_plugin.verify(&token, None, &ctx).await?.is_none());
    }
    Ok(())
}
