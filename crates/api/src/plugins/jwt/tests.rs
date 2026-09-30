use super::*;
use crate::plugins::test_helpers::create_test_context;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

fn header(token: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap()
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
