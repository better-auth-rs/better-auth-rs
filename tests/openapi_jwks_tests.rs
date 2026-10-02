use better_auth::{
    __private_core::{AuthRequest, HttpMethod, RateLimitConfig},
    AuthConfig, BetterAuth,
    plugins::{JwtPlugin, OpenApiPlugin},
};
use serde_json::{Value, json};

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "the test propagates setup failures and asserts the pinned OpenAPI contract"
)]
async fn configured_jwks_paths_preserve_the_pinned_openapi_operation()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let expected: Value = serde_json::from_str(include_str!("fixtures/openapi-jwks-1.7.6.json"))?;
    let mut cases = Vec::new();
    for name in ["default", "renamed", "disabled"] {
        let path = if name == "default" { "/jwks" } else { "/keys" };
        let mut config =
            AuthConfig::new("ordinary-openapi-jwks-secret-at-least-thirty-two-characters")
                .base_url("https://openapi-jwks.example.test");
        config.logger.disabled = Some(true);
        if name == "disabled" {
            config.disabled_paths.push(path.into());
        }
        let jwt = if name == "default" {
            JwtPlugin::new()
        } else {
            JwtPlugin::new().jwks_path(path)
        };
        let auth = BetterAuth::stateless(config)
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(jwt)
            .plugin(OpenApiPlugin::new())
            .build()
            .await?;
        let response = auth
            .handle_request(AuthRequest::new(
                HttpMethod::Get,
                "/api/auth/open-api/generate-schema",
            ))
            .await?;
        let schema: Value = serde_json::from_slice(&response.body)?;
        let paths = schema
            .get("paths")
            .and_then(Value::as_object)
            .ok_or("OpenAPI schema must contain a paths object")?;
        cases.push(json!({
            "name": name,
            "status": response.status,
            "defaultPathPresent": paths.contains_key("/jwks"),
            "renamedPathPresent": paths.contains_key("/keys"),
            "operation": paths.get(path).and_then(|item| item.get("get")).unwrap_or(&Value::Null),
        }));
    }
    assert_eq!(json!({ "version": "1.7.6", "cases": cases }), expected);
    Ok(())
}
