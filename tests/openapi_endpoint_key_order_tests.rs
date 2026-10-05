use async_trait::async_trait;
use better_auth::{BetterAuth, plugins::OpenApiPlugin};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, OpenApiRouteMetadata, RateLimitConfig,
};
use serde_json::{Map, Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const ENDPOINT_KEYS: [&str; 6] = ["tail", "10", "2", "01", "4294967294", "4294967295"];
const PREFIX: &str = "/ordinary-endpoint-order/";

struct EndpointOrder {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for EndpointOrder {
    fn name(&self) -> &'static str {
        "ordinary-endpoint-order"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        ENDPOINT_KEYS
            .into_iter()
            .map(|key| {
                let metadata = OpenApiRouteMetadata {
                    operation_id: Some("ordinaryDisplay".into()),
                    description: Some(format!("Display endpoint {key}")),
                    responses: Map::from_iter([(
                        "200".into(),
                        json!({
                            "description": "Ordinary display response",
                            "content": { "application/json": { "schema": {
                                "type": "object", "properties": { "label": { "type": "string" } },
                                "required": ["label"],
                            } } },
                        }),
                    )]),
                    ..Default::default()
                };
                AuthRoute::get(format!("{PREFIX}{key}"), key)
                    .endpoint_key(key)
                    .openapi(metadata)
            })
            .collect()
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let _ = self.calls.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::internal(
            "Schema generation executed an endpoint handler",
        ))
    }
}

#[tokio::test]
async fn endpoint_keys_match_upstream_paths_operations_and_duplicate_ids()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let expected: Value = serde_json::from_str(&std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/openapi-endpoint-key-order-1.7.6.json"
    ))?)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut config =
        AuthConfig::new("ordinary-openapi-endpoint-key-order-secret-at-least-32-characters")
            .base_url("http://openapi-endpoint-key-order.test");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    let auth = BetterAuth::stateless(config)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(EndpointOrder {
            calls: calls.clone(),
        })
        .plugin(OpenApiPlugin::new())
        .build()
        .await?;
    let document = auth.openapi_spec()?.to_value()?;
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| AuthError::internal("Expected the complete OpenAPI paths"))?;
    let operations: Map<String, Value> = paths
        .iter()
        .filter(|(path, _)| path.starts_with(PREFIX))
        .map(|(path, methods)| (path.clone(), methods.clone()))
        .collect();
    if operations.len() != ENDPOINT_KEYS.len() {
        return Err(AuthError::internal("Every declared endpoint must be documented").into());
    }
    let operation_ids: Vec<Value> = operations
        .iter()
        .map(|(path, methods)| {
            let id = methods
                .get("get")
                .and_then(|operation| operation.get("operationId"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AuthError::internal(format!("Expected a GET operation ID at {path}"))
                })?;
            Ok(json!({ "path": path, "method": "get", "operationId": id }))
        })
        .collect::<AuthResult<_>>()?;
    let callback_calls = calls.load(Ordering::SeqCst);
    if callback_calls != 0 {
        return Err(
            AuthError::internal("Schema generation must not execute endpoint handlers").into(),
        );
    }
    let actual = json!({
        "version": "1.7.6", "endpointKeys": ENDPOINT_KEYS,
        "pathKeys": paths.keys().collect::<Vec<_>>(), "operations": operations,
        "operationIds": operation_ids, "callbackCalls": callback_calls,
    });
    if actual != expected {
        return Err(AuthError::internal(format!(
            "Endpoint key-order contract differs: actual {actual}; expected {expected}"
        ))
        .into());
    }
    Ok(())
}
