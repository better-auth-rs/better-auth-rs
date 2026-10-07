use async_trait::async_trait;
use better_auth::{BetterAuth, plugins::OpenApiPlugin};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, OpenApiPluginMetadata, RateLimitConfig,
    middleware::RateLimitStorageKind,
    user_fields::{UserConfig, UserFieldConfig},
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct RateLimitModel {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for RateLimitModel {
    fn name(&self) -> &'static str {
        "ordinary-rate-limit-model"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    fn openapi(&self) -> AuthResult<OpenApiPluginMetadata> {
        let ordinary = UserConfig {
            additional_fields: Some(
                [(
                    "label".into(),
                    UserFieldConfig {
                        required: Some(true),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        };
        let calls = self.calls.clone();
        let declared = UserConfig {
            additional_fields: Some(
                [
                    (
                        "count".into(),
                        UserFieldConfig {
                            required: Some(false),
                            default_value: Some("plugin-count".into()),
                            ..Default::default()
                        },
                    ),
                    (
                        "label".into(),
                        UserFieldConfig {
                            required: Some(true),
                            input: Some(false),
                            default_value_fn: Some(Arc::new(move || {
                                let _ = calls.fetch_add(1, Ordering::SeqCst);
                                Ok("plugin-label".into())
                            })),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        };
        Ok(
            OpenApiPluginMetadata::from_routes("ordinary-rate-limit-model", Vec::new())?
                .model("beforeRateLimit", &ordinary)?
                .model("rateLimit", &declared)?
                .model("afterRateLimit", &ordinary)?,
        )
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Err(AuthError::internal(
            "Schema generation must not execute request handlers",
        ))
    }
}

#[tokio::test]
async fn database_rate_limit_metadata_matches_upstream_replacement_and_order()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let expected: Value = serde_json::from_str(&std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/openapi-rate-limit-model-1.7.6.json"
    ))?)?;
    let mut cases = Vec::new();
    for (storage, kind) in [
        ("database", RateLimitStorageKind::Database),
        ("memory", RateLimitStorageKind::Memory),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut config =
            AuthConfig::new("ordinary-openapi-rate-limit-model-secret-at-least-32-characters")
                .base_url("http://openapi-rate-limit-model.test");
        config.logger.disabled = Some(true);
        config.telemetry.enabled = false;
        let auth = BetterAuth::stateless(config)
            .rate_limit(RateLimitConfig::new().enabled(false).storage(kind))
            .plugin(RateLimitModel {
                calls: calls.clone(),
            })
            .plugin(OpenApiPlugin::new())
            .build()
            .await?;
        let document = auth.openapi_spec()?.to_value()?;
        let components = document
            .get("components")
            .ok_or_else(|| AuthError::internal("Expected the complete OpenAPI components"))?;
        let schemas = components
            .get("schemas")
            .and_then(Value::as_object)
            .ok_or_else(|| AuthError::internal("Expected the component model map"))?;
        let properties = schemas
            .get("RateLimit")
            .and_then(|model| model.get("properties"))
            .and_then(Value::as_object)
            .ok_or_else(|| {
                AuthError::internal("The declared RateLimit model must be documented")
            })?;
        let callback_calls = calls.load(Ordering::SeqCst);
        if callback_calls != 0 {
            return Err(AuthError::internal(
                "Schema generation must not execute model field defaults",
            )
            .into());
        }
        cases.push(json!({
            "storage": storage, "components": components,
            "modelKeys": schemas.keys().collect::<Vec<_>>(),
            "rateLimitPropertyKeys": properties.keys().collect::<Vec<_>>(),
            "callbackCalls": callback_calls,
        }));
    }
    let actual = json!({ "version": "1.7.6", "cases": cases });
    if actual != expected {
        return Err(AuthError::internal(format!(
            "RateLimit model contract differs: actual {actual}; expected {expected}"
        ))
        .into());
    }
    Ok(())
}
