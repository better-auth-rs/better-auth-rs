use async_trait::async_trait;
use better_auth::{BetterAuth, plugins::OpenApiPlugin};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse,
    AuthResult, AuthRoute, AuthSchema, OpenApiPluginMetadata, RateLimitConfig,
    store::schema::EntityRole,
    user_fields::{UserConfig, UserFieldConfig},
};
use serde_json::{Value, json};

fn fields(name: Option<&str>) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            name.into_iter()
                .map(|name| {
                    (
                        name.into(),
                        UserFieldConfig {
                            required: Some(true),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

struct RuntimeDevice {
    empty: bool,
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for RuntimeDevice {
    fn name(&self) -> &'static str {
        "ordinary-runtime-device"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(
            EntityRole::DeviceCode,
            fields((!self.empty).then_some("label")),
        )
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

struct ExplicitPasskey {
    empty: bool,
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for ExplicitPasskey {
    fn name(&self) -> &'static str {
        "ordinary-explicit-passkey"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    fn openapi(&self) -> AuthResult<OpenApiPluginMetadata> {
        Ok(
            OpenApiPluginMetadata::from_routes("ordinary-explicit-passkey", Vec::new())?
                .model("passkey", &fields((!self.empty).then_some("name")))?,
        )
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The test propagates setup errors and compares complete captured component maps and model-key arrays."
)]
async fn runtime_models_preserve_empty_declarations_and_plugin_order()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/openapi-model-presence-1.7.6.json"))?;
    let mut cases = Vec::new();
    for name in [
        "empty-runtime",
        "runtime-before-explicit",
        "explicit-before-runtime",
        "empty-explicit",
    ] {
        let mut config =
            AuthConfig::new("ordinary-openapi-model-presence-secret-at-least-32-characters")
                .base_url("http://openapi-model-presence.test");
        config.logger.disabled = Some(true);
        config.telemetry.enabled = false;
        let builder =
            BetterAuth::stateless(config).rate_limit(RateLimitConfig::new().enabled(false));
        let builder = match name {
            "empty-runtime" => builder.plugin(RuntimeDevice { empty: true }),
            "empty-explicit" => builder.plugin(ExplicitPasskey { empty: true }),
            "runtime-before-explicit" => builder
                .plugin(RuntimeDevice { empty: false })
                .plugin(ExplicitPasskey { empty: false }),
            _ => builder
                .plugin(ExplicitPasskey { empty: false })
                .plugin(RuntimeDevice { empty: false }),
        };
        let auth = builder.plugin(OpenApiPlugin::new()).build().await?;
        let document = auth.openapi_spec()?.to_value()?;
        let schemas = document
            .pointer("/components/schemas")
            .and_then(Value::as_object)
            .ok_or_else(|| AuthError::internal("Expected the complete generated component map"))?;
        let model_keys: Vec<_> = schemas.keys().collect();
        cases.push(json!({ "name": name, "schemas": schemas, "modelKeys": model_keys }));
    }
    assert_eq!(json!({ "version": "1.7.6", "cases": cases }), expected);
    Ok(())
}
