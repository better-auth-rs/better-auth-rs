use async_trait::async_trait;
use better_auth::{BetterAuth, plugins::OpenApiPlugin};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, RateLimitConfig,
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
    fields: UserConfig,
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for RuntimeDevice {
    fn name(&self) -> &'static str {
        "ordinary-runtime-device"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    fn schema(
        &self,
        context: &mut better_auth_core::plugin_runtime::ModelFields,
    ) -> AuthResult<()> {
        context.register_model_fields(EntityRole::DeviceCode, self.fields.clone())
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
    fields: UserConfig,
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for ExplicitPasskey {
    fn name(&self) -> &'static str {
        "ordinary-explicit-passkey"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    fn schema(
        &self,
        context: &mut better_auth_core::plugin_runtime::ModelFields,
    ) -> AuthResult<()> {
        context.register_model_fields(EntityRole::Passkey, self.fields.clone())
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
    for default_empty in [false, true] {
        let empty = if default_empty {
            UserConfig::default()
        } else {
            fields(None)
        };
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
            config.logger = better_auth_core::LoggerConfig {
                disabled: Some(true),
                ..Default::default()
            }
            .into();
            config.telemetry.enabled = false;
            let builder =
                BetterAuth::stateless(config).rate_limit(RateLimitConfig::new().enabled(false));
            let builder = match name {
                "empty-runtime" => builder.plugin(RuntimeDevice {
                    fields: empty.clone(),
                }),
                "empty-explicit" => builder.plugin(ExplicitPasskey {
                    fields: empty.clone(),
                }),
                "runtime-before-explicit" => builder
                    .plugin(RuntimeDevice {
                        fields: fields(Some("label")),
                    })
                    .plugin(ExplicitPasskey {
                        fields: fields(Some("name")),
                    }),
                _ => builder
                    .plugin(ExplicitPasskey {
                        fields: fields(Some("name")),
                    })
                    .plugin(RuntimeDevice {
                        fields: fields(Some("label")),
                    }),
            };
            let auth = builder.plugin(OpenApiPlugin::new()).build().await?;
            let document = auth.openapi_spec()?.to_value()?;
            let schemas = document
                .pointer("/components/schemas")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    AuthError::internal("Expected the complete generated component map")
                })?;
            let model_keys: Vec<_> = schemas.keys().collect();
            cases.push(json!({ "name": name, "schemas": schemas, "modelKeys": model_keys }));
        }
        assert_eq!(
            json!({ "version": "1.7.6", "cases": cases }),
            expected,
            "default_empty={default_empty}"
        );
    }
    Ok(())
}
