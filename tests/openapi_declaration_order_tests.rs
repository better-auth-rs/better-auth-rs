use async_trait::async_trait;
use better_auth::{
    BetterAuth,
    plugins::{DeviceAuthorizationPlugin, OpenApiPlugin},
};
use better_auth_core::{
    AuthConfig, AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, RateLimitConfig,
    store::schema::EntityRole,
    user_fields::{UserConfig, UserFieldConfig},
};
use serde_json::{Value, json};

struct DisplayField;

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for DisplayField {
    fn name(&self) -> &'static str {
        "ordinary-openapi-declaration-order"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(
            EntityRole::DeviceCode,
            UserConfig {
                additional_fields: Some(
                    [(
                        "label".into(),
                        UserFieldConfig {
                            required: Some(true),
                            field_name: Some("stored_label".into()),
                            default_value: Some(json!("display-label")),
                            ..Default::default()
                        },
                    )]
                    .into_iter()
                    .collect(),
                ),
            },
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
    reason = "The test propagates setup errors and compares complete captured OpenAPI components."
)]
async fn registered_fields_retain_their_plugin_declaration_position()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let expected: Value = serde_json::from_str(include_str!(
        "fixtures/openapi-declaration-order-1.7.6.json"
    ))?;
    let mut cases = Vec::new();
    for name in ["custom-before-device", "device-before-custom"] {
        let mut config =
            AuthConfig::new("ordinary-openapi-declaration-order-secret-at-least-32-characters")
                .base_url("http://openapi-declaration-order.test");
        config.logger.disabled = Some(true);
        config.telemetry.enabled = false;
        let builder =
            BetterAuth::stateless(config).rate_limit(RateLimitConfig::new().enabled(false));
        let builder = if name == "custom-before-device" {
            builder
                .plugin(DisplayField)
                .plugin(DeviceAuthorizationPlugin::new())
        } else {
            builder
                .plugin(DeviceAuthorizationPlugin::new())
                .plugin(DisplayField)
        };
        let auth = builder.plugin(OpenApiPlugin::new()).build().await?;
        let document = auth.openapi_spec()?.to_value()?;
        let component = document
            .pointer("/components/schemas/DeviceCode")
            .ok_or("The DeviceCode component must be present")?;
        cases.push(json!({ "name": name, "component": component }));
    }
    assert_eq!(json!({ "version": "1.7.6", "cases": cases }), expected);
    Ok(())
}
