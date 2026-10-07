use std::sync::Arc;

use async_trait::async_trait;
use better_auth::{BetterAuth, plugins::OpenApiPlugin};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse,
    AuthResult, AuthRoute, AuthSchema, OpenApiPluginMetadata, RateLimitConfig,
    store::{SecondaryStorage, schema::EntityRole},
    user_fields::{UserConfig, UserFieldConfig},
};
use serde_json::{Value, json};

fn plugin_fields() -> UserConfig {
    UserConfig {
        additional_fields: Some(
            [(
                "label".into(),
                UserFieldConfig {
                    required: Some(true),
                    field_name: Some("stored_label".into()),
                    ..Default::default()
                },
            )]
            .into_iter()
            .collect(),
        ),
    }
}

struct VerificationDisplay;

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for VerificationDisplay {
    fn name(&self) -> &'static str {
        "ordinary-verification-display"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    fn openapi(&self) -> AuthResult<OpenApiPluginMetadata> {
        Ok(
            OpenApiPluginMetadata::from_routes("ordinary-verification-display", Vec::new())?
                .model("verification", &plugin_fields())?,
        )
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(EntityRole::Verification, plugin_fields())
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

struct UnusedSecondaryStorage;

#[async_trait]
impl SecondaryStorage for UnusedSecondaryStorage {
    async fn get(&self, _: &str) -> AuthResult<Option<Value>> {
        Err(AuthError::internal(
            "OpenAPI schema generation must not access secondary storage",
        ))
    }

    async fn set(&self, _: &str, _: &str, _: Option<u64>) -> AuthResult<()> {
        Err(AuthError::internal(
            "OpenAPI schema generation must not access secondary storage",
        ))
    }

    async fn delete(&self, _: &str) -> AuthResult<()> {
        Err(AuthError::internal(
            "OpenAPI schema generation must not access secondary storage",
        ))
    }

    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<Value>> {
        Err(AuthError::internal(
            "OpenAPI schema generation must not access secondary storage",
        ))
    }
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The test propagates setup errors and compares complete captured component maps and model-key arrays."
)]
async fn verification_component_follows_final_storage_configuration()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let expected: Value = serde_json::from_str(include_str!(
        "fixtures/openapi-verification-model-1.7.6.json"
    ))?;
    let mut cases = Vec::new();
    for name in ["no-secondary", "secondary-only", "secondary-database"] {
        let mut config =
            AuthConfig::new("ordinary-openapi-verification-model-secret-at-least-32-characters")
                .base_url("http://openapi-verification-model.test");
        config.logger.disabled = Some(true);
        config.telemetry.enabled = false;
        config.verification.store_in_database = name == "secondary-database";
        config.verification.additional_fields = [(
            "caption".into(),
            UserFieldConfig {
                required: Some(false),
                field_name: Some("stored_caption".into()),
                default_value: Some(json!("application caption")),
                ..Default::default()
            },
        )]
        .into_iter()
        .collect();
        let builder = BetterAuth::stateless(config)
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(VerificationDisplay)
            .plugin(OpenApiPlugin::new());
        let builder = if name == "no-secondary" {
            builder
        } else {
            builder.secondary_storage(Arc::new(UnusedSecondaryStorage))
        };
        let auth = builder.build().await?;
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
