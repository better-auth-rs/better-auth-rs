//! Username login with endpoint, database-hook and adapter policies.
use better_auth_core::user_fields::{FieldTransforms, UserFieldTransform};

use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::user_fields::{UserConfig, UserFieldConfig};
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, AuthUser, BeforeRequestAction, FieldValue, HttpMethod,
};
use serde_json::Value;

mod config;
mod endpoint_hooks;
mod endpoints;
mod hooks;
pub(crate) mod request;
pub use config::{
    UsernameConfig, UsernameNormalization, UsernameNormalizer, UsernameValidationOrder,
    UsernameValidator,
};

/// Install username fields, validation, availability and password login endpoints.
#[derive(Clone, Default)]
pub struct UsernamePlugin {
    config: UsernameConfig,
}

impl UsernamePlugin {
    /// Construct the plugin with explicit options.
    pub fn new(config: UsernameConfig) -> Self {
        Self { config }
    }

    fn fields(&self) -> UserConfig {
        let mut fields = UserConfig::default();
        let config = self.config.clone();
        let _ = fields.fields_mut().insert(
            "username".into(),
            UserFieldConfig {
                required: Some(false),
                field_name: config.username_field_name.clone(),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| match value {
                        FieldValue::String(value) => config.normalize(&value).map(Into::into),
                        value => Ok(value),
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        if self.config.display_username {
            let config = self.config.clone();
            let _ = fields.fields_mut().insert(
                "displayUsername".into(),
                UserFieldConfig {
                    required: Some(false),
                    field_name: config.display_username_field_name.clone(),
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(move |value| match value {
                            FieldValue::String(value) => {
                                config.normalize_display(&value).map(Into::into)
                            }
                            value => Ok(value),
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        }
        fields
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for UsernamePlugin {
    fn name(&self) -> &'static str {
        "username"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/sign-in/username", "signInUsername")
                .body_validator(request::sign_in_body),
            AuthRoute::post("/is-username-available", "isUsernameAvailable")
                .body_validator(request::availability_body),
        ]
    }
    fn openapi(&self) -> AuthResult<better_auth_core::openapi::OpenApiPluginMetadata> {
        let mut metadata = better_auth_core::openapi::OpenApiPluginMetadata::from_routes(
            <Self as better_auth_core::AuthPlugin<S>>::name(self),
            <Self as better_auth_core::AuthPlugin<S>>::routes(self),
        )?
        .model("user", &self.fields())?;
        if !self.config.display_username {
            metadata = metadata.remove_field("user", "displayUsername");
        }
        Ok(metadata)
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        let required = if self.config.display_username {
            &["username", "display_username"][..]
        } else {
            &["username"][..]
        };
        S::User::require_plugin_fields("username", required)?;
        context.set_metadata("username.enabled", Value::Bool(true));
        context.set_metadata(
            "username.display.enabled",
            Value::Bool(self.config.display_username),
        );
        context.extensions.insert(self.config.clone());
        context.register_user_fields(self.fields());
        context.register_database_hook(Arc::new(hooks::UsernameHooks {
            config: self.config.clone(),
            runtime: context.runtime(),
        }));
        Ok(())
    }
    async fn before_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.before_endpoint(request, context).await
    }
    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (request.method(), request.path()) {
            (HttpMethod::Post, "/sign-in/username") => {
                self.sign_in(request, context).await.map(Some)
            }
            (HttpMethod::Post, "/is-username-available") => {
                self.available(request, context).await.map(Some)
            }
            _ => Ok(None),
        }
    }
}
