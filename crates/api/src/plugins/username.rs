//! Username login with endpoint, database-hook and adapter policies.

use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::user_fields::{UserConfig, UserFieldConfig};
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, AuthUser, BeforeRequestAction, HttpMethod,
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
        let _ = fields.additional_fields.insert(
            "username".into(),
            UserFieldConfig {
                required: Some(false),
                field_name: config.username_field_name.clone(),
                input_transform: Some(Arc::new(move |value| match value {
                    Some(Value::String(value)) => {
                        config.normalize(&value).map(|value| Some(value.into()))
                    }
                    value => Ok(value),
                })),
                ..Default::default()
            },
        );
        if self.config.display_username {
            let config = self.config.clone();
            let _ = fields.additional_fields.insert(
                "displayUsername".into(),
                UserFieldConfig {
                    required: Some(false),
                    field_name: config.display_username_field_name.clone(),
                    input_transform: Some(Arc::new(move |value| match value {
                        Some(Value::String(value)) => config
                            .normalize_display(&value)
                            .map(|value| Some(value.into())),
                        value => Ok(value),
                    })),
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
            AuthRoute::post("/sign-in/username", "sign_in_username"),
            AuthRoute::post("/is-username-available", "is_username_available"),
        ]
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
