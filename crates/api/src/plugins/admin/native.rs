use super::{AdminConfig, AdminPlugin, AdminUserResponse, CreateAdminUser};
use better_auth_core::{
    AuthContext, AuthError, AuthResult, AuthRoute, AuthSchema, NativeRequest, wire::UserView,
};
use std::collections::HashMap;

/// Administrator operations bound to the registered plugin configuration.
/// Dynamic URL policy resolves supplied host headers or the configured fallback before any writes.
pub struct AdminApi<'a, S: AuthSchema> {
    plugin: AdminPlugin,
    context: &'a AuthContext<S>,
}
impl<'a, S: AuthSchema> AdminApi<'a, S> {
    pub fn from_context(context: &'a AuthContext<S>) -> AuthResult<Self> {
        let config = context
            .extensions
            .get::<AdminConfig>()
            .ok_or_else(|| AuthError::config("AdminPlugin is not registered"))?;
        Ok(Self {
            plugin: AdminPlugin::with_config(config.clone()),
            context,
        })
    }

    /// Omit headers only for trusted server provisioning. Any supplied headers require a session.
    /// Run endpoint hooks and return the final native User fields after response hooks.
    pub async fn create_user(
        &self,
        body: &CreateAdminUser,
        headers: Option<&HashMap<String, String>>,
    ) -> AuthResult<AdminUserResponse<UserView>> {
        let response = self
            .context
            .dispatch_native(
                NativeRequest {
                    request: None,
                    headers,
                },
                AuthRoute::post("/admin/create-user", "createUser")
                    .body_validator(super::request::validate),
                Some(serde_json::to_value(body)?),
                None,
                |request, context| async move {
                    self.plugin.handle_create_user(&request, &context).await
                },
            )
            .await?;
        let result = response.body.field_value()?;
        let user = result.model_property("user")?.as_object().ok_or_else(|| {
            AuthError::internal("Admin create-user response must contain a user object")
        })?;
        Ok(AdminUserResponse {
            user: UserView::try_from(user.clone())?,
        })
    }
}

#[cfg(test)]
mod tests;
