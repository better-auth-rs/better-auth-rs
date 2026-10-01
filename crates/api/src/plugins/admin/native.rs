use super::{AdminConfig, AdminPlugin, AdminUserResponse, CreateAdminUser, MESSAGE_CREATE_USERS};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, HttpMethod,
    wire::UserView,
};
use std::collections::HashMap;

/// Administrator operations bound to the registered plugin configuration.
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
    pub async fn create_user(
        &self,
        body: &CreateAdminUser,
        headers: Option<&HashMap<String, String>>,
    ) -> AuthResult<AdminUserResponse<UserView>> {
        let mut request = AuthRequest::new(HttpMethod::Post, "/admin/create-user");
        if let Some(headers) = headers {
            request.headers = headers.clone();
        }
        let mut hook_context = better_auth_core::RequestHookContext::from_request(&request);
        hook_context.body = Some(serde_json::to_value(body)?);
        better_auth_core::with_request_hook_context_value(hook_context, async {
            let session = if headers.is_some() {
                let session = self
                    .context
                    .require_authoritative_session(&request)
                    .await
                    .map_err(|error| match error {
                        AuthError::Unauthenticated => AuthError::from(AuthResponse::new(401)),
                        error => error,
                    })?;
                self.plugin
                    .authorize(&session.0, "user", "create", MESSAGE_CREATE_USERS)?;
                Some(session)
            } else {
                None
            };
            super::handlers::create_user_core(
                body,
                None,
                session,
                &self.plugin.config,
                self.context,
            )
            .await
        })
        .await
    }
}
