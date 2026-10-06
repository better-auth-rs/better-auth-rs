//! Typed endpoint context for application callbacks.

use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, BeforeRequestAction,
};
mod owned;
pub use owned::OwnedEndpointContext;

use serde_json::Value;
use std::sync::Arc;

/// The parsed endpoint input and the active authentication runtime.
pub struct EndpointContext<'a, S: AuthSchema> {
    input_request: Option<&'a AuthRequest>,
    /// Original Request supplied by HTTP transport or an explicit native caller.
    pub request: Option<&'a AuthRequest>,
    /// Endpoint path, including synthetic dispatch from another endpoint.
    pub path: Option<&'a str>,
    /// Values captured from the matched endpoint template.
    pub params: std::collections::HashMap<String, String>,
    /// Input after endpoint validation and unknown-field filtering.
    pub body: Value,
    /// Full typed runtime, including the store, options, metadata, and extensions.
    pub auth: &'a AuthContext<S>,
    /// Active transaction. Use this store for database work inside transactional callbacks.
    pub transaction: Option<&'a dyn better_auth_core::store::AuthTransaction<S>>,
    /// Session already resolved by this endpoint before the callback.
    pub session: Option<(
        better_auth_core::wire::UserView,
        better_auth_core::wire::SessionView,
    )>,
    /// Completed response when the callback runs from an after hook.
    pub response: Option<&'a AuthResponse>,
}
impl<'a, S: AuthSchema> EndpointContext<'a, S> {
    /// Access installed test helpers using this endpoint's active transaction.
    pub fn test(&'a self) -> AuthResult<super::test_utils::TestUtilsApi<'a, S>> {
        super::test_utils::TestUtilsApi::from_endpoint(self)
    }

    /// Supplied endpoint headers, preserving omission for native calls.
    pub fn headers(&self) -> Option<&std::collections::HashMap<String, String>> {
        self.input_request.and_then(AuthRequest::endpoint_headers)
    }

    /// Endpoint query, preserving native omission separately from null and an empty object.
    pub fn query(&self) -> Option<&Value> {
        self.input_request
            .and_then(|request| request.query.as_ref())
    }

    /// Active endpoint input and shared server state, independent of the original Request.
    pub fn input_request(&self) -> Option<&'a AuthRequest> {
        self.input_request
    }

    /// Set a response header without replacing other header names.
    pub fn set_header(&self, name: &str, value: impl Into<String>) -> AuthResult<()> {
        self.input_request
            .ok_or_else(|| {
                better_auth_core::AuthError::internal("Endpoint response is unavailable")
            })?
            .set_response_header(name, value.into())
    }

    /// Append a response header, including another `Set-Cookie` value.
    pub fn append_header(&self, name: &str, value: impl Into<String>) -> AuthResult<()> {
        self.input_request
            .ok_or_else(|| {
                better_auth_core::AuthError::internal("Endpoint response is unavailable")
            })?
            .append_response_header(name, value.into())
    }

    /// Identity supplied to the most recent session-cookie write in this endpoint.
    pub fn new_session(&self) -> AuthResult<Option<better_auth_core::session::SessionData>> {
        self.input_request
            .map(AuthRequest::new_session)
            .transpose()
            .map(Option::flatten)
    }
    /// Use the registered Email OTP plugin within this endpoint's active transaction.
    pub fn email_otp(&self) -> AuthResult<super::email_otp::EmailOtpApi<'a, S>> {
        super::email_otp::EmailOtpApi::from_endpoint(self)
    }

    /// Add organization members within this endpoint's active transaction.
    pub fn organization(&self) -> AuthResult<super::organization::OrganizationApi<'a, S>> {
        super::organization::OrganizationApi::from_endpoint(self)
    }

    /// Consume a phone OTP within this endpoint's active transaction.
    pub fn phone_number(&self) -> AuthResult<super::phone_number::PhoneNumberApi<'a, S>> {
        super::phone_number::PhoneNumberApi::from_endpoint(self)
    }

    /// Use the registered JWT key adapter within this endpoint's active transaction.
    pub fn jwt(&self) -> AuthResult<super::jwt::JwtApi<'a, S>> {
        super::jwt::JwtApi::from_endpoint(self)
    }

    /// Construct a native endpoint without inferring a Request from ambient HTTP activity.
    pub fn native(
        input_request: Option<&'a AuthRequest>,
        original_request: Option<&'a AuthRequest>,
        body: Value,
        auth: &'a AuthContext<S>,
    ) -> Self {
        let mut context = Self::new(input_request, body, auth);
        context.request = original_request;
        context.params.clear();
        context
    }

    /// Construct an endpoint context from its request, validated body, and runtime.
    /// Set `transaction` when the caller executes inside an active database transaction.
    pub fn new(request: Option<&'a AuthRequest>, body: Value, auth: &'a AuthContext<S>) -> Self {
        Self {
            input_request: request,
            request: request.and_then(|request| {
                request.original_request().or_else(|| {
                    better_auth_core::hooks::current_request_hook_context()
                        .is_none_or(|context| context.is_http)
                        .then_some(request)
                })
            }),
            path: request.map(AuthRequest::path),
            params: better_auth_core::hooks::current_request_hook_context()
                .map(|context| context.params)
                .unwrap_or_default(),
            body,
            auth,
            transaction: None,
            session: None,
            response: None,
        }
    }
}

pub(crate) struct WithCallbacks<P, C> {
    pub(crate) plugin: P,
    pub(crate) callbacks: Arc<C>,
}

#[async_trait::async_trait]
impl<S: AuthSchema, P: AuthPlugin<S>, C: Send + Sync + 'static> AuthPlugin<S>
    for WithCallbacks<P, C>
{
    fn name(&self) -> &'static str {
        self.plugin.name()
    }
    fn telemetry_plugin_id(&self) -> Option<&'static str> {
        self.plugin.telemetry_plugin_id()
    }
    fn routes(&self) -> Vec<AuthRoute> {
        self.plugin.routes()
    }
    fn openapi(&self) -> AuthResult<better_auth_core::openapi::OpenApiPluginMetadata> {
        self.plugin.openapi()
    }
    fn password_hasher(&self) -> Option<Arc<dyn better_auth_core::PasswordHasher>> {
        self.plugin.password_hasher()
    }
    fn telemetry(&self, options: &mut better_auth_core::observability::telemetry::PluginTelemetry) {
        self.plugin.telemetry(options);
        let callbacks = self.callbacks.as_ref() as &dyn std::any::Any;
        if callbacks.is::<super::email_verification::EmailVerificationCallbacks<S>>() {
            options.email_verification.send_verification_email = true;
        }
        if callbacks.is::<super::password_management::PasswordManagementCallbacks<S>>() {
            options.email_and_password.send_reset_password = true;
        }
        if let Some(callbacks) =
            callbacks.downcast_ref::<super::user_management::UserManagementCallbacks<S>>()
        {
            options.send_change_email_confirmation |= callbacks.has_confirmation_sender();
        }
        if let Some(callbacks) = callbacks.downcast_ref::<super::oauth::OAuthCallbacks<S>>() {
            for provider in &mut options.social_providers {
                provider.verify_id_token |= callbacks.verifiers.contains_key(&provider.id);
            }
        }
    }
    fn rate_limits(&self) -> AuthResult<Vec<better_auth_core::middleware::PluginRateLimit>> {
        self.plugin.rate_limits()
    }
    async fn on_init(&self, ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        ctx.extensions.insert(self.callbacks.clone());
        self.plugin.on_init(ctx).await
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.plugin.before_request(req, ctx).await
    }
    async fn on_http_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.plugin.on_http_request(req, ctx).await
    }
    async fn on_http_response(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.plugin.on_http_response(req, response, ctx).await
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.plugin.on_request(req, ctx).await
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.plugin.after_request(req, response, ctx).await
    }
}

#[cfg(test)]
mod tests;
