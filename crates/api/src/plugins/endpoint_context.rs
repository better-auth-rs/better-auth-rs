//! Typed endpoint context for application callbacks.

use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, BeforeRequestAction,
};
use serde_json::Value;
use std::sync::Arc;

/// The parsed endpoint input and the active authentication runtime.
pub struct EndpointContext<'a, S: AuthSchema> {
    /// Original HTTP request, when the call originates from HTTP.
    pub request: Option<&'a AuthRequest>,
    /// Endpoint path, including synthetic dispatch from another endpoint.
    pub path: Option<&'a str>,
    /// Input after endpoint validation and unknown-field filtering.
    pub body: Value,
    /// Full typed runtime, including the store, options, metadata, and extensions.
    pub auth: &'a AuthContext<S>,
    /// Session already resolved by this endpoint before the callback.
    pub session: Option<(
        better_auth_core::wire::UserView,
        better_auth_core::wire::SessionView,
    )>,
    /// Completed response when the callback runs from an after hook.
    pub response: Option<&'a AuthResponse>,
}
impl<'a, S: AuthSchema> EndpointContext<'a, S> {
    pub(crate) fn new(
        request: Option<&'a AuthRequest>,
        body: Value,
        auth: &'a AuthContext<S>,
    ) -> Self {
        Self {
            request,
            path: request.map(AuthRequest::path),
            body,
            auth,
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
    fn routes(&self) -> Vec<AuthRoute> {
        self.plugin.routes()
    }
    fn rate_limits(
        &self,
    ) -> AuthResult<Vec<(String, better_auth_core::middleware::EndpointRateLimit)>> {
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
