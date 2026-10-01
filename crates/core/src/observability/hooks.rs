use crate::{AuthContext, AuthRequest, AuthResponse, AuthResult, AuthSchema, BeforeRequestAction};
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait BeforeEndpointHook<S: AuthSchema>: Send + Sync {
    async fn before(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>>;
}
#[async_trait]
pub trait AfterEndpointHook<S: AuthSchema>: Send + Sync {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        context: &AuthContext<S>,
    ) -> AuthResult<()>;
}

/// Global user hooks run before plugin hooks of the same phase.
pub struct EndpointHooks<S: AuthSchema> {
    pub before: Option<Arc<dyn BeforeEndpointHook<S>>>,
    pub after: Option<Arc<dyn AfterEndpointHook<S>>>,
}
impl<S: AuthSchema> Default for EndpointHooks<S> {
    fn default() -> Self {
        Self {
            before: None,
            after: None,
        }
    }
}
