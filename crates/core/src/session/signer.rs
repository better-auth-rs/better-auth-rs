use crate::{AuthConfig, AuthRequest, AuthResult, AuthSchema, store::AuthTransaction};
use serde_json::{Map, Value};

/// The active request and storage transaction for a session-cache signature.
pub struct SessionCookieContext<'a, S: AuthSchema> {
    pub request: &'a AuthRequest,
    pub config: &'a AuthConfig,
    /// Read and create signing keys through this transaction when present.
    pub transaction: Option<&'a dyn AuthTransaction<S>>,
}

/// Runtime boundary for plugins that sign and verify session cookie caches.
#[async_trait::async_trait]
pub trait SessionCookieSigner<S: AuthSchema>: Send + Sync {
    /// Sign cache claims with the lifetime in seconds, preserving fractional seconds.
    async fn sign(
        &self,
        payload: Map<String, Value>,
        expires_in: f64,
        context: SessionCookieContext<'_, S>,
    ) -> AuthResult<String>;
    /// Return verified cache claims, or `None` for an invalid token.
    async fn verify(
        &self,
        token: &str,
        context: SessionCookieContext<'_, S>,
    ) -> AuthResult<Option<Map<String, Value>>>;
}
