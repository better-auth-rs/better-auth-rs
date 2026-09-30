use crate::AuthResult;
use serde_json::{Map, Value};

/// Runtime boundary for plugins that sign and verify session cookie caches.
#[async_trait::async_trait]
pub trait SessionCookieSigner: Send + Sync {
    /// Sign cache claims with the supplied lifetime in seconds.
    async fn sign(&self, payload: Map<String, Value>, expires_in: i64) -> AuthResult<String>;
    /// Return verified cache claims, or `None` for an invalid token.
    async fn verify(&self, token: &str) -> AuthResult<Option<Map<String, Value>>>;
}
