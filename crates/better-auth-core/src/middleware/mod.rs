pub mod body_limit;
pub mod cors;
pub mod csrf;
pub mod rate_limit;

use crate::error::AuthResult;
use crate::types::{AuthRequest, AuthResponse};
use async_trait::async_trait;

/// Middleware trait for request/response processing.
///
/// Middleware runs before plugin dispatch (`before_request`) and after
/// a response has been produced (`after_request`).
#[async_trait]
pub trait Middleware: Send + Sync {
    /// Human-readable name for logging / debugging.
    fn name(&self) -> &'static str;

    /// Called before the request is dispatched to plugins.
    ///
    /// Return `Ok(Some(response))` to short-circuit (e.g. block the request).
    /// Return `Ok(None)` to continue processing.
    async fn before_request(&self, req: &AuthRequest) -> AuthResult<Option<AuthResponse>>;

    /// Called after a response has been produced.
    ///
    /// Allows the middleware to mutate the response (e.g. add CORS headers).
    /// The default implementation is a no-op pass-through.
    async fn after_request(
        &self,
        _req: &AuthRequest,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        Ok(response)
    }
}

/// Run a middleware chain on a request.
///
/// Returns `Ok(Some(response))` if any middleware short-circuits, otherwise `Ok(None)`.
pub async fn run_before(
    middlewares: &[Box<dyn Middleware>],
    req: &AuthRequest,
) -> AuthResult<Option<AuthResponse>> {
    for mw in middlewares {
        if let Some(response) = mw.before_request(req).await? {
            return Ok(Some(response));
        }
    }
    Ok(None)
}

/// Run the after-request middleware chain, applying each middleware in reverse order.
pub async fn run_after(
    middlewares: &[Box<dyn Middleware>],
    req: &AuthRequest,
    mut response: AuthResponse,
) -> AuthResult<AuthResponse> {
    for mw in middlewares.iter().rev() {
        response = mw.after_request(req, response).await?;
    }
    Ok(response)
}

pub use body_limit::{BodyLimitConfig, BodyLimitMiddleware};
pub use cors::{CorsConfig, CorsMiddleware};
pub use csrf::{CsrfConfig, CsrfMiddleware};
pub use rate_limit::{EndpointRateLimit, RateLimitConfig, RateLimitMiddleware};
