//! Middleware traits and configuration types.

pub use better_auth_core::middleware::{
    BodyLimitConfig, BodyLimitMiddleware, CorsConfig, CorsMiddleware, CsrfConfig, CsrfMiddleware,
    EndpointRateLimit, Middleware, RateLimitConfig, RateLimitMiddleware,
};
