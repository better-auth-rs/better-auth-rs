//! Middleware traits and configuration types.

pub use better_auth_core::middleware::{
    BodyLimitConfig, BodyLimitMiddleware, CorsConfig, CorsMiddleware, CsrfConfig, CsrfMiddleware,
    CustomRateLimitRule, EndpointRateLimit, Middleware, PluginRateLimit, RateLimitConfig,
    RateLimitDecision, RateLimitMiddleware, RateLimitOverride, RateLimitRuleResolver,
    RateLimitStorage, RateLimitStorageKind,
};
