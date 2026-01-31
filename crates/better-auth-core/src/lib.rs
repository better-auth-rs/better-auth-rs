//! # Better Auth Core
//!
//! Core abstractions for the Better Auth authentication framework.
//! Contains traits, types, configuration, and error handling.

pub mod types;
pub mod error;
pub mod config;
pub mod plugin;
pub mod session;
pub mod adapters;
pub mod middleware;
pub mod hooks;
pub mod openapi;

// Re-export commonly used items
pub use config::{AuthConfig, SessionConfig, JwtConfig, PasswordConfig, Argon2Config, SameSite};
pub use plugin::{AuthPlugin, AuthRoute, AuthContext};
pub use session::SessionManager;
pub use error::{AuthError, AuthResult, DatabaseError, validation_error_response, validate_request_body};
pub use types::{
    User, Session, Account, Verification, TwoFactor, Passkey,
    HttpMethod, AuthRequest, AuthResponse,
    CreateUser, UpdateUser, CreateSession, CreateAccount, CreateVerification,
    UpdateUserRequest, UpdateUserResponse, DeleteUserResponse,
};
pub use adapters::{DatabaseAdapter, MemoryDatabaseAdapter, CacheAdapter, MemoryCacheAdapter};
pub use hooks::{DatabaseHooks, HookedDatabaseAdapter};
pub use openapi::{OpenApiSpec, OpenApiBuilder, OpenApiInfo, OpenApiOperation, OpenApiResponse};
pub use middleware::{
    Middleware, CsrfMiddleware, CsrfConfig,
    RateLimitMiddleware, RateLimitConfig, EndpointRateLimit,
    CorsMiddleware, CorsConfig,
    BodyLimitMiddleware, BodyLimitConfig,
};
