//! # Better Auth Core
//!
//! Core abstractions for the Better Auth authentication framework.
//! Contains traits, types, configuration, and error handling.

pub mod adapters;
pub mod config;
pub mod email;
pub mod error;
pub mod hooks;
pub mod middleware;
pub mod openapi;
pub mod plugin;
pub mod session;
pub mod types;

// Re-export commonly used items
pub use adapters::{CacheAdapter, DatabaseAdapter, MemoryCacheAdapter, MemoryDatabaseAdapter};
pub use config::{Argon2Config, AuthConfig, JwtConfig, PasswordConfig, SameSite, SessionConfig};
pub use email::{ConsoleEmailProvider, EmailProvider};
pub use error::{
    AuthError, AuthResult, DatabaseError, validate_request_body, validation_error_response,
};
pub use hooks::{DatabaseHooks, HookedDatabaseAdapter};
pub use middleware::{
    BodyLimitConfig, BodyLimitMiddleware, CorsConfig, CorsMiddleware, CsrfConfig, CsrfMiddleware,
    EndpointRateLimit, Middleware, RateLimitConfig, RateLimitMiddleware,
};
pub use openapi::{OpenApiBuilder, OpenApiInfo, OpenApiOperation, OpenApiResponse, OpenApiSpec};
pub use plugin::{AuthContext, AuthPlugin, AuthRoute};
pub use session::SessionManager;
pub use types::{
    Account, AuthRequest, AuthResponse, CreateAccount, CreateSession, CreateUser,
    CreateVerification, DeleteUserResponse, HttpMethod, Passkey, Session, TwoFactor, UpdateUser,
    UpdateUserRequest, UpdateUserResponse, User, Verification,
};
