//! # Better Auth Core
//!
//! Core abstractions for the Better Auth authentication framework.
//! Contains traits, types, configuration, and error handling.

pub mod adapters;
pub mod config;
pub mod email;
pub mod entity;
pub mod error;
pub mod hooks;
pub mod middleware;
pub mod openapi;
pub mod plugin;
pub mod session;
pub mod types;
pub mod types_impls;
pub mod types_org;

// Re-export derive macros when the `derive` feature is enabled
#[cfg(feature = "derive")]
pub use better_auth_derive::*;

// Re-export commonly used items
pub use adapters::{
    AccountOps, ApiKeyOps, CacheAdapter, DatabaseAdapter, InvitationOps, MemberOps, MemoryAccount,
    MemoryApiKey, MemoryCacheAdapter, MemoryDatabaseAdapter, MemoryInvitation, MemoryMember,
    MemoryOrganization, MemoryPasskey, MemorySession, MemoryTwoFactor, MemoryUser,
    MemoryVerification, OrganizationOps, PasskeyOps, SessionOps, TwoFactorOps, UserOps,
    VerificationOps,
};
#[cfg(feature = "sqlx-postgres")]
pub use adapters::{SqlxAdapter, SqlxEntity};
pub use config::{Argon2Config, AuthConfig, JwtConfig, PasswordConfig, SameSite, SessionConfig};
pub use email::{ConsoleEmailProvider, EmailProvider};
pub use entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
    AuthSession, AuthTwoFactor, AuthUser, AuthVerification, MemberUserView,
};
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
    Account, ApiKey, AuthRequest, AuthResponse, CodeMessageResponse, CreateAccount, CreateApiKey,
    CreateInvitation, CreateMember, CreateOrganization, CreatePasskey, CreateSession,
    CreateTwoFactor, CreateUser, CreateVerification, DeleteUserResponse, ErrorMessageResponse,
    HealthCheckResponse, HttpMethod, Invitation, InvitationStatus, OkResponse, Passkey,
    RateLimitErrorResponse, Session, StatusMessageResponse, StatusResponse, TwoFactor,
    UpdateAccount, UpdateApiKey, UpdateOrganization, UpdatePasskey, UpdateUser, UpdateUserRequest,
    UpdateUserResponse, User, ValidationErrorResponse, Verification,
};
