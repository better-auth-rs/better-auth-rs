//! # Better Auth Core
//!
//! Core abstractions for the Better Auth authentication framework.
//! Contains traits, types, configuration, and error handling.

#![cfg_attr(
    test,
    allow(
        unused_results,
        unreachable_pub,
        reason = "test code intentionally discards setup return values and exposes helpers broadly"
    )
)]

pub mod config;
pub mod email;
pub mod entity;
pub mod error;
pub mod extractors;
pub mod hooks;
pub mod middleware;
pub mod openapi;
pub mod plugin;
pub mod session;
pub mod store;
pub mod types;
pub mod types_impls;
pub mod types_org;
pub mod utils;

// Re-export commonly used items
pub use better_auth_macros::PluginConfig;
pub use config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, Argon2Config,
    AuthConfig, CookieAttributes, CookieCacheConfig, CookieCacheStrategy, CookieOverride,
    CrossSubDomainConfig, IpAddressConfig, JwtConfig, OAuthStateStrategy, PasswordConfig, SameSite,
    SessionConfig, core_paths, extract_origin,
};
pub use email::{ConsoleEmailProvider, EmailProvider};
pub use entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
    AuthSession, AuthTwoFactor, AuthUser, AuthVerification, MemberUserView, PASSWORD_HASH_KEY,
};
pub use error::{
    AuthError, AuthResult, DatabaseError, validate_request_body, validation_error_response,
};
#[cfg(feature = "axum")]
pub use extractors::{
    AdminRole, AdminSession, AuthRequestExt, AxumAuthResponse, CurrentSession, OptionalSession,
    Pending2faToken, ValidatedJson,
};
pub use hooks::{
    DatabaseHookContext, DatabaseHooks, HookControl, RequestHookContext, with_request_hook_context,
    with_request_hook_context_value,
};
pub use middleware::{
    BodyLimitConfig, BodyLimitMiddleware, CorsConfig, CorsMiddleware, CsrfConfig, CsrfMiddleware,
    EndpointRateLimit, Middleware, RateLimitConfig, RateLimitMiddleware,
};
pub use openapi::{OpenApiBuilder, OpenApiInfo, OpenApiOperation, OpenApiResponse, OpenApiSpec};
#[cfg(feature = "axum")]
pub use plugin::AxumPlugin;
pub use plugin::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRoute, AuthState, BeforeRequestAction,
};
pub use sea_orm;
pub use session::SessionManager;
pub use store::{AuthMigrator, AuthStore, CacheAdapter, MemoryCacheAdapter, run_migrations};
pub use types::{
    Account, ApiKey, AuthRequest, AuthResponse, CodeMessageResponse, CreateAccount, CreateApiKey,
    CreateInvitation, CreateMember, CreateOrganization, CreatePasskey, CreateSession,
    CreateTwoFactor, CreateUser, CreateVerification, ErrorCodeMessageResponse,
    ErrorMessageResponse, Headers, HealthCheckResponse, HttpMethod, Invitation, InvitationStatus,
    ListUsersParams, Member, OkResponse, Organization, Passkey, RateLimitErrorResponse,
    RequestMeta, Session, StatusMessageResponse, StatusResponse, SuccessMessageResponse,
    SuccessResponse, TwoFactor, UpdateAccount, UpdateApiKey, UpdateOrganization, UpdatePasskey,
    UpdateUser, UpdateUserRequest, UpdateUserResponse, User, ValidationErrorResponse, Verification,
};
pub use utils::password::{PasswordHasher, hash_password, verify_password};
