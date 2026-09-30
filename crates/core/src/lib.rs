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

extern crate self as better_auth;

pub mod config;
pub mod email;
pub mod entity;
pub mod error;
mod error_codes;
pub mod hooks;
pub mod middleware;
pub mod openapi;
pub mod plugin;
mod runtime_extensions;
pub mod schema;
pub mod session;
pub mod store;
#[cfg(test)]
pub(crate) mod test_store;
pub mod types;
mod types_jwt;
pub use runtime_extensions::RuntimeExtensions;
mod types_org;
mod types_team;
pub use types_team::{
    CreateOrganizationRole, CreateTeam, OrganizationRole, Team, TeamMember, UpdateOrganizationRole,
};
mod types_plugin;
pub use types_jwt::{CreateJwk, Jwk};
pub mod user_fields;
#[doc(hidden)]
pub mod user_query;
pub mod utils;
pub mod wire;

// Re-export commonly used items
pub use better_auth_macros::{AuthSchema, PluginConfig};
pub use config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, Argon2Config,
    AuthConfig, BearerConfig, CookieAttributes, CookieCacheConfig, CookieCacheStrategy,
    CookieOverride, CrossSubDomainConfig, IpAddressConfig, JwtConfig, OAuthStateStrategy,
    PasswordConfig, SameSite, SessionConfig, SessionFieldConfig, core_paths, extract_origin,
};
pub use email::{ConsoleEmailProvider, EmailProvider};
pub use entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
    AuthSession, AuthTwoFactor, AuthUser, AuthVerification, MemberUserView,
};
pub use error::{
    AuthError, AuthResult, DatabaseError, validate_request_body, validation_error_response,
};
pub use hooks::{RequestHookContext, with_request_hook_context, with_request_hook_context_value};
pub use middleware::{
    BodyLimitConfig, BodyLimitMiddleware, CorsConfig, CorsMiddleware, CsrfConfig, CsrfMiddleware,
    EndpointRateLimit, Middleware, RateLimitConfig, RateLimitMiddleware,
};
pub use openapi::{OpenApiBuilder, OpenApiInfo, OpenApiOperation, OpenApiResponse, OpenApiSpec};
pub use plugin::{AuthContext, AuthInitContext, AuthPlugin, AuthRoute, BeforeRequestAction};
pub use schema::AuthSchema;
#[doc(hidden)]
pub use serde_json;
pub use session::SessionManager;
pub use store::{
    AuthStore, AuthTransaction, CacheAdapter, ConsumeApiKeyResult, MemoryCacheAdapter, transaction,
};
pub use types::{
    ApiKey, AuthRequest, AuthResponse, CodeMessageResponse, CreateAccount, CreateApiKey,
    CreateDeviceCode, CreateInvitation, CreateMember, CreateOrganization, CreatePasskey,
    CreateSession, CreateTwoFactor, CreateUser, CreateVerification, DeviceCode,
    ErrorCodeMessageResponse, ErrorMessageResponse, Headers, HealthCheckResponse, HttpMethod,
    Invitation, InvitationStatus, ListUsersParams, Member, OkResponse, Organization, Passkey,
    RateLimitErrorResponse, RequestMeta, StatusMessageResponse, StatusResponse,
    SuccessMessageResponse, SuccessResponse, TwoFactor, UpdateAccount, UpdateApiKey,
    UpdateDeviceCode, UpdateOrganization, UpdatePasskey, UpdateTwoFactor, UpdateUser,
    UpdateUserRequest, UpdateUserResponse, ValidationErrorResponse,
};
pub use utils::password::{PasswordHasher, hash_password, verify_password};
#[doc(hidden)]
pub use uuid;
pub use wire::{
    AccountView, ApiKeyView, InvitationView, OrganizationView, PasskeyView, SessionView, UserView,
    VerificationView,
};

#[doc(hidden)]
pub use crate as __private_core;
