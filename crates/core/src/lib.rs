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

mod api_key_start;
pub use api_key_start::{ApiKeyStart, Utf16String};

pub mod api_error;
pub mod background;
pub mod config;
pub mod email;
pub mod entity;
pub mod error;
mod error_codes;
pub mod field_value;
pub use field_value::{
    FieldDate, FieldFunction, FieldMap, FieldObject, FieldValue, StructuredCloneContext,
};
pub mod hooks;
pub mod id;
pub mod middleware;
pub mod observability;
pub use observability::{
    ExperimentalConfig, InstrumentationConfig, LogArgument, LogLevel, LogSink, LoggerConfig,
    TelemetryConfig,
};
mod memory_sort;
pub mod openapi;
pub mod plugin;
pub mod plugin_runtime;
pub mod query;
pub mod request_runtime;
pub use request_runtime::{
    BaseUrl, BaseUrlProtocol, DynamicBaseUrl, NativeRequest, TrustedValues, TrustedValuesResolver,
};
mod response_body;
mod runtime_extensions;
pub use response_body::{ResponseBlob, ResponseBody};
pub mod schema;
pub mod session;
pub mod store;
#[cfg(test)]
pub(crate) mod test_store;
pub mod types;
mod types_account;
mod types_jwt;
pub use runtime_extensions::RuntimeExtensions;
mod types_org;
mod types_team;
pub use types_team::{
    CreateOrganizationRole, CreateTeam, OrganizationRole, Team, TeamMember, UpdateOrganizationRole,
    UpdateTeam,
};
mod types_plugin;
pub use types_jwt::{CreateJwk, Jwk};
pub mod organization_fields;
pub mod schema_value;
pub mod user_fields;
pub use schema_value::{SchemaField, SchemaValue};
#[doc(hidden)]
pub mod user_query;
pub mod utils;
pub mod wire;

// Re-export commonly used items
#[doc(hidden)]
pub use async_trait as __private_async_trait;
pub use better_auth_macros::{AuthSchema, PluginConfig, database_hooks};
pub use config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, Argon2Config,
    AuthConfig, BearerConfig, CookieAttributes, CookieCacheConfig, CookieCacheStrategy,
    CookieOverride, CrossSubDomainConfig, IpAddressConfig, JwtConfig, OAuthStateStrategy,
    PasswordConfig, SameSite, SecretKey, SessionConfig, SessionFieldConfig, VersionedSecret,
    core_paths, extract_origin,
};
pub use email::{ConsoleEmailProvider, EmailProvider};
pub use entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
    AuthRecordFields, AuthSession, AuthTwoFactor, AuthUser, AuthVerification, FromFieldMap,
    MemberUserView,
};
pub use error::{
    AuthError, AuthResult, DatabaseError, validate_request_body, validation_error_response,
};
pub use hooks::{RequestHookContext, with_request_hook_context, with_request_hook_context_value};
pub use middleware::{
    BodyLimitConfig, BodyLimitMiddleware, CorsConfig, CorsMiddleware, CsrfConfig, CsrfMiddleware,
    CustomRateLimitRule, EndpointRateLimit, Middleware, PluginRateLimit, RateLimitConfig,
    RateLimitDecision, RateLimitMiddleware, RateLimitOverride, RateLimitRuleResolver,
    RateLimitStorage, RateLimitStorageKind,
};
pub use openapi::{
    OpenApiBuilder, OpenApiInfo, OpenApiPluginMetadata, OpenApiRegistry, OpenApiRouteMetadata,
    OpenApiSpec,
};
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
    CreateSession, CreateTwoFactor, CreateUser, CreateVerification, CreateWalletAddress,
    DeviceCode, DeviceCodeOwnership, DeviceCodeWhere, ErrorCodeMessageResponse,
    ErrorMessageResponse, Headers, HealthCheckResponse, HttpMethod, Invitation, InvitationStatus,
    ListUsersParams, Member, NativeResponseStatus, OkResponse, Organization, Passkey,
    PasskeyCredentialState, PasskeyStorage, RateLimitErrorResponse, RequestMeta,
    StatusMessageResponse, StatusResponse, SuccessMessageResponse, SuccessResponse, TwoFactor,
    TwoFactorStorage, UpdateAccount, UpdateApiKey, UpdateDeviceCode, UpdateOrganization,
    UpdatePasskey, UpdatePasskeyAuthentication, UpdateTwoFactor, UpdateUser, UpdateUserRequest,
    UpdateUserResponse, ValidationErrorResponse, WalletAddress, WhereMode, WhereOperator,
};
pub use utils::password::{
    Argon2PasswordHasher, PasswordHasher, ScryptPasswordHasher, hash_password, verify_password,
};
#[doc(hidden)]
pub use uuid;
pub use wire::{
    AccountView, ApiKeyView, InvitationView, OrganizationView, PasskeyView, SessionView, UserView,
    VerificationView,
};

#[doc(hidden)]
pub use crate as __private_core;

pub mod endpoint_dispatch;
pub mod endpoint_input;
mod http_body;
