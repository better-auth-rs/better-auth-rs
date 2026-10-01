//! Configuration types beyond the root `AuthConfig` entrypoint.

pub use better_auth_core::config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, ApiErrorConfig,
    Argon2Config, BearerConfig, CookieAttributes, CookieCacheConfig, CookieCacheRefresh,
    CookieCacheStrategy, CookieCacheVersion, CookieCacheVersionCallback, CookieOverride,
    CrossSubDomainConfig, ErrorPageColors, ErrorPageCustomization, ErrorPageFont, ErrorPageSize,
    FieldTransforms, IpAddressConfig, JwtConfig, OAuthStateStrategy, PasswordConfig, SameSite,
    SecretKey, SessionConfig, SessionFieldConfig, UserConfig, UserFieldConfig, UserFieldReference,
    UserFieldTransform, UserFieldType, UserFieldValidator, VersionedSecret, core_paths,
    extract_origin,
};

pub use better_auth_core::config::{
    VerificationConfig, VerificationIdentifierConfig, VerificationIdentifierHasher,
    VerificationIdentifierStorage,
};

pub use better_auth_core::api_error::{ApiErrorHandler, ApiErrorTask};
pub use better_auth_core::id::{IdGeneration, IdGenerationRequest, IdGenerator};

pub use better_auth_core::background::{BackgroundFuture, BackgroundTask, BackgroundTasks};
