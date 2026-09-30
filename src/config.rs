//! Configuration types beyond the root `AuthConfig` entrypoint.

pub use better_auth_core::config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, Argon2Config,
    BearerConfig, CookieAttributes, CookieCacheConfig, CookieCacheStrategy, CookieCacheVersion,
    CookieCacheVersionCallback, CookieOverride, CrossSubDomainConfig, IpAddressConfig, JwtConfig,
    OAuthStateStrategy, PasswordConfig, SameSite, SessionConfig, SessionFieldConfig, UserConfig,
    UserFieldConfig, UserFieldTransform, UserFieldType, UserFieldValidator, core_paths,
    extract_origin,
};

pub use better_auth_core::config::{
    VerificationConfig, VerificationIdentifierConfig, VerificationIdentifierHasher,
    VerificationIdentifierStorage,
};
