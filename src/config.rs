//! Configuration types beyond the root `AuthConfig` entrypoint.

pub use better_auth_core::config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, Argon2Config,
    BearerConfig, CookieAttributes, CookieCacheConfig, CookieCacheRefresh, CookieCacheStrategy,
    CookieCacheVersion, CookieCacheVersionCallback, CookieOverride, CrossSubDomainConfig,
    IpAddressConfig, JwtConfig, OAuthStateStrategy, PasswordConfig, SameSite, SecretKey,
    SessionConfig, SessionFieldConfig, UserConfig, UserFieldConfig, UserFieldReference,
    UserFieldTransform, UserFieldType, UserFieldValidator, VersionedSecret, core_paths,
    extract_origin,
};

pub use better_auth_core::config::{
    VerificationConfig, VerificationIdentifierConfig, VerificationIdentifierHasher,
    VerificationIdentifierStorage,
};
