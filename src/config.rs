//! Configuration types beyond the root `AuthConfig` entrypoint.

pub use better_auth_core::config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, Argon2Config,
    CookieAttributes, CookieCacheConfig, CookieCacheStrategy, CookieOverride, CrossSubDomainConfig,
    IpAddressConfig, JwtConfig, OAuthStateStrategy, PasswordConfig, SameSite, SessionConfig,
    core_paths, extract_origin,
};
