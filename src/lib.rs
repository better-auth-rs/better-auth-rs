//! # Better Auth - Rust
//!
//! A comprehensive authentication framework for Rust, inspired by Better-Auth.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use better_auth::{run_migrations, sea_orm::Database, AuthBuilder, AuthConfig};
//! use better_auth::plugins::EmailPasswordPlugin;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = AuthConfig::new("your-secret-key-that-is-at-least-32-chars");
//!     let database = Database::connect("sqlite::memory:").await?;
//!     run_migrations(&database).await?;
//!
//!     let auth = AuthBuilder::new(config)
//!         .database(database)
//!         .plugin(EmailPasswordPlugin::new())
//!         .build()
//!         .await?;
//!
//!     Ok(())
//! }
//! ```

#![cfg_attr(
    test,
    allow(
        unused_results,
        unreachable_pub,
        reason = "test code intentionally discards setup return values and exposes helpers broadly"
    )
)]

// Core module — BetterAuth struct lives here in the root crate
// because it orchestrates plugins (from better-auth-api) + core (from better-auth-core)
pub mod core;
pub mod handlers;

// Re-export core abstractions
pub use better_auth_core as types_mod;
pub use better_auth_core::AuthStore;
pub use better_auth_core::sea_orm;
pub use better_auth_core::{
    Account, Argon2Config, AuthConfig, AuthContext, AuthError, AuthInitContext, AuthMigrator,
    AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, BodyLimitConfig,
    BodyLimitMiddleware, CacheAdapter, ConsoleEmailProvider, CookieCacheConfig,
    CookieCacheStrategy, CorsConfig, CorsMiddleware, CreateAccount, CreateInvitation, CreateMember,
    CreateOrganization, CreatePasskey, CreateSession, CreateUser, CreateVerification, CsrfConfig,
    CsrfMiddleware, DatabaseError, DatabaseHookContext, DatabaseHooks, EmailProvider,
    EndpointRateLimit, HookControl, HttpMethod, Invitation, InvitationStatus, JwtConfig, Member,
    MemoryCacheAdapter, Middleware, OAuthStateStrategy, OpenApiBuilder, OpenApiSpec, Organization,
    Passkey, PasswordConfig, RateLimitConfig, RateLimitMiddleware, RequestHookContext, SameSite,
    Session, SessionConfig, SessionManager, TwoFactor, UpdateOrganization, UpdatePasskey,
    UpdateUser, UpdateUserRequest, UpdateUserResponse, User, Verification, core_paths,
    run_migrations, with_request_hook_context_value,
};

// Re-export entity traits
pub use better_auth_core::entity::{
    AuthAccount, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey, AuthSession,
    AuthTwoFactor, AuthUser, AuthVerification, MemberUserView,
};

// Re-export types under `types` module for backwards compatibility
pub mod types {
    pub use better_auth_core::{
        Account, AuthRequest, AuthResponse, CreateAccount, CreateInvitation, CreateMember,
        CreateOrganization, CreatePasskey, CreateSession, CreateUser, CreateVerification,
        HttpMethod, Invitation, InvitationStatus, Member, Organization, Passkey, Session,
        TwoFactor, UpdateOrganization, UpdatePasskey, UpdateUser, UpdateUserRequest,
        UpdateUserResponse, User, Verification,
    };
}

// Re-export plugins
pub mod plugins {
    pub use better_auth_api::plugins::*;
    pub use better_auth_api::*;
}

// Re-export the main BetterAuth struct
pub use core::{AuthBuilder, BetterAuth};

#[cfg(feature = "axum")]
pub use handlers::axum::{AxumIntegration, CurrentSession, OptionalSession};
