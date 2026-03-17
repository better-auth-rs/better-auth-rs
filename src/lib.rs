//! # Better Auth - Rust
//!
//! A comprehensive authentication framework for Rust, inspired by Better-Auth.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use better_auth::{run_migrations, AuthConfig, BetterAuth};
//! use better_auth::plugins::EmailPasswordPlugin;
//! use better_auth::store::Database;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = AuthConfig::new("your-secret-key-that-is-at-least-32-chars");
//!     let database = Database::connect("sqlite::memory:").await?;
//!     run_migrations(&database).await?;
//!
//!     let auth = BetterAuth::new(config)
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

mod core;
#[cfg(feature = "axum")]
mod handlers;

pub mod config;
pub mod email;
pub mod error;
pub mod hooks;
pub mod integrations;
pub mod middleware;
pub mod plugin;
pub mod plugins;
pub mod prelude;
pub mod store;

pub use better_auth_core::store::run_migrations;
pub use better_auth_core::{AuthConfig, AuthError, AuthResult};
pub use core::{AuthBuilder, BetterAuth};
