//! # Better Auth - Rust
//!
//! A comprehensive authentication framework for Rust, inspired by Better-Auth.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use better_auth::{AuthConfig, AuthSchema, BetterAuth};
//! use better_auth::plugins::EmailPasswordPlugin;
//! use better_auth::seaorm::{Database, SeaOrmStore};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = AuthConfig::new("your-secret-key-that-is-at-least-32-chars");
//!     let database = Database::connect("sqlite::memory:").await?;
//!     let store = SeaOrmStore::<AppAuthSchema>::new(config.clone(), database);
//!
//!     let auth = BetterAuth::<AppAuthSchema>::new(config)
//!         .store(store)
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

extern crate self as better_auth;

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
pub mod schema;
#[cfg(feature = "seaorm2")]
pub mod seaorm;
pub mod store;
pub mod wire;

pub use better_auth_core::{AuthConfig, AuthError, AuthResult, AuthSchema};
pub use core::{AuthBuilder, BetterAuth};

#[doc(hidden)]
pub use better_auth_core as __private_core;
