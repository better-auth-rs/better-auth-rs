//! SQL migrations for the Better Auth tables.
//!
//! The migrations are standard Diesel migration directories under
//! `migrations/postgres` and `migrations/sqlite` in this crate. The host
//! application owns when they run. Either copy the directory for your backend
//! into the application's `migrations` directory, or run the embedded set
//! with a Diesel migration harness next to the application migrations:
//!
//! ```rust,ignore
//! use better_auth_diesel::diesel_async::AsyncMigrationHarness;
//! use better_auth_diesel::diesel_migrations::MigrationHarness;
//!
//! let mut harness = AsyncMigrationHarness::new(connection);
//! harness.run_pending_migrations(better_auth_diesel::migrations::POSTGRES)?;
//! ```

use diesel_migrations::{EmbeddedMigrations, embed_migrations};

/// Migrations for PostgreSQL.
#[cfg(feature = "postgres")]
pub const POSTGRES: EmbeddedMigrations = embed_migrations!("migrations/postgres");

/// Migrations for SQLite.
#[cfg(feature = "sqlite")]
pub const SQLITE: EmbeddedMigrations = embed_migrations!("migrations/sqlite");
