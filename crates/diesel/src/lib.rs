//! Diesel integration for Better Auth.
//!
//! [`DieselStore`] persists the Better Auth tables through
//! [`diesel-async`](diesel_async) connection pools. PostgreSQL and SQLite are
//! supported through the `postgres` and `sqlite` features.
//!
//! The table definitions live in [`schema`] and the row types in [`models`].
//! Apply the SQL migrations in [`migrations`] with the rest of the
//! application schema.

#[cfg(not(any(feature = "postgres", feature = "sqlite")))]
compile_error!("better-auth-diesel needs at least one backend feature: `postgres` or `sqlite`");

mod connection;
mod error;
pub mod hooks;
pub mod migrations;
pub mod models;
pub mod schema;
pub mod sql_types;
pub mod store;

#[cfg(feature = "sqlite")]
pub use connection::AsyncSqliteConnection;
pub use connection::{DieselConnection, DieselPool};
pub use hooks::{DieselHookContext, DieselHooks, HookControl, current_request_hook_context};
pub use store::{DieselAuthSchema, DieselStore};

pub use diesel;
pub use diesel_async;
pub use diesel_migrations;
