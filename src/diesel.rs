//! Diesel integration re-exports, gated behind the `diesel-postgres` and
//! `diesel-sqlite` features.

#[cfg(feature = "diesel-sqlite")]
pub use better_auth_diesel::AsyncSqliteConnection;
pub use better_auth_diesel::{
    DieselAuthSchema, DieselConnection, DieselHookContext, DieselHooks, DieselPool, DieselStore,
    HookControl, current_request_hook_context, diesel, diesel_async, diesel_migrations, migrations,
    models, schema, sql_types, with_connection,
};
