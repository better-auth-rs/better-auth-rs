//! Storage-related database handles, migrations, cache adapters, and advanced
//! SeaORM re-exports.

pub use better_auth_core::sea_orm::{Database, DatabaseConnection};
#[cfg(feature = "redis-cache")]
pub use better_auth_core::store::RedisAdapter;
pub use better_auth_core::store::{AuthMigrator, CacheAdapter, MemoryCacheAdapter};

/// Advanced SeaORM re-exports for applications that need lower-level traits
/// and query types.
pub mod sea_orm {
    pub use better_auth_core::sea_orm::*;
}
