//! Storage-related types, migrations, cache adapters, and the SeaORM re-export.

pub use better_auth_core::sea_orm;
#[cfg(feature = "redis-cache")]
pub use better_auth_core::store::RedisAdapter;
pub use better_auth_core::store::{AuthMigrator, AuthStore, CacheAdapter, MemoryCacheAdapter};
