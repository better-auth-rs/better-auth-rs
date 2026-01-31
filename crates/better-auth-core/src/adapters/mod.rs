pub mod cache;
pub mod database;

pub use cache::{CacheAdapter, MemoryCacheAdapter};
pub use database::{DatabaseAdapter, MemoryDatabaseAdapter};

#[cfg(feature = "sqlx-postgres")]
pub use database::sqlx_adapter::{PoolConfig, PoolStats, SqlxAdapter};

#[cfg(feature = "redis-cache")]
pub use cache::RedisAdapter;
