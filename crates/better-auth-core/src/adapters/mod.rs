pub mod database;
pub mod cache;

pub use database::{DatabaseAdapter, MemoryDatabaseAdapter};
pub use cache::{CacheAdapter, MemoryCacheAdapter};

#[cfg(feature = "sqlx-postgres")]
pub use database::sqlx_adapter::{SqlxAdapter, PoolConfig, PoolStats};

#[cfg(feature = "redis-cache")]
pub use cache::RedisAdapter;
