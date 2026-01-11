pub mod database;
pub mod cache;
pub mod mailer;

pub use database::{DatabaseAdapter, MemoryDatabaseAdapter};
pub use cache::{CacheAdapter, MemoryCacheAdapter};
pub use mailer::{MailerAdapter, MemoryMailerAdapter};

#[cfg(feature = "sqlx-postgres")]
pub use database::sqlx_adapter::{SqlxAdapter, PoolConfig, PoolStats};

#[cfg(feature = "redis-cache")]
pub use cache::RedisAdapter;
