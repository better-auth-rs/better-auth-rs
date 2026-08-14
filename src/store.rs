//! Storage traits and cache adapters used by Better Auth.

#[cfg(feature = "redis-cache")]
pub use better_auth_core::store::RedisAdapter;
pub use better_auth_core::store::{
    AuthStore, AuthTransaction, CacheAdapter, MemoryCacheAdapter, transaction,
};
