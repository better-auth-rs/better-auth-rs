//! Storage traits and cache adapters used by Better Auth.

#[cfg(feature = "redis-cache")]
pub use better_auth_core::store::RedisAdapter;
pub use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks, SessionUpdate,
    VerificationUpdate,
};
pub use better_auth_core::store::{
    AuthStore, AuthTransaction, CacheAdapter, EphemeralStore, MemoryCacheAdapter, RateLimitRecord,
    RateLimitStore, RuntimeStore, SecondaryStorage, SessionUpdateWriter, StatelessSchema,
    StoreCapabilities, VerificationCleanup, VerificationSessionCleanup, transaction,
};
