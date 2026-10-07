//! Storage traits and cache adapters used by Better Auth.

#[cfg(feature = "redis-cache")]
pub use better_auth_core::store::RedisAdapter;
pub use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks, SessionUpdate,
    VerificationUpdate,
};
pub use better_auth_core::store::{
    AccountOwner, AuthStore, AuthTransaction, CacheAdapter, EphemeralStore, InvitationOrganization,
    MemoryCacheAdapter, OrganizationRoleKey, RateLimitRecord, RateLimitStore, RuntimeStore,
    SecondaryStorage, SessionCreateWriter, SessionUpdateWriter, StatelessSchema, StoreCapabilities,
    UserAccounts, VerificationCleanup, VerificationCreateWriter, VerificationSessionCleanup,
    transaction,
};
