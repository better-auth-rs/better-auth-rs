pub mod cache;
pub mod database;
pub mod memory;
pub mod memory_traits;
pub mod traits;

pub use cache::{CacheAdapter, MemoryCacheAdapter};
pub use database::{
    AccountOps, ApiKeyOps, DatabaseAdapter, InvitationOps, MemberOps, OrganizationOps, SessionOps,
    TwoFactorOps, UserOps, VerificationOps,
};
pub use memory::{
    MemoryAccount, MemoryApiKey, MemoryDatabaseAdapter, MemoryInvitation, MemoryMember,
    MemoryOrganization, MemorySession, MemoryTwoFactor, MemoryUser, MemoryVerification,
};

#[cfg(feature = "sqlx-postgres")]
pub use database::sqlx_adapter::{PoolConfig, PoolStats, SqlxAdapter, SqlxEntity};

#[cfg(feature = "redis-cache")]
pub use cache::RedisAdapter;
