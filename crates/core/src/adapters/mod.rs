pub mod cache;
pub mod database;
pub mod memory;

pub use cache::{CacheAdapter, MemoryCacheAdapter};
pub use database::{
    AccountOps, DatabaseAdapter, InvitationOps, MemberOps, OrganizationOps, SessionOps, UserOps,
    VerificationOps,
};
pub use memory::{
    MemoryAccount, MemoryDatabaseAdapter, MemoryInvitation, MemoryMember, MemoryOrganization,
    MemorySession, MemoryUser, MemoryVerification,
};

#[cfg(feature = "sqlx-postgres")]
pub use database::sqlx_adapter::{PoolConfig, PoolStats, SqlxAdapter, SqlxEntity};

#[cfg(feature = "redis-cache")]
pub use cache::RedisAdapter;
