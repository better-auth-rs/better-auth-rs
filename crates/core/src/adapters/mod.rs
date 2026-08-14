pub mod cache;
pub mod database;
pub mod memory;
pub mod memory_traits;
pub mod traits;

pub use cache::{CacheAdapter, MemoryCacheAdapter};
pub use database::{
    AccountOps, ApiKeyOps, DatabaseAdapter, InvitationOps, MemberOps, OrganizationOps, PasskeyOps,
    SessionOps, TwoFactorOps, UserOps, VerificationOps,
};
pub use memory::{
    MemoryAccount, MemoryApiKey, MemoryDatabaseAdapter, MemoryInvitation, MemoryMember,
    MemoryOrganization, MemoryPasskey, MemorySession, MemoryTwoFactor, MemoryUser,
    MemoryVerification,
};

// Always export PoolConfig and PoolStats when any sqlx feature is enabled
#[cfg(any(feature = "sqlx-postgres", feature = "sqlx-sqlite"))]
pub use database::sqlx_adapter::{PoolConfig, PoolStats};

#[cfg(feature = "sqlx-postgres")]
pub use database::sqlx_adapter::{PostgresAdapter, PostgresEntity};

#[cfg(feature = "sqlx-sqlite")]
pub use database::sqlx_adapter::{SqliteAdapter, SqliteEntity};

#[cfg(feature = "redis-cache")]
pub use cache::RedisAdapter;
