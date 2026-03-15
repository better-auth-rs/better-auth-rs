pub mod cache;
pub mod database;
pub mod memory;
pub mod memory_traits;
pub mod sea_orm;
pub mod traits;

pub use cache::{CacheAdapter, MemoryCacheAdapter};
pub use database::{
    AccountOps, ApiKeyOps, AuthDatabase, DatabaseAdapter, InvitationOps, MemberOps,
    OrganizationOps, PasskeyOps, SessionOps, TwoFactorOps, UserOps, VerificationOps,
};
pub use memory::{
    MemoryAccount, MemoryApiKey, MemoryDatabaseAdapter, MemoryInvitation, MemoryMember,
    MemoryOrganization, MemoryPasskey, MemorySession, MemoryTwoFactor, MemoryUser,
    MemoryVerification,
};

#[cfg(feature = "sqlx-postgres")]
pub use database::sqlx_adapter::{PoolConfig, PoolStats, SqlxAdapter, SqlxEntity};
pub use sea_orm::{
    SeaOrmAdapter,
    migrator::{AuthMigrator, run_migrations},
};

#[cfg(feature = "redis-cache")]
pub use cache::RedisAdapter;
