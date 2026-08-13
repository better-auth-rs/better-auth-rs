// Backend-specific implementations
#[cfg(feature = "sqlx-postgres")]
pub mod postgres;

#[cfg(feature = "sqlx-sqlite")]
pub mod sqlite;

// Shared pool configuration types
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: std::time::Duration,
    pub idle_timeout: Option<std::time::Duration>,
    pub max_lifetime: Option<std::time::Duration>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_connections: 0,
            acquire_timeout: std::time::Duration::from_secs(30),
            idle_timeout: Some(std::time::Duration::from_secs(600)),
            max_lifetime: Some(std::time::Duration::from_secs(1800)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub size: u32,
    pub idle: usize,
}

// Re-export adapters directly
#[cfg(feature = "sqlx-postgres")]
pub use postgres::{PostgresAdapter, PostgresEntity};

#[cfg(feature = "sqlx-sqlite")]
pub use sqlite::{SqliteAdapter, SqliteEntity};

// Legacy alias for backward compatibility (PostgreSQL was the first implementation)
#[cfg(feature = "sqlx-postgres")]
pub use PostgresAdapter as SqlxAdapter;

#[cfg(feature = "sqlx-postgres")]
pub use PostgresEntity as SqlxEntity;
