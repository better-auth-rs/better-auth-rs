use crate::error::{AuthError, AuthResult};
use crate::types::{
    Account, ApiKey, Invitation, Member, Organization, Passkey, Session, TwoFactor, User,
    Verification,
};
use std::marker::PhantomData;

// Backend-specific implementations
#[cfg(feature = "sqlx-postgres")]
pub mod postgres;

#[cfg(feature = "sqlx-sqlite")]
pub mod sqlite;

#[cfg(feature = "sqlx-postgres")]
use sqlx::postgres::PgPool;

#[cfg(feature = "sqlx-sqlite")]
use sqlx::sqlite::SqlitePool;

/// Database backend type detected from URL
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseBackendType {
    #[cfg(feature = "sqlx-postgres")]
    Postgres,
    #[cfg(feature = "sqlx-sqlite")]
    Sqlite,
}

/// Parse database URL to detect backend type
fn parse_database_url(url: &str) -> AuthResult<DatabaseBackendType> {
    let lower = url.to_lowercase();

    #[cfg(feature = "sqlx-postgres")]
    if lower.starts_with("postgres://") || lower.starts_with("postgresql://") {
        return Ok(DatabaseBackendType::Postgres);
    }

    #[cfg(feature = "sqlx-sqlite")]
    if lower.starts_with("sqlite://") || lower.starts_with("file:") {
        return Ok(DatabaseBackendType::Sqlite);
    }

    Err(AuthError::bad_request(format!(
        "Unsupported database URL scheme. Expected one of: {}",
        {
            #[cfg(all(feature = "sqlx-postgres", feature = "sqlx-sqlite"))]
            {
                "postgres://, postgresql://, sqlite://, or file:"
            }
            #[cfg(all(feature = "sqlx-postgres", not(feature = "sqlx-sqlite")))]
            {
                "postgres:// or postgresql://"
            }
            #[cfg(all(not(feature = "sqlx-postgres"), feature = "sqlx-sqlite"))]
            {
                "sqlite:// or file:"
            }
        }
    )))
}

/// Backend-specific implementation enum
enum SqlxBackend<U, S, A, O, M, I, V, TF, AK, PK> {
    #[cfg(feature = "sqlx-postgres")]
    Postgres(postgres::PostgresAdapter<U, S, A, O, M, I, V, TF, AK, PK>),
    #[cfg(feature = "sqlx-sqlite")]
    Sqlite(sqlite::SqliteAdapter<U, S, A, O, M, I, V, TF, AK, PK>),
}

type SqlxAdapterEntities<U, S, A, O, M, I, V, TF, AK, PK> = (U, S, A, O, M, I, V, TF, AK, PK);

/// Legacy re-export for backward compatibility
#[cfg(feature = "sqlx-postgres")]
pub use postgres::PostgresEntity as SqlxEntity;

/// Unified database adapter supporting PostgreSQL and SQLite.
///
/// Runtime backend selection based on connection URL:
/// - `postgres://` or `postgresql://` → PostgreSQL
/// - `sqlite://` or `file:` → SQLite
///
/// Generic over entity types — use default type parameters for the built-in
/// types, or supply your own custom structs that implement `Auth*` + `sqlx::FromRow`.
pub struct SqlxAdapter<
    U = User,
    S = Session,
    A = Account,
    O = Organization,
    M = Member,
    I = Invitation,
    V = Verification,
    TF = TwoFactor,
    AK = ApiKey,
    PK = Passkey,
> {
    backend: SqlxBackend<U, S, A, O, M, I, V, TF, AK, PK>,
    #[allow(clippy::type_complexity)]
    _phantom: PhantomData<SqlxAdapterEntities<U, S, A, O, M, I, V, TF, AK, PK>>,
}

/// Constructors for the default (built-in) entity types.
impl SqlxAdapter {
    /// Create a new adapter with runtime backend detection from URL.
    ///
    /// Supported URL schemes:
    /// - PostgreSQL: `postgres://` or `postgresql://`
    /// - SQLite: `sqlite://` or `file:`
    pub async fn new(database_url: &str) -> AuthResult<Self> {
        let backend_type = parse_database_url(database_url)?;

        match backend_type {
            #[cfg(feature = "sqlx-postgres")]
            DatabaseBackendType::Postgres => {
                let adapter = postgres::PostgresAdapter::new(database_url)
                    .await
                    .map_err(|e| {
                        AuthError::internal(format!("Failed to connect to PostgreSQL: {}", e))
                    })?;
                Ok(Self {
                    backend: SqlxBackend::Postgres(adapter),
                    _phantom: PhantomData,
                })
            }
            #[cfg(feature = "sqlx-sqlite")]
            DatabaseBackendType::Sqlite => {
                let adapter = sqlite::SqliteAdapter::new(database_url)
                    .await
                    .map_err(|e| {
                        AuthError::internal(format!("Failed to connect to SQLite: {}", e))
                    })?;
                Ok(Self {
                    backend: SqlxBackend::Sqlite(adapter),
                    _phantom: PhantomData,
                })
            }
            #[cfg(not(any(feature = "sqlx-postgres", feature = "sqlx-sqlite")))]
            _ => Err(AuthError::internal("No SQL backend feature enabled")),
        }
    }

    /// Create adapter with custom pool configuration.
    pub async fn with_config(database_url: &str, config: PoolConfig) -> AuthResult<Self> {
        let backend_type = parse_database_url(database_url)?;

        match backend_type {
            #[cfg(feature = "sqlx-postgres")]
            DatabaseBackendType::Postgres => {
                let adapter = postgres::PostgresAdapter::with_config(database_url, config)
                    .await
                    .map_err(|e| {
                        AuthError::internal(format!("Failed to connect to PostgreSQL: {}", e))
                    })?;
                Ok(Self {
                    backend: SqlxBackend::Postgres(adapter),
                    _phantom: PhantomData,
                })
            }
            #[cfg(feature = "sqlx-sqlite")]
            DatabaseBackendType::Sqlite => {
                let adapter = sqlite::SqliteAdapter::with_config(database_url, config)
                    .await
                    .map_err(|e| {
                        AuthError::internal(format!("Failed to connect to SQLite: {}", e))
                    })?;
                Ok(Self {
                    backend: SqlxBackend::Sqlite(adapter),
                    _phantom: PhantomData,
                })
            }
            #[cfg(not(any(feature = "sqlx-postgres", feature = "sqlx-sqlite")))]
            _ => Err(AuthError::internal("No SQL backend feature enabled")),
        }
    }
}

/// Feature-specific constructors
impl SqlxAdapter {
    /// Create adapter from an existing PostgreSQL pool.
    #[cfg(feature = "sqlx-postgres")]
    pub fn from_postgres_pool(pool: PgPool) -> Self {
        Self {
            backend: SqlxBackend::Postgres(postgres::PostgresAdapter::from_pool(pool)),
            _phantom: PhantomData,
        }
    }

    /// Create adapter from an existing SQLite pool.
    #[cfg(feature = "sqlx-sqlite")]
    pub fn from_sqlite_pool(pool: SqlitePool) -> Self {
        Self {
            backend: SqlxBackend::Sqlite(sqlite::SqliteAdapter::from_pool(pool)),
            _phantom: PhantomData,
        }
    }
}

/// Methods available for all type parameterizations.
impl<U, S, A, O, M, I, V, TF, AK, PK> SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK> {
    pub async fn test_connection(&self) -> Result<(), sqlx::Error> {
        match &self.backend {
            #[cfg(feature = "sqlx-postgres")]
            SqlxBackend::Postgres(pg) => pg.test_connection().await,
            #[cfg(feature = "sqlx-sqlite")]
            SqlxBackend::Sqlite(sq) => sq.test_connection().await,
        }
    }

    pub fn pool_stats(&self) -> PoolStats {
        match &self.backend {
            #[cfg(feature = "sqlx-postgres")]
            SqlxBackend::Postgres(pg) => pg.pool_stats(),
            #[cfg(feature = "sqlx-sqlite")]
            SqlxBackend::Sqlite(sq) => sq.pool_stats(),
        }
    }

    pub async fn close(&self) {
        match &self.backend {
            #[cfg(feature = "sqlx-postgres")]
            SqlxBackend::Postgres(pg) => pg.close().await,
            #[cfg(feature = "sqlx-sqlite")]
            SqlxBackend::Sqlite(sq) => sq.close().await,
        }
    }
}

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
