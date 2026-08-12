mod account_ops;
mod api_key_ops;
mod invitation_ops;
mod member_ops;
mod organization_ops;
mod passkey_ops;
mod session_ops;
mod two_factor_ops;
mod user_ops;
mod verification_ops;

use super::*;


use crate::error::{AuthError, AuthResult};
use crate::types::{
    Account, ApiKey, Invitation, Member, Organization, Passkey, Session, TwoFactor, User,
    Verification,
};
use std::marker::PhantomData;

#[cfg(feature = "sqlx-postgres")]
use sqlx::postgres::{PgPool, PgRow};

#[cfg(feature = "sqlx-sqlite")]
use sqlx::sqlite::{SqlitePool, SqliteRow};

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
            let mut schemes = vec![];
            #[cfg(feature = "sqlx-postgres")]
            schemes.push("postgres://");
            #[cfg(feature = "sqlx-sqlite")]
            schemes.push("sqlite://");
            schemes.join(", ")
        }
    )))
}

/// Quote a SQL identifier with double quotes for PostgreSQL.
///
/// This prevents issues with reserved words (e.g. `user`, `key`, `order`)
/// and ensures correct identifier handling regardless of the names returned
/// by `Auth*Meta` traits.
#[inline]
fn qi(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

/// Blanket trait combining all bounds needed for SQLx-based entity types.
///
/// Any type that implements `sqlx::FromRow` plus the standard marker traits
/// automatically satisfies this bound. Custom entity types just need
/// `#[derive(sqlx::FromRow)]` (or a manual `FromRow` impl) alongside
/// their `Auth*` derive.
pub trait SqlxEntity:
    for<'r> sqlx::FromRow<'r, PgRow> + Send + Sync + Unpin + Clone + 'static
{
}

impl<T> SqlxEntity for T where
    T: for<'r> sqlx::FromRow<'r, PgRow> + Send + Sync + Unpin + Clone + 'static
{
}

type SqlxAdapterEntities<U, S, A, O, M, I, V, TF, AK, PK> = (U, S, A, O, M, I, V, TF, AK, PK);

/// PostgreSQL database adapter via SQLx.
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
    pool: PgPool,
    #[allow(clippy::type_complexity)]
    _phantom: PhantomData<SqlxAdapterEntities<U, S, A, O, M, I, V, TF, AK, PK>>,
}

/// Constructors for the default (built-in) entity types.
impl SqlxAdapter {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self {
            pool,
            _phantom: PhantomData,
        })
    }

    pub async fn with_config(database_url: &str, config: PoolConfig) -> Result<Self, sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(config.acquire_timeout)
            .idle_timeout(config.idle_timeout)
            .max_lifetime(config.max_lifetime)
            .connect(database_url)
            .await?;
        Ok(Self {
            pool,
            _phantom: PhantomData,
        })
    }
}

/// Methods available for all type parameterizations.
impl<U, S, A, O, M, I, V, TF, AK, PK> SqlxAdapter<U, S, A, O, M, I, V, TF, AK, PK> {
    pub fn from_pool(pool: PgPool) -> Self {
        Self {
            pool,
            _phantom: PhantomData,
        }
    }

    pub async fn test_connection(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub fn pool_stats(&self) -> PoolStats {
        PoolStats {
            size: self.pool.size(),
            idle: self.pool.num_idle(),
        }
    }

    pub async fn close(&self) {
        self.pool.close().await;
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
