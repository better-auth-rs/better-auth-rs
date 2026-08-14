// PostgreSQL-specific implementation

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

use crate::adapters::traits::{
    AccountOps, ApiKeyOps, InvitationOps, MemberOps, OrganizationOps, PasskeyOps, SessionOps,
    TwoFactorOps, VerificationOps,
};
use crate::types::{
    Account, ApiKey, Invitation, Member, Organization, Passkey, Session, TwoFactor, User,
    Verification,
};
use sqlx::postgres::{PgPool, PgRow};
use std::marker::PhantomData;

use super::{PoolConfig, PoolStats};

/// Quote a SQL identifier with double quotes for PostgreSQL.
///
/// This prevents issues with reserved words (e.g. `user`, `key`, `order`)
/// and ensures correct identifier handling.
#[inline]
pub(crate) fn qi(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

/// Blanket trait combining all bounds needed for PostgreSQL entity types.
///
/// Any type that implements `sqlx::FromRow<PgRow>` plus the standard marker traits
/// automatically satisfies this bound.
pub trait PostgresEntity:
    for<'r> sqlx::FromRow<'r, PgRow> + Send + Sync + Unpin + Clone + 'static
{
}

impl<T> PostgresEntity for T where
    T: for<'r> sqlx::FromRow<'r, PgRow> + Send + Sync + Unpin + Clone + 'static
{
}

type PostgresAdapterEntities<U, S, A, O, M, I, V, TF, AK, PK> = (U, S, A, O, M, I, V, TF, AK, PK);

/// PostgreSQL-specific adapter implementation
pub struct PostgresAdapter<
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
    pub(crate) pool: PgPool,
    #[allow(clippy::type_complexity)]
    _phantom: PhantomData<PostgresAdapterEntities<U, S, A, O, M, I, V, TF, AK, PK>>,
}

/// Constructors
impl PostgresAdapter {
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

/// Methods for all parameterizations
impl<U, S, A, O, M, I, V, TF, AK, PK> PostgresAdapter<U, S, A, O, M, I, V, TF, AK, PK> {
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
