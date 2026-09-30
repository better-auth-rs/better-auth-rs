//! SeaORM-backed persistence implementation for built-in auth tables.

mod accounts;
mod api_key_numbers;
mod api_keys;
mod bundled_schema;
mod device_codes;
pub mod entities;
mod identity_schema;
mod invitations;
mod jwks;
mod members;
mod migrator;
mod organizations;
mod passkeys;
mod sessions;
mod two_factor;
mod two_factor_security;
mod user_verification;
mod users;
mod verifications;
mod wallets;

#[doc(hidden)]
pub mod __private_test_support {
    pub mod bundled_schema {
        pub use super::super::bundled_schema::BundledSchema;
    }

    pub mod migrator {
        pub use super::super::migrator::{AuthMigrator, run_migrations};
    }
}

use std::marker::PhantomData;
use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
};
use chrono::{DateTime, Utc};
use sea_orm::{DatabaseConnection, DatabaseTransaction, DbErr, SqlErr, TransactionTrait};

use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult, DatabaseError};
use crate::hooks::{SeaOrmHookContext, SeaOrmHooks, current_request_hook_context};
use crate::schema::{AuthSchema, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel};

#[derive(Clone)]
pub struct SeaOrmStore<S: AuthSchema> {
    config: Arc<AuthConfig>,
    db: DatabaseConnection,
    hooks: Vec<Arc<dyn SeaOrmHooks<S>>>,
    _schema: PhantomData<S>,
}

impl<S: AuthSchema> SeaOrmStore<S> {
    pub fn new(config: impl Into<Arc<AuthConfig>>, db: DatabaseConnection) -> Self {
        Self {
            config: config.into(),
            db,
            hooks: Vec::new(),
            _schema: PhantomData,
        }
    }

    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn SeaOrmHooks<S>>>) -> Self {
        self.hooks = hooks;
        self
    }

    pub fn hook<H: SeaOrmHooks<S> + 'static>(mut self, hook: H) -> Self {
        self.hooks.push(Arc::new(hook));
        self
    }

    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }

    pub fn config(&self) -> &Arc<AuthConfig> {
        &self.config
    }

    pub(crate) fn hooks(&self) -> &[Arc<dyn SeaOrmHooks<S>>] {
        &self.hooks
    }

    pub(crate) fn hook_context<'a>(
        &'a self,
        tx: Option<&'a DatabaseTransaction>,
    ) -> SeaOrmHookContext<'a> {
        SeaOrmHookContext {
            config: self.config.as_ref(),
            db: &self.db,
            tx,
            request: current_request_hook_context(),
        }
    }

    pub async fn test_connection(&self) -> Result<(), DbErr> {
        self.db.ping().await
    }
}

struct SeaOrmTransaction<'a, S: AuthSchema> {
    store: &'a SeaOrmStore<S>,
    tx: &'a DatabaseTransaction,
}

#[async_trait]
impl<S> AuthTransaction<S> for SeaOrmTransaction<'_, S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
{
    async fn create_user(&self, create_user: better_auth_core::CreateUser) -> AuthResult<S::User> {
        self.store.create_user_in_tx(self.tx, create_user).await
    }

    async fn create_account(
        &self,
        create_account: better_auth_core::CreateAccount,
    ) -> AuthResult<S::Account> {
        self.store
            .create_account_in_tx(self.tx, create_account)
            .await
    }

    async fn create_session(
        &self,
        create_session: better_auth_core::CreateSession,
    ) -> AuthResult<S::Session> {
        self.store
            .create_session_in_tx(self.tx, create_session)
            .await
    }
}

#[async_trait]
impl<S> TransactionStore<S> for SeaOrmStore<S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
{
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        let tx = self.db.begin().await.map_err(map_db_err)?;
        let tx_store = SeaOrmTransaction {
            store: self,
            tx: &tx,
        };

        match work(&tx_store).await {
            Ok(value) => {
                tx.commit().await.map_err(map_db_err)?;
                Ok(value)
            }
            Err(err) => {
                tx.rollback().await.map_err(map_db_err)?;
                Err(err)
            }
        }
    }
}

fn map_db_err(err: DbErr) -> AuthError {
    match err.sql_err() {
        Some(SqlErr::UniqueConstraintViolation(message)) => {
            AuthError::Database(DatabaseError::UniqueConstraint(message))
        }
        Some(SqlErr::ForeignKeyConstraintViolation(message)) => {
            AuthError::Database(DatabaseError::Constraint(message))
        }
        Some(_) | None => AuthError::Database(DatabaseError::Query(err.to_string())),
    }
}

pub(crate) fn cancelled_by_hook(operation: &str) -> AuthError {
    AuthError::forbidden(format!("{operation} cancelled by database hook"))
}

fn parse_rfc3339(value: &str, field: &str) -> Result<DateTime<Utc>, AuthError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| AuthError::bad_request(format!("Invalid RFC 3339 timestamp for {field}")))
}

fn parse_optional_rfc3339(
    value: Option<&str>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, AuthError> {
    value.map(|inner| parse_rfc3339(inner, field)).transpose()
}
