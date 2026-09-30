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
mod organization_extensions;
mod organization_models;
mod organization_roles;
mod organizations;
mod passkeys;
mod sessions;
mod team_invitation;
mod teams;
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

pub struct SeaOrmStore<
    S: AuthSchema,
    O: crate::SeaOrmOrganizationSchema = crate::OrganizationModels,
> {
    config: Arc<AuthConfig>,
    db: DatabaseConnection,
    hooks: Vec<Arc<dyn SeaOrmHooks<S>>>,
    organization_fields:
        Arc<std::sync::RwLock<better_auth_core::organization_fields::OrganizationFields>>,
    _schema: PhantomData<(S, O)>,
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema> Clone for SeaOrmStore<S, O> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            db: self.db.clone(),
            hooks: self.hooks.clone(),
            organization_fields: self.organization_fields.clone(),
            _schema: PhantomData,
        }
    }
}

impl<S: AuthSchema> SeaOrmStore<S> {
    /// Construct a store with bundled organization models.
    pub fn new(config: impl Into<Arc<AuthConfig>>, db: DatabaseConnection) -> Self {
        Self {
            config: config.into(),
            db,
            hooks: Vec::new(),
            organization_fields: Default::default(),
            _schema: PhantomData,
        }
    }
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema> SeaOrmStore<S, O> {
    /// Bind application-owned organization models while retaining core auth models and hooks.
    pub fn with_organization_schema<T: crate::SeaOrmOrganizationSchema>(self) -> SeaOrmStore<S, T> {
        SeaOrmStore {
            config: self.config,
            db: self.db,
            hooks: self.hooks,
            organization_fields: self.organization_fields,
            _schema: PhantomData,
        }
    }

    pub(crate) fn organization_fields(
        &self,
    ) -> AuthResult<better_auth_core::organization_fields::OrganizationFields> {
        self.organization_fields
            .read()
            .map(|fields| fields.clone())
            .map_err(|error| AuthError::internal(error.to_string()))
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

struct SeaOrmTransaction<'a, S: AuthSchema, O: crate::SeaOrmOrganizationSchema> {
    store: &'a SeaOrmStore<S, O>,
    tx: &'a DatabaseTransaction,
}

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema> AuthTransaction<S> for SeaOrmTransaction<'_, S, O>
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
impl<S, O: crate::SeaOrmOrganizationSchema> TransactionStore<S> for SeaOrmStore<S, O>
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

#[cfg(test)]
mod organization_extension_tests;
