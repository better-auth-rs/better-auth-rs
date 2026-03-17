//! SeaORM-backed persistence implementation for built-in auth tables.

mod accounts;
mod api_keys;
mod conversions;
pub mod entities;
mod invitations;
mod members;
pub mod migrator;
mod organizations;
mod passkeys;
mod sessions;
mod two_factor;
mod users;
mod verifications;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use sea_orm::{DatabaseConnection, DatabaseTransaction, DbErr, SqlErr, TransactionTrait};

use crate::config::AuthConfig;
use crate::error::{AuthError, DatabaseError};
use crate::hooks::{DatabaseHookContext, DatabaseHooks, current_request_hook_context};

#[derive(Clone)]
pub struct AuthStore {
    config: Arc<AuthConfig>,
    db: DatabaseConnection,
    hooks: Vec<Arc<dyn DatabaseHooks>>,
}

impl AuthStore {
    pub fn new(config: Arc<AuthConfig>, db: DatabaseConnection) -> Self {
        Self {
            config,
            db,
            hooks: Vec::new(),
        }
    }

    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn DatabaseHooks>>) -> Self {
        self.hooks = hooks;
        self
    }

    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }

    pub fn config(&self) -> &Arc<AuthConfig> {
        &self.config
    }

    pub(crate) fn hooks(&self) -> &[Arc<dyn DatabaseHooks>] {
        &self.hooks
    }

    pub(crate) fn hook_context<'a>(
        &'a self,
        tx: Option<&'a DatabaseTransaction>,
    ) -> DatabaseHookContext<'a> {
        DatabaseHookContext {
            config: self.config.as_ref(),
            db: &self.db,
            tx,
            request: current_request_hook_context(),
        }
    }

    pub async fn test_connection(&self) -> Result<(), DbErr> {
        self.db.ping().await
    }

    /// Execute work inside a database transaction bound to this store.
    #[doc(hidden)]
    pub async fn transaction<T, F>(&self, work: F) -> Result<T, AuthError>
    where
        F: for<'a> FnOnce(
                &'a DatabaseTransaction,
            )
                -> Pin<Box<dyn Future<Output = Result<T, AuthError>> + Send + 'a>>
            + Send,
        T: Send,
    {
        let tx = self.db.begin().await.map_err(map_db_err)?;
        match work(&tx).await {
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
            AuthError::Database(DatabaseError::Constraint(message))
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

fn to_i32(value: i64, field: &str) -> Result<i32, AuthError> {
    i32::try_from(value).map_err(|_| AuthError::bad_request(format!("{field} exceeds i32 range")))
}

fn to_optional_i32(value: Option<i64>, field: &str) -> Result<Option<i32>, AuthError> {
    value.map(|inner| to_i32(inner, field)).transpose()
}
