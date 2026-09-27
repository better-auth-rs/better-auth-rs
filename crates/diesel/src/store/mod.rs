//! Diesel-backed persistence for the Better Auth tables.

/// Run `$body` on a database connection and map the Diesel error.
///
/// `run_query!(store, |c| ...)` checks a connection out of the store pool,
/// `run_query!(on connection, |c| ...)` uses a `&mut DieselConnection`, and
/// `run_query!(lock hook_connection, |c| ...)` locks the connection of a
/// hooked write. The body follows [`with_connection!`](crate::with_connection).
///
/// Defined before the submodules so that they can use it.
macro_rules! run_query {
    (on $connection:expr, |$c:ident| $body:expr) => {
        $crate::connection::with_connection!($connection, |$c| $body)
            .map_err($crate::error::map_query_err)
    };
    (lock $connection:expr, |$c:ident| $body:expr) => {{
        let mut connection = $connection.lock().await?;
        $crate::connection::with_connection!(&mut *connection, |$c| $body)
            .map_err($crate::error::map_query_err)
    }};
    ($store:expr, |$c:ident| $body:expr) => {{
        let mut connection = $store.connection().await?;
        $crate::connection::with_connection!(&mut connection, |$c| $body)
            .map_err($crate::error::map_query_err)
    }};
}

mod accounts;
mod api_keys;
mod device_codes;
mod invitations;
mod members;
mod organizations;
mod passkeys;
mod sessions;
mod two_factor;
mod users;
mod verifications;

use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::config::AuthConfig;
use better_auth_core::schema::AuthSchema;
use better_auth_core::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
};
use better_auth_core::types::{CreateAccount, CreateSession, CreateUser};
use tokio::sync::{Mutex, MutexGuard};

use crate::connection::{DieselConnection, DieselPool};
use crate::error::{AuthResult, map_query_err};
use crate::hooks::{DieselHookContext, DieselHooks, HookConnection, current_request_hook_context};
use crate::models::{Account, Session, User, Verification};

/// Auth schema served by [`DieselStore`]: the row types in
/// [`models`](crate::models) over the tables in [`schema`](crate::schema).
#[derive(Debug, Clone, Copy, Default)]
pub struct DieselAuthSchema;

impl AuthSchema for DieselAuthSchema {
    type User = User;
    type Session = Session;
    type Account = Account;
    type Verification = Verification;
}

/// Auth store backed by a Diesel connection pool.
///
/// ```rust,ignore
/// use better_auth::diesel::{DieselAuthSchema, DieselPool, DieselStore};
///
/// let pool = DieselPool::postgres(database_url)?;
/// let store = DieselStore::new(config.clone(), pool);
/// let auth = BetterAuth::<DieselAuthSchema>::new(config).store(store).build().await?;
/// ```
#[derive(Clone)]
pub struct DieselStore {
    config: Arc<AuthConfig>,
    pool: DieselPool,
    hooks: Vec<Arc<dyn DieselHooks>>,
}

impl DieselStore {
    pub fn new(config: impl Into<Arc<AuthConfig>>, pool: impl Into<DieselPool>) -> Self {
        Self {
            config: config.into(),
            pool: pool.into(),
            hooks: Vec::new(),
        }
    }

    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn DieselHooks>>) -> Self {
        self.hooks = hooks;
        self
    }

    pub fn hook<H: DieselHooks + 'static>(mut self, hook: H) -> Self {
        self.hooks.push(Arc::new(hook));
        self
    }

    pub fn pool(&self) -> &DieselPool {
        &self.pool
    }

    pub fn config(&self) -> &Arc<AuthConfig> {
        &self.config
    }

    /// Check out a connection and run a trivial statement on it.
    pub async fn test_connection(&self) -> AuthResult<()> {
        use diesel_async::SimpleAsyncConnection;

        run_query!(self, |c| c.batch_execute("SELECT 1").await)
    }

    pub(crate) fn hooks(&self) -> &[Arc<dyn DieselHooks>] {
        &self.hooks
    }

    pub(crate) fn hook_context<'a>(
        &'a self,
        connection: &'a HookConnection<'a>,
    ) -> DieselHookContext<'a> {
        DieselHookContext {
            config: self.config.as_ref(),
            pool: &self.pool,
            in_transaction: connection.in_transaction(),
            request: current_request_hook_context(),
            connection,
        }
    }

    pub(crate) async fn connection(&self) -> AuthResult<DieselConnection> {
        self.pool.get().await
    }
}

impl std::fmt::Debug for DieselStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DieselStore")
            .field("pool", &self.pool)
            .field("hooks", &self.hooks.len())
            .finish_non_exhaustive()
    }
}

/// Auth writes that share one database transaction.
///
/// The connection sits behind a mutex because `AuthTransaction` methods take
/// `&self` while each write needs `&mut` access to it.
struct DieselTransaction<'a> {
    store: &'a DieselStore,
    connection: Mutex<&'a mut DieselConnection>,
}

impl<'a> DieselTransaction<'a> {
    async fn lock(&self) -> MutexGuard<'_, &'a mut DieselConnection> {
        self.connection.lock().await
    }
}

#[async_trait]
impl AuthTransaction<DieselAuthSchema> for DieselTransaction<'_> {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<User> {
        let mut connection = self.lock().await;
        let connection = HookConnection::transaction(&self.store.pool, &mut connection);
        self.store.insert_user(&connection, create_user).await
    }

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<Account> {
        let mut connection = self.lock().await;
        let connection = HookConnection::transaction(&self.store.pool, &mut connection);
        self.store.insert_account(&connection, create_account).await
    }

    async fn create_session(&self, create_session: CreateSession) -> AuthResult<Session> {
        let mut connection = self.lock().await;
        let connection = HookConnection::transaction(&self.store.pool, &mut connection);
        self.store.insert_session(&connection, create_session).await
    }
}

#[async_trait]
impl TransactionStore<DieselAuthSchema> for DieselStore {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<DieselAuthSchema>>,
    ) -> AuthResult<BoxedTransactionValue> {
        let mut connection = self.connection().await?;
        connection
            .begin_transaction()
            .await
            .map_err(map_query_err)?;

        let transaction = DieselTransaction {
            store: self,
            connection: Mutex::new(&mut connection),
        };
        let result = work(&transaction).await;

        connection.finish_transaction(result).await
    }
}

pub(crate) use better_auth_core::store::adapter::{
    cancelled_by_hook, normalize_email, normalize_optional_email, parse_optional_rfc3339, to_i32,
    to_optional_i32,
};

pub(crate) fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
