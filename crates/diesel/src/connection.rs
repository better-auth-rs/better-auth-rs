//! Connection pools and backend dispatch.

use std::fmt;

#[cfg(feature = "postgres")]
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::{BuildError, Object, Pool};

use crate::error::{AuthError, AuthResult, DatabaseError, map_query_err};

/// Async SQLite connection: Diesel's `SqliteConnection` run on blocking
/// threads by `diesel-async`.
#[cfg(feature = "sqlite")]
pub type AsyncSqliteConnection =
    diesel_async::sync_connection_wrapper::SyncConnectionWrapper<diesel::SqliteConnection>;

/// Connection pool used by [`DieselStore`](crate::DieselStore).
///
/// Build it with [`DieselPool::postgres`] or [`DieselPool::sqlite`], or wrap
/// an existing `diesel-async` deadpool with `From`. Cloning is cheap and
/// shares the same pool.
///
/// The variants depend on the enabled backend features, and another crate in
/// the build can enable more of them. Use [`as_postgres`](Self::as_postgres)
/// or [`as_sqlite`](Self::as_sqlite) rather than an exhaustive `match`.
#[derive(Clone)]
pub enum DieselPool {
    #[cfg(feature = "postgres")]
    Postgres(Pool<AsyncPgConnection>),
    #[cfg(feature = "sqlite")]
    Sqlite(Pool<AsyncSqliteConnection>),
}

impl fmt::Debug for DieselPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pool) => f.debug_tuple("Postgres").field(&pool.status()).finish(),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(pool) => f.debug_tuple("Sqlite").field(&pool.status()).finish(),
        }
    }
}

impl DieselPool {
    /// Build a PostgreSQL pool with the `diesel-async` defaults.
    ///
    /// The connection does not use TLS. To configure TLS or other connection
    /// options, build the pool with `diesel-async` and convert it with `From`.
    #[cfg(feature = "postgres")]
    pub fn postgres(database_url: impl Into<String>) -> Result<Self, BuildError> {
        use diesel_async::pooled_connection::AsyncDieselConnectionManager;

        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
        Ok(Self::Postgres(Pool::builder(manager).build()?))
    }

    /// Build a SQLite pool.
    ///
    /// Each connection enables `foreign_keys`, which the auth schema needs
    /// for cascading deletes, and sets a `busy_timeout`. A pool built with
    /// `diesel-async` directly must set both pragmas on every connection in
    /// the same way.
    ///
    /// A private in-memory database (`:memory:`) exists once per connection,
    /// so its pool holds one connection. Use it for tests only: when the pool
    /// drops that connection, for example after a cancelled transaction, the
    /// database goes with it.
    #[cfg(feature = "sqlite")]
    pub fn sqlite(database_url: impl Into<String>) -> Result<Self, BuildError> {
        use diesel_async::pooled_connection::{AsyncDieselConnectionManager, ManagerConfig};

        let database_url = database_url.into();
        let in_memory = is_private_memory_database(&database_url);

        let mut config = ManagerConfig::<AsyncSqliteConnection>::default();
        config.custom_setup = Box::new(|url| Box::pin(establish_sqlite(url)));
        let manager = AsyncDieselConnectionManager::new_with_config(database_url, config);

        let mut builder = Pool::builder(manager);
        if in_memory {
            builder = builder.max_size(1);
        }
        Ok(Self::Sqlite(builder.build()?))
    }

    /// The PostgreSQL pool, if this is one.
    #[cfg(feature = "postgres")]
    pub fn as_postgres(&self) -> Option<&Pool<AsyncPgConnection>> {
        match self {
            Self::Postgres(pool) => Some(pool),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(_) => None,
        }
    }

    /// The SQLite pool, if this is one.
    #[cfg(feature = "sqlite")]
    pub fn as_sqlite(&self) -> Option<&Pool<AsyncSqliteConnection>> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => None,
            Self::Sqlite(pool) => Some(pool),
        }
    }

    /// Check out a connection.
    pub async fn get(&self) -> Result<DieselConnection, AuthError> {
        let connection = match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pool) => pool.get().await.map(DieselConnection::Postgres),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(pool) => pool.get().await.map(DieselConnection::Sqlite),
        };
        connection.map_err(|err| AuthError::Database(DatabaseError::Connection(err.to_string())))
    }
}

#[cfg(feature = "postgres")]
impl From<Pool<AsyncPgConnection>> for DieselPool {
    fn from(pool: Pool<AsyncPgConnection>) -> Self {
        Self::Postgres(pool)
    }
}

#[cfg(feature = "sqlite")]
impl From<Pool<AsyncSqliteConnection>> for DieselPool {
    fn from(pool: Pool<AsyncSqliteConnection>) -> Self {
        Self::Sqlite(pool)
    }
}

/// Whether every connection to `url` opens its own in-memory database.
///
/// A shared-cache memory URI (`file:name?mode=memory&cache=shared`) is one
/// database for all connections of the process.
#[cfg(feature = "sqlite")]
fn is_private_memory_database(url: &str) -> bool {
    let in_memory =
        url == ":memory:" || url.starts_with("file::memory:") || url.contains("mode=memory");
    in_memory && !url.contains("cache=shared")
}

#[cfg(feature = "sqlite")]
async fn establish_sqlite(url: &str) -> diesel::ConnectionResult<AsyncSqliteConnection> {
    use diesel_async::{AsyncConnection, SimpleAsyncConnection};

    let mut connection = AsyncSqliteConnection::establish(url).await?;
    connection
        .batch_execute("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;")
        .await
        .map_err(diesel::ConnectionError::CouldntSetupConfiguration)?;
    Ok(connection)
}

/// A connection checked out of a [`DieselPool`].
///
/// Run a query on it with [`with_connection!`](crate::with_connection), which
/// compiles the query once per enabled backend. As with [`DieselPool`], the
/// variants depend on the enabled backend features.
#[cfg_attr(
    all(feature = "postgres", feature = "sqlite"),
    expect(
        clippy::large_enum_variant,
        reason = "a connection is checked out once per store call; boxing would add an allocation to every call"
    )
)]
pub enum DieselConnection {
    #[cfg(feature = "postgres")]
    Postgres(Object<AsyncPgConnection>),
    #[cfg(feature = "sqlite")]
    Sqlite(Object<AsyncSqliteConnection>),
}

/// Run an expression on the concrete connection behind a
/// [`DieselConnection`].
///
/// `$conn` is a `&mut DieselConnection`. `$c` is bound to
/// `&mut AsyncPgConnection` or `&mut AsyncSqliteConnection`, and the body is
/// compiled once per enabled backend, so a query built from the shared
/// [`schema`](crate::schema) runs on either backend. The body is not a
/// closure: `?` and `return` in it leave the enclosing function.
///
/// ```rust,ignore
/// use better_auth_diesel::diesel::prelude::*;
/// use better_auth_diesel::diesel_async::RunQueryDsl;
/// use better_auth_diesel::schema::users;
///
/// let count: i64 = better_auth_diesel::with_connection!(&mut connection, |c| {
///     users::table.count().get_result(c).await
/// })?;
/// ```
#[cfg(all(feature = "postgres", feature = "sqlite"))]
#[macro_export]
macro_rules! with_connection {
    ($conn:expr, |$c:ident| $body:expr) => {
        match $conn {
            $crate::DieselConnection::Postgres(object) => {
                let $c: &mut $crate::diesel_async::AsyncPgConnection = &mut **object;
                $body
            }
            $crate::DieselConnection::Sqlite(object) => {
                let $c: &mut $crate::AsyncSqliteConnection = &mut **object;
                $body
            }
        }
    };
}

// The backend features are checked where the macro is defined: a `cfg` in
// the expansion would test the features of the calling crate instead.
#[cfg(all(feature = "postgres", not(feature = "sqlite")))]
#[macro_export]
macro_rules! with_connection {
    ($conn:expr, |$c:ident| $body:expr) => {
        match $conn {
            $crate::DieselConnection::Postgres(object) => {
                let $c: &mut $crate::diesel_async::AsyncPgConnection = &mut **object;
                $body
            }
        }
    };
}

#[cfg(all(feature = "sqlite", not(feature = "postgres")))]
#[macro_export]
macro_rules! with_connection {
    ($conn:expr, |$c:ident| $body:expr) => {
        match $conn {
            $crate::DieselConnection::Sqlite(object) => {
                let $c: &mut $crate::AsyncSqliteConnection = &mut **object;
                $body
            }
        }
    };
}

pub(crate) use with_connection;

impl DieselConnection {
    /// Begin a write transaction.
    ///
    /// SQLite uses `BEGIN IMMEDIATE` so that the write lock is taken up
    /// front: a deferred transaction that reads and then writes fails with
    /// `SQLITE_BUSY` when another connection writes in between.
    pub(crate) async fn begin_transaction(&mut self) -> diesel::QueryResult<()> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(object) => begin(&mut **object).await,
            #[cfg(feature = "sqlite")]
            Self::Sqlite(object) => {
                object
                    .spawn_blocking(|connection| {
                        diesel::connection::AnsiTransactionManager::begin_transaction_sql(
                            connection,
                            "BEGIN IMMEDIATE",
                        )
                    })
                    .await
            }
        }
    }

    /// End the transaction begun by
    /// [`begin_transaction`](Self::begin_transaction): commit when `result`
    /// is `Ok`, roll back when it is `Err`.
    ///
    /// A failed rollback is logged and the original error returned; the pool
    /// discards the connection because its transaction is still open.
    pub(crate) async fn finish_transaction<T>(&mut self, result: AuthResult<T>) -> AuthResult<T> {
        match result {
            Ok(value) => {
                with_connection!(self, |c| commit(c).await).map_err(map_query_err)?;
                Ok(value)
            }
            Err(err) => {
                if let Err(rollback_err) = with_connection!(self, |c| rollback(c).await) {
                    tracing::warn!(error = %rollback_err, "failed to roll back auth transaction");
                }
                Err(err)
            }
        }
    }
}

#[cfg(feature = "postgres")]
async fn begin<C: diesel_async::AsyncConnection>(connection: &mut C) -> diesel::QueryResult<()> {
    <C::TransactionManager as diesel_async::TransactionManager<C>>::begin_transaction(connection)
        .await
}

async fn commit<C: diesel_async::AsyncConnection>(connection: &mut C) -> diesel::QueryResult<()> {
    <C::TransactionManager as diesel_async::TransactionManager<C>>::commit_transaction(connection)
        .await
}

async fn rollback<C: diesel_async::AsyncConnection>(connection: &mut C) -> diesel::QueryResult<()> {
    <C::TransactionManager as diesel_async::TransactionManager<C>>::rollback_transaction(connection)
        .await
}
