use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{
    ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, ExecResult, QueryResult, Statement,
};
use tokio::sync::RwLock;

enum State {
    Active(DatabaseTransaction),
    Committed,
    RolledBack,
    Failed(DbErr),
}

impl State {
    fn active(&self) -> Result<&DatabaseTransaction, DbErr> {
        match self {
            Self::Active(transaction) => Ok(transaction),
            Self::Committed => Err(DbErr::Custom("Transaction is already committed".into())),
            Self::RolledBack => Err(DbErr::Custom("Transaction is already rolled back".into())),
            Self::Failed(error) => Err(error.clone()),
        }
    }
}

/// A retained SQL transaction connection with explicit commit and rollback state.
/// Query locks cover one database operation, so callbacks do not delay finalization.
#[derive(Clone)]
pub struct TransactionConnection {
    backend: DbBackend,
    state: Arc<RwLock<State>>,
}

impl TransactionConnection {
    pub(crate) fn new(transaction: DatabaseTransaction) -> Self {
        Self {
            backend: transaction.get_database_backend(),
            state: Arc::new(RwLock::new(State::Active(transaction))),
        }
    }

    pub(crate) async fn commit(&self) -> Result<(), DbErr> {
        let mut state = self.state.write().await;
        let transaction = match std::mem::replace(&mut *state, State::Committed) {
            State::Active(transaction) => transaction,
            previous => {
                *state = previous;
                return state.active().map(|_| ());
            }
        };
        if let Err(error) = transaction.commit().await {
            *state = State::Failed(error.clone());
            return Err(error);
        }
        Ok(())
    }

    pub(crate) async fn rollback(&self) -> Result<(), DbErr> {
        let mut state = self.state.write().await;
        let transaction = match std::mem::replace(&mut *state, State::RolledBack) {
            State::Active(transaction) => transaction,
            previous => {
                *state = previous;
                return state.active().map(|_| ());
            }
        };
        if let Err(error) = transaction.rollback().await {
            *state = State::Failed(error.clone());
            return Err(error);
        }
        Ok(())
    }
}

#[async_trait]
impl ConnectionTrait for TransactionConnection {
    fn get_database_backend(&self) -> DbBackend {
        self.backend
    }

    async fn execute_raw(&self, statement: Statement) -> Result<ExecResult, DbErr> {
        self.state
            .read()
            .await
            .active()?
            .execute_raw(statement)
            .await
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        self.state
            .read()
            .await
            .active()?
            .execute_unprepared(sql)
            .await
    }

    async fn query_one_raw(&self, statement: Statement) -> Result<Option<QueryResult>, DbErr> {
        self.state
            .read()
            .await
            .active()?
            .query_one_raw(statement)
            .await
    }

    async fn query_all_raw(&self, statement: Statement) -> Result<Vec<QueryResult>, DbErr> {
        self.state
            .read()
            .await
            .active()?
            .query_all_raw(statement)
            .await
    }
}
