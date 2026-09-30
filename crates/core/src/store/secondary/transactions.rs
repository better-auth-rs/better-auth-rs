use super::SecondaryStore;
use crate::store::{AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork};
use crate::types::{CreateAccount, CreateSession, CreateUser};
use crate::{AuthError, AuthResult, AuthSchema};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

struct Transaction<'a, S: AuthSchema> {
    inner: &'a dyn AuthTransaction<S>,
    runtime: SecondaryStore<S>,
    sessions: Arc<Mutex<Vec<S::Session>>>,
}

#[async_trait]
impl<S: AuthSchema> AuthTransaction<S> for Transaction<'_, S> {
    async fn create_user(&self, input: CreateUser) -> AuthResult<S::User> {
        self.inner.create_user(input).await
    }
    async fn create_account(&self, input: CreateAccount) -> AuthResult<S::Account> {
        self.inner.create_account(input).await
    }
    async fn create_session(&self, mut input: CreateSession) -> AuthResult<S::Session> {
        let session = if self.runtime.database_sessions() {
            self.inner.create_session(input).await?
        } else {
            self.inner.before_create_runtime_session(&mut input).await?;
            self.runtime.new_session(input)?
        };
        self.sessions
            .lock()
            .map_err(|_| AuthError::internal("Session transaction queue lock poisoned"))?
            .push(session.clone());
        Ok(session)
    }
}

#[async_trait]
impl<S: AuthSchema> TransactionStore<S> for SecondaryStore<S> {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        if self.storage.is_none() {
            return self.inner.transaction_boxed(work).await;
        }
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let queued = sessions.clone();
        let runtime = self.clone();
        let result = self
            .inner
            .transaction_boxed(Box::new(move |inner| {
                Box::pin(async move {
                    work(&Transaction {
                        inner,
                        runtime,
                        sessions: queued,
                    })
                    .await
                })
            }))
            .await?;
        let committed = std::mem::take(
            &mut *sessions
                .lock()
                .map_err(|_| AuthError::internal("Session transaction queue lock poisoned"))?,
        );
        for session in committed {
            if let Err(error) = self.mirror_session(&session).await {
                // Upstream tolerates mirror failure after commit only when database session fallback is available.
                if self.database_sessions() && !self.config.session.preserve_session_in_database {
                    tracing::error!(%error, "Failed to mirror committed session to secondary storage");
                } else {
                    return Err(error);
                }
            }
            if !self.database_sessions() {
                self.inner.after_create_runtime_session(&session).await?;
            }
        }
        Ok(result)
    }
}
