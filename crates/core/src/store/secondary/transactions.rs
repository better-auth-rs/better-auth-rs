use super::SecondaryStore;
use crate::store::{AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork};
use crate::types::{CreateAccount, CreateSession, CreateUser};
use crate::{AuthError, AuthResult, AuthSchema};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

enum CommittedEffect<S: AuthSchema> {
    Session(S::Session),
    Verification(S::Verification),
    UserUpdated(S::User),
    UserDeleted {
        id: String,
        sessions: Vec<super::sessions::SessionReference>,
    },
}

struct Transaction<'a, S: AuthSchema> {
    inner: &'a dyn AuthTransaction<S>,
    runtime: SecondaryStore<S>,
    effects: Arc<Mutex<Vec<CommittedEffect<S>>>>,
}

#[async_trait]
impl<S: AuthSchema> AuthTransaction<S> for Transaction<'_, S> {
    async fn create_verification(
        &self,
        input: crate::CreateVerification,
    ) -> AuthResult<S::Verification> {
        let verification = self
            .runtime
            .create_verification_in_transaction(input, Some(self.inner))
            .await?;
        if !self.runtime.database_verifications() {
            self.effects
                .lock()
                .map_err(|_| AuthError::internal("Transaction cache queue lock poisoned"))?
                .push(CommittedEffect::Verification(verification.clone()));
        }
        Ok(verification)
    }
    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.runtime
            .find_verification_in_transaction(identifier, Some(self.inner))
            .await
    }
    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        self.inner.delete_expired_verifications().await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_id(id).await
    }
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_email(email).await
    }
    async fn update_user(&self, id: &str, update: crate::UpdateUser) -> AuthResult<S::User> {
        let user = self.inner.update_user(id, update).await?;
        self.effects
            .lock()
            .map_err(|_| AuthError::internal("Transaction cache queue lock poisoned"))?
            .push(CommittedEffect::UserUpdated(user.clone()));
        Ok(user)
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        if self.runtime.storage.is_none() {
            return self.inner.delete_user(id).await;
        }
        let sessions = self.runtime.references(id).await?;
        self.inner.delete_user(id).await?;
        self.effects
            .lock()
            .map_err(|_| AuthError::internal("Transaction cache queue lock poisoned"))?
            .push(CommittedEffect::UserDeleted {
                id: id.to_owned(),
                sessions,
            });
        Ok(())
    }
    async fn create_passkey(&self, input: crate::CreatePasskey) -> AuthResult<crate::Passkey> {
        self.inner.create_passkey(input).await
    }
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
        self.effects
            .lock()
            .map_err(|_| AuthError::internal("Session transaction queue lock poisoned"))?
            .push(CommittedEffect::Session(session.clone()));
        Ok(session)
    }
}

#[async_trait]
impl<S: AuthSchema> TransactionStore<S> for SecondaryStore<S> {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        let effects = Arc::new(Mutex::new(Vec::new()));
        let queued = effects.clone();
        let runtime = self.clone();
        let result = self
            .inner
            .transaction_boxed(Box::new(move |inner| {
                Box::pin(async move {
                    work(&Transaction {
                        inner,
                        runtime,
                        effects: queued,
                    })
                    .await
                })
            }))
            .await?;
        let committed = std::mem::take(
            &mut *effects
                .lock()
                .map_err(|_| AuthError::internal("Session transaction queue lock poisoned"))?,
        );
        for effect in committed {
            let session = match effect {
                CommittedEffect::Session(session) => session,
                CommittedEffect::Verification(verification) => {
                    self.inner
                        .after_create_runtime_verification(&verification)
                        .await?;
                    continue;
                }
                CommittedEffect::UserUpdated(user) => {
                    // Upstream runs cache refresh after commit and logs backend failures.
                    if let Err(error) = self.refresh_user_sessions(&user).await {
                        tracing::error!(%error, "Failed to refresh committed user sessions in secondary storage");
                    }
                    continue;
                }
                CommittedEffect::UserDeleted { id, sessions } => {
                    if let Err(error) = self.delete_cached_sessions(&id, &sessions).await {
                        tracing::error!(%error, "Failed to delete committed user sessions from secondary storage");
                    }
                    continue;
                }
            };
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
