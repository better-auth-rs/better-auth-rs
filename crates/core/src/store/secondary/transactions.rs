use super::SecondaryStore;
use crate::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
    TypedTransactionFuture,
};
use crate::types::{CreateAccount, CreateSession, CreateUser};
use crate::{AuthResult, AuthSchema};
use async_trait::async_trait;

struct Transaction<'a, S: AuthSchema> {
    inner: &'a dyn AuthTransaction<S>,
    runtime: SecondaryStore<S>,
}

impl<S: AuthSchema> Transaction<'_, S> {
    async fn create_session_with_storage(
        &self,
        mut input: CreateSession,
        deferred: bool,
    ) -> AuthResult<S::Session> {
        let session = if self.runtime.database_sessions() {
            self.inner.create_session(input).await?
        } else {
            self.inner.before_create_runtime_session(&mut input).await?;
            self.runtime.new_session(input)?
        };
        if !deferred {
            self.runtime
                .mirror_session_in_transaction(&session, Some(self.inner))
                .await?;
        }
        if !self.runtime.database_sessions() {
            let runtime = self.runtime.clone();
            let created = session.clone();
            self.inner.queue_after_commit(Box::pin(async move {
                runtime.inner.after_create_runtime_session(&created).await
            }))?;
        }
        if deferred {
            let runtime = self.runtime.clone();
            let created = session.clone();
            self.inner.queue_after_commit(Box::pin(async move {
                if let Err(error) = runtime.mirror_session(&created).await {
                    // Upstream tolerates a committed mirror failure only with database fallback.
                    if runtime.database_sessions()
                        && !runtime.config.session.preserve_session_in_database
                    {
                        tracing::error!(%error, "Failed to mirror committed session to secondary storage");
                    } else {
                        return Err(error);
                    }
                }
                Ok(())
            }))?;
        }
        Ok(session)
    }
}

#[async_trait]
impl<S: AuthSchema> AuthTransaction<S> for Transaction<'_, S> {
    fn queue_after_commit(&self, effect: TypedTransactionFuture<'static, ()>) -> AuthResult<()> {
        self.inner.queue_after_commit(effect)
    }

    async fn create_verification(
        &self,
        input: crate::CreateVerification,
    ) -> AuthResult<S::Verification> {
        let verification = self
            .runtime
            .create_verification_in_transaction(input, Some(self.inner))
            .await?;
        if !self.runtime.database_verifications() {
            let runtime = self.runtime.clone();
            let created = verification.clone();
            self.inner.queue_after_commit(Box::pin(async move {
                runtime
                    .inner
                    .after_create_runtime_verification(&created)
                    .await
            }))?;
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
        let runtime = self.runtime.clone();
        let updated = user.clone();
        self.inner.queue_after_commit(Box::pin(async move {
            // Upstream logs a committed cache refresh failure and continues the hook queue.
            if let Err(error) = runtime.refresh_user_sessions(&updated).await {
                tracing::error!(%error, "Failed to refresh committed user sessions in secondary storage");
            }
            Ok(())
        }))?;
        Ok(user)
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        if self.runtime.storage.is_none() {
            return self.inner.delete_user(id).await;
        }
        let sessions = self.runtime.references(id).await?;
        self.inner.delete_user(id).await?;
        let runtime = self.runtime.clone();
        let id = id.to_owned();
        self.inner.queue_after_commit(Box::pin(async move {
            if let Err(error) = runtime.delete_cached_sessions(&id, &sessions).await {
                tracing::error!(%error, "Failed to delete committed user sessions from secondary storage");
            }
            Ok(())
        }))
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
    async fn create_session(&self, input: CreateSession) -> AuthResult<S::Session> {
        self.create_session_with_storage(input, false).await
    }
    async fn create_session_with_deferred_secondary(
        &self,
        input: CreateSession,
    ) -> AuthResult<S::Session> {
        self.create_session_with_storage(input, true).await
    }
}

#[async_trait]
impl<S: AuthSchema> TransactionStore<S> for SecondaryStore<S> {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        let runtime = self.clone();
        self.inner
            .transaction_boxed(Box::new(move |inner| {
                Box::pin(async move { work(&Transaction { inner, runtime }).await })
            }))
            .await
    }
}

#[async_trait]
impl<S: AuthSchema> crate::store::JwksStore for Transaction<'_, S> {
    async fn list_jwks(&self) -> AuthResult<Vec<crate::Jwk>> {
        crate::store::JwksStore::list_jwks(self.inner).await
    }
    async fn create_jwk(&self, input: crate::CreateJwk) -> AuthResult<crate::Jwk> {
        crate::store::JwksStore::create_jwk(self.inner, input).await
    }
}
