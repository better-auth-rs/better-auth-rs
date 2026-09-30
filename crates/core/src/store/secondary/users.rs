use super::{SecondaryStore, decode, ttl};
use crate::entity::AuthUser;
use crate::store::{UserStore, VerificationCleanup, VerificationSessionCleanup};
use crate::types::{CreateUser, ListUsersParams, UpdateUser};
use crate::wire::UserView;
use crate::{AuthResult, AuthSchema};
use async_trait::async_trait;
use serde_json::json;

struct CachedVerificationSessions<'a, S: AuthSchema> {
    store: &'a SecondaryStore<S>,
    user_id: &'a str,
    references: &'a [super::sessions::SessionReference],
}

#[async_trait]
impl<S: AuthSchema> VerificationSessionCleanup for CachedVerificationSessions<'_, S> {
    async fn revoke(&self) -> AuthResult<()> {
        self.store
            .delete_cached_sessions(self.user_id, self.references)
            .await
    }
}

impl<S: AuthSchema> SecondaryStore<S> {
    async fn refresh_user_sessions(&self, user: &S::User) -> AuthResult<()> {
        if self.storage.is_none() {
            return Ok(());
        }
        let user = UserView::with_internal_fields_for_adapter(
            user,
            &self.config.user,
            &self.metadata,
            self.inner.supports_native_json(),
        )?;
        for reference in self.references(&user.id).await? {
            if reference.expires_at <= chrono::Utc::now().timestamp_millis() {
                continue;
            }
            let Some(mut cached) = decode(self.secondary()?.get(&reference.token).await?) else {
                continue;
            };
            let Some(session) = cached.get("session") else {
                continue;
            };
            let expires =
                serde_json::from_value(session.get("expiresAt").cloned().unwrap_or_default())?;
            let _ = cached
                .as_object_mut()
                .ok_or_else(|| crate::AuthError::internal("Cached session must be an object"))?
                .insert("user".into(), json!(user));
            self.secondary()?
                .set(
                    &reference.token,
                    &serde_json::to_string(&cached)?,
                    Some(ttl(expires)),
                )
                .await?;
        }
        Ok(())
    }
}

#[async_trait]
impl<S: AuthSchema> UserStore<S> for SecondaryStore<S> {
    fn supports_native_json(&self) -> bool {
        self.inner.supports_native_json()
    }
    async fn get_user_by_id_value(&self, id: &serde_json::Value) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_id_value(id).await
    }

    async fn verify_user_with_cleanup(
        &self,
        user_id: &str,
        cleanup: VerificationCleanup,
        sessions: Option<&dyn VerificationSessionCleanup>,
    ) -> AuthResult<Option<S::User>> {
        self.inner
            .verify_user_with_cleanup(user_id, cleanup, sessions)
            .await
    }

    async fn verify_user_and_revoke_unproven_access(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<S::User>> {
        if self.storage.is_none() {
            return self
                .inner
                .verify_user_and_revoke_unproven_access(user_id)
                .await;
        }
        let unverified = self
            .inner
            .get_user_by_id(user_id)
            .await?
            .is_some_and(|user| !user.email_verified());
        let references = if unverified {
            self.references(user_id).await?
        } else {
            Vec::new()
        };
        let cleanup = if self.database_sessions() {
            VerificationCleanup::AccountsAndSessions
        } else {
            VerificationCleanup::Accounts
        };
        let sessions = CachedVerificationSessions {
            store: self,
            user_id,
            references: &references,
        };
        let user = self
            .inner
            .verify_user_with_cleanup(user_id, cleanup, Some(&sessions))
            .await?;
        if let Some(user) = &user {
            self.refresh_user_sessions(user).await?;
        }
        Ok(user)
    }
    async fn create_user(&self, input: CreateUser) -> AuthResult<S::User> {
        self.inner.create_user(input).await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_id(id).await
    }
    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<S::User>> {
        self.inner.list_users_by_ids(ids).await
    }
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_email(email).await
    }
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_username(username).await
    }
    async fn get_user_by_phone_number(&self, phone: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_phone_number(phone).await
    }
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<S::User> {
        let user = self.inner.update_user(id, update).await?;
        self.refresh_user_sessions(&user).await?;
        Ok(user)
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        if self.storage.is_none() {
            return self.inner.delete_user(id).await;
        }
        let references = self.references(id).await?;
        self.inner.delete_user(id).await?;
        self.delete_cached_sessions(id, &references).await
    }
    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)> {
        self.inner.list_users(params).await
    }
}
