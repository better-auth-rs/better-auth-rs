use super::{SecondaryStore, cache};
use crate::entity::AuthUser;
use crate::store::{AuthTransaction, UserStore, VerificationCleanup, VerificationSessionCleanup};
use crate::types::{CreateUser, ListUsersParams, UpdateUser};
use crate::wire::UserView;
use crate::{AuthError, AuthResult, AuthSchema, FieldDate, FieldMap, FieldValue, SchemaValue};
use async_trait::async_trait;

#[cfg(test)]
mod tests;

struct CachedVerificationSessions<'a, S: AuthSchema> {
    store: &'a SecondaryStore<S>,
    user_id: &'a str,
    references: &'a [super::sessions::SessionReference],
}

fn cached_expiration(value: FieldValue) -> SchemaValue<FieldDate> {
    SchemaValue::from_field(match value {
        FieldValue::String(text) => match crate::utils::json::parse_json_date(&text) {
            Some(date) => FieldDate::from(date).into(),
            None => FieldValue::String(text),
        },
        value => value,
    })
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
    pub(super) async fn queue_user_session_refresh(
        &self,
        user: Option<UserView>,
        transaction: Option<&dyn AuthTransaction<S>>,
    ) -> AuthResult<()> {
        let runtime = self.clone();
        let effect = Box::pin(async move {
            // Only refresh failures use the upstream onError policy; ordinary after hooks propagate.
            if let Err(error) = runtime.refresh_user_sessions(user.as_ref()).await {
                runtime.config.logger.error(
                    "Failed to refresh committed user sessions in secondary storage",
                    &[crate::observability::LogArgument::Error(&error)],
                );
            }
            Ok(())
        });
        match transaction {
            Some(transaction) => transaction.queue_after_commit(effect),
            None => effect.await,
        }
    }

    async fn refresh_user_sessions(&self, user: Option<&UserView>) -> AuthResult<()> {
        if self.storage.is_none() {
            return Ok(());
        }
        let user =
            user.ok_or_else(|| AuthError::internal("Cannot refresh sessions for a missing user"))?;
        let user = UserView::with_internal_fields_for_adapter(
            user,
            &self.config.user,
            &self.metadata,
            self.inner.supports_native_json(),
        )
        .await?;
        let references = cache::decode(
            self.secondary()?
                .get_native(&format!("active-sessions-{}", user.id.display_string()?).into())
                .await?,
        )
        .unwrap_or_default();
        if !references.is_truthy() {
            return Ok(());
        }
        let now = self.now();
        let references = references
            .as_array()
            .ok_or_else(|| AuthError::internal("Cached user session index must be an array"))?;
        let mut tokens = Vec::new();
        for reference in references {
            if reference.is_null() {
                return Err(AuthError::internal(
                    "Cached user session index entry cannot be null",
                ));
            }
            let fields = reference.as_object();
            let expires = fields
                .and_then(|fields| fields.get("expiresAt"))
                .cloned()
                .unwrap_or_default();
            if cached_expiration(expires).is_after(now)? {
                tokens.push(
                    fields
                        .and_then(|fields| fields.get("token"))
                        .cloned()
                        .unwrap_or_default(),
                );
            }
        }
        let count = tokens.len();
        let mut fields = FieldMap::from(user);
        let mut ordered = FieldMap::new();
        let configured = self.config.user.user_adapter_fields();
        // Runtime configuration omits unchanged native fields; emit their slots first and append only an implicit ID after other fields.
        for name in crate::user_fields::USER_FIELDS
            .iter()
            .copied()
            .chain(configured.fields().keys().map(String::as_str))
        {
            if let Some(value) = fields.remove(name) {
                let _ = ordered.insert(name.to_owned(), value);
            }
        }
        let id = fields.remove("id");
        ordered.extend(fields);
        if let Some(id) = id {
            let _ = ordered.insert("id".into(), id);
        }
        let user = FieldValue::from(ordered);
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let runtime = self.clone();
        // Promise.all rejects on the first failure while already-started peers continue.
        let task = crate::request_runtime::spawn_with_request_context(async move {
            let runtime = &runtime;
            let user = &user;
            let _ = futures_util::future::join_all(tokens.into_iter().map(|token| {
                let sender = sender.clone();
                async move {
                    let result = runtime.refresh_cached_user_session(&token, user, now).await;
                    let _ = sender.send(result);
                }
            }))
            .await;
        });
        for _ in 0..count {
            let Some(result) = receiver.recv().await else {
                break;
            };
            result?;
        }
        match task.await {
            Ok(()) => Ok(()),
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => Err(AuthError::internal(format!(
                "User session refresh task: {error}"
            ))),
        }
    }

    async fn refresh_cached_user_session(
        &self,
        token: &FieldValue,
        user: &FieldValue,
        now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<()> {
        let Some(cached) = cache::decode(self.secondary()?.get_native(token).await?) else {
            return Ok(());
        };
        let session = cached
            .as_object()
            .and_then(|cached| cached.get("session"))
            .ok_or_else(|| {
                AuthError::internal("Cached user session refresh requires a session object")
            })?;
        let expires = session
            .as_object()
            .and_then(|session| session.get("expiresAt"))
            .cloned()
            .unwrap_or_default();
        let seconds = cached_expiration(expires).cache_ttl(now)?;
        let envelope = FieldValue::from(FieldMap::from([
            ("session".into(), session.clone()),
            ("user".into(), user.clone()),
        ]));
        self.secondary()?
            .set_native(token, &cache::stringify(&envelope)?, Some(seconds))
            .await?;
        Ok(())
    }
}

#[async_trait]
impl<S: AuthSchema> UserStore<S> for SecondaryStore<S> {
    fn supports_native_json(&self) -> bool {
        self.inner.supports_native_json()
    }
    async fn get_user_by_id_value(
        &self,
        id: &crate::FieldValue,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_id_value(id).await
    }

    async fn verify_user_with_cleanup(
        &self,
        user_id: &str,
        cleanup: VerificationCleanup,
        sessions: Option<&dyn VerificationSessionCleanup>,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner
            .verify_user_with_cleanup(user_id, cleanup, sessions)
            .await
    }

    async fn verify_user_and_revoke_unproven_access(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<crate::wire::UserView>> {
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
            .is_some_and(|user| !user.email_verified().field_value().is_truthy());
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
        self.queue_user_session_refresh(user.clone(), None).await?;
        Ok(user)
    }
    async fn create_user_optional(
        &self,
        input: CreateUser,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.create_user_optional(input).await
    }
    async fn create_user(&self, input: CreateUser) -> AuthResult<crate::wire::UserView> {
        self.inner.create_user(input).await
    }
    async fn get_user_by_id_field(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_id_field(id).await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_id(id).await
    }
    async fn list_users_by_ids(
        &self,
        ids: &[String],
        limit: f64,
    ) -> AuthResult<Vec<crate::wire::UserView>> {
        self.inner.list_users_by_ids(ids, limit).await
    }
    async fn get_user_with_accounts(
        &self,
        email: &str,
    ) -> AuthResult<Option<crate::store::UserAccounts>> {
        self.inner.get_user_with_accounts(email).await
    }
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_email(email).await
    }
    async fn get_user_by_username(
        &self,
        username: &str,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_username(username).await
    }
    async fn get_user_by_phone_number(
        &self,
        phone: &str,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_phone_number(phone).await
    }
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<crate::wire::UserView> {
        let user = self.inner.update_user(id, update).await?;
        self.queue_user_session_refresh(Some(user.clone()), None)
            .await?;
        Ok(user)
    }
    async fn update_user_optional(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<Option<crate::UserView>> {
        self.update_user_by_id_value(&crate::FieldValue::from(id), update)
            .await
    }
    async fn update_user_by_id_value(
        &self,
        id: &crate::FieldValue,
        update: UpdateUser,
    ) -> AuthResult<Option<crate::UserView>> {
        let user = self.inner.update_user_by_id_value(id, update).await?;
        self.queue_user_session_refresh(user.clone(), None).await?;
        Ok(user)
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        if self.storage.is_none() {
            return self.inner.delete_user(id).await;
        }
        let references = self.references(id).await?;
        let removed = self
            .inner
            .delete_user_optional(id, self.database_sessions())
            .await?;
        if removed.is_some() {
            self.queue_cached_user_session_deletion(id.to_owned(), references, None)
                .await?;
        }
        Ok(())
    }
    async fn delete_user_optional(
        &self,
        id: &str,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner
            .delete_user_optional(id, delete_database_sessions)
            .await
    }

    async fn list_users(
        &self,
        params: ListUsersParams,
    ) -> AuthResult<(Vec<crate::wire::UserView>, usize)> {
        self.inner.list_users(params).await
    }
}
