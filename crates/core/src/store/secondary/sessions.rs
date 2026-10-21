use super::{SecondaryStore, cache};
use crate::entity::AuthSession;
use crate::store::database_hooks::SessionUpdate;
use crate::store::{
    SessionStore, SessionUpdateWriter, SessionUpdateWriterFactory, SessionWriteEffects,
    TeamMemberLimits,
};
use crate::types::{CreateSession, Invitation, Member};
use crate::wire::{SessionView, UserView};
use crate::{AuthError, AuthResult, AuthSchema, FieldMap, FieldValue};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

mod deletion;
#[cfg(test)]
mod logging_tests;
pub(super) mod references;

pub(super) fn active_sessions_key(user_id: &FieldValue) -> AuthResult<FieldValue> {
    let user_id = user_id.display_utf16()?;
    let mut units: Vec<_> = "active-sessions-".encode_utf16().collect();
    units.extend_from_slice(user_id.as_utf16());
    Ok(crate::Utf16String::from_units(units).into())
}

impl<S: AuthSchema> SecondaryStore<S> {
    pub(super) fn session_create_writer(
        &self,
        owner: crate::SchemaValue<String>,
        deferred: bool,
        transaction: Option<std::sync::Arc<dyn crate::store::AuthTransaction<S>>>,
    ) -> Option<crate::store::SessionCreateWriter> {
        let _ = self.storage.as_ref()?;
        let runtime = self.clone();
        Some(crate::store::SessionCreateWriter {
            write_database: self.database_sessions(),
            deferred,
            write: Box::new(move |original, session| {
                Box::pin(async move {
                    let result = runtime
                        .mirror_created_session(&owner, original, &session, transaction.as_deref())
                        .await;
                    if deferred
                        && runtime.database_sessions()
                        && !runtime.config.session.preserve_session_in_database()
                    {
                        if let Err(error) = result {
                            runtime.config.logger()?.error(
                                "Failed to mirror committed session to secondary storage",
                                &[crate::observability::LogArgument::Error(&error)],
                            )?;
                        }
                        Ok(())
                    } else {
                        result
                    }
                })
            }),
        })
    }

    async fn mirror_created_session(
        &self,
        owner: &crate::SchemaValue<String>,
        original: FieldMap,
        session: &FieldMap,
        transaction: Option<&dyn crate::store::AuthTransaction<S>>,
    ) -> AuthResult<()> {
        let user_id = owner.field_value();
        let token = original.get("token").cloned().unwrap_or_default();
        let current = self
            .secondary()?
            .clone()
            .invoke_get_native(active_sessions_key(&user_id)?)?
            .await?;
        let now = self.now();
        let current = cache::decode(current)?.unwrap_or_else(references::empty);
        let filter_token = token.clone();
        let retained = references::filter(&current, move |reference| {
            Ok(
                crate::query::field_number(&reference.model_property("expiresAt")?)?
                    > now.timestamp_millis() as f64
                    && !reference
                        .model_property("token")?
                        .strict_equals(&filter_token),
            )
        })?;
        let mut references = references::iter(&retained)?.collect::<AuthResult<Vec<_>>>()?;
        let expiry = original.get("expiresAt").cloned().unwrap_or_default();
        references.push(references::new(
            token.clone(),
            expiry.get_time_method("data.expiresAt")?,
        ));
        let references = references::sort(&references.into())?;
        let furthest = references::last_expiration(&references)?;
        let furthest = if furthest.is_null() || furthest.is_undefined() {
            expiry.get_time_method("data.expiresAt")?
        } else {
            furthest
        };
        let seconds =
            crate::SchemaValue::<crate::FieldDate>::from_field(furthest).cache_ttl(now)?;
        if seconds > 0.0 {
            self.secondary()?
                .clone()
                .invoke_set_native(
                    active_sessions_key(&user_id)?,
                    references.stringify_native()?,
                    Some(Some(seconds)),
                )?
                .await?;
        }
        let user = match transaction {
            Some(transaction) => transaction.get_user_by_id_field(owner).await?,
            None => self.inner.get_user_by_id_field(owner).await?,
        };
        let seconds = crate::SchemaValue::<crate::FieldDate>::from_field(expiry).cache_ttl(now)?;
        if seconds > 0.0 {
            let value = cache::session_envelope(session.clone(), user);
            self.secondary()?
                .clone()
                .invoke_set_native(token, value.stringify_native()?, Some(Some(seconds)))?
                .await?;
        }
        Ok(())
    }

    pub(super) async fn references_value(&self, user_id: &FieldValue) -> AuthResult<FieldValue> {
        Ok(cache::decode(
            self.secondary()?
                .clone()
                .invoke_get_native(active_sessions_key(user_id)?)?
                .await?,
        )?
        .unwrap_or_else(references::empty))
    }

    async fn write_references(
        &self,
        key: &FieldValue,
        references: &FieldValue,
        expires_at: FieldValue,
        now: DateTime<Utc>,
    ) -> AuthResult<()> {
        let encoded = references.stringify_native()?;
        let seconds =
            crate::SchemaValue::<crate::FieldDate>::from_field(expires_at).cache_ttl(now)?;
        self.secondary()?
            .clone()
            .invoke_set_native(key.clone(), encoded, Some(Some(seconds)))?
            .await
    }

    async fn update_cached_session(
        &self,
        token: &FieldValue,
        patch: FieldMap,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        let Some(cached) = cache::decode(
            self.secondary()?
                .clone()
                .invoke_get_native(token.clone())?
                .await?,
        )?
        else {
            return Ok(None);
        };
        let mut fields = cached.model_property("session")?.enumerable_fields()?;
        fields.extend(patch.clone());
        for name in ["expiresAt", "createdAt", "updatedAt"] {
            let value = if name != "createdAt"
                && let Some(value) = patch
                    .get(name)
                    .filter(|value| !value.is_null() && !value.is_undefined())
            {
                value.clone()
            } else {
                cached.model_property("session")?.model_property(name)?
            };
            let _ = fields.insert(name.into(), crate::query::field_date(&value)?.into());
        }
        let mut updated = cache::session(fields)?;
        updated.filter_returned_fields(&self.config.session)?;
        let now = self.now();
        let expires_at = updated.expires_at().converted_date()?.date_milliseconds()?;
        let seconds =
            crate::SchemaValue::<crate::FieldDate>::from_field(expires_at.into()).cache_ttl(now)?;
        if seconds > 0.0 {
            let envelope = FieldMap::from([
                ("session".into(), FieldMap::from(updated.clone()).into()),
                ("user".into(), cached.model_property("user")?),
            ]);
            self.secondary()?
                .clone()
                .invoke_set_native(
                    token.clone(),
                    FieldValue::from(envelope).stringify_native()?,
                    Some(Some(seconds)),
                )?
                .await?;
            let key = active_sessions_key(&updated.user_id.field_value())?;
            let current = cache::decode(
                self.secondary()?
                    .clone()
                    .invoke_get_native(key.clone())?
                    .await?,
            )?
            .unwrap_or_else(references::empty);
            let filter_token = token.clone();
            let filtered = references::filter(&current, move |reference| {
                Ok(!reference
                    .model_property("token")?
                    .strict_equals(&filter_token)
                    && crate::query::field_number(&reference.model_property("expiresAt")?)?
                        > now.timestamp_millis() as f64)
            })?;
            let references = filtered.concat_method(
                &[vec![references::new(token.clone(), expires_at.into())].into()],
                "references",
            )?;
            let references = references::sort(&references)?;
            let furthest = references::last_expiration(&references)?;
            if furthest.is_truthy()
                && crate::query::field_number(&furthest)? > now.timestamp_millis() as f64
            {
                self.write_references(&key, &references, furthest, now)
                    .await?;
            } else {
                self.secondary()?.clone().invoke_delete_native(key)?.await?;
            }
        }
        Ok(Some(updated))
    }

    async fn update_runtime_session(
        &self,
        token: &str,
        update: SessionUpdate,
    ) -> AuthResult<Option<SessionView>> {
        self.update_runtime_session_by_token_value(&token.into(), update)
            .await
    }

    async fn update_runtime_session_by_token_value(
        &self,
        token: &FieldValue,
        update: SessionUpdate,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        self.inner
            .update_session_with_writer_by_token_value(
                token,
                update,
                self.session_update_writer_factory()
                    .map(|writer| writer.bind(token.clone())),
            )
            .await
    }

    pub(super) fn session_update_writer_factory(&self) -> Option<SessionUpdateWriterFactory> {
        let _ = self.storage.as_ref()?;
        let runtime = self.clone();
        Some(SessionUpdateWriterFactory {
            write_database: self.database_sessions(),
            write: std::sync::Arc::new(move |token, update| {
                let runtime = runtime.clone();
                Box::pin(async move { runtime.update_cached_session(&token, update).await })
            }),
        })
    }

    pub(super) async fn queue_cached_user_session_deletion_value(
        &self,
        user_id: FieldValue,
        references: FieldValue,
        transaction: Option<&dyn crate::store::AuthTransaction<S>>,
    ) -> AuthResult<()> {
        let runtime = self.clone();
        let effect = Box::pin(async move {
            runtime
                .delete_committed_cached_sessions(&user_id, &references)
                .await
        });
        match transaction {
            Some(transaction) => transaction.queue_after_commit(effect),
            None => effect.await,
        }
    }

    /// Queue the cached-session removal before a transactional deletion queues its after hooks.
    ///
    /// The commit runs its effects in order and stops at the first error. Queued first, the
    /// removal still runs when a later after hook fails. It does nothing unless the caller
    /// sets the returned flag, so a cancelled deletion keeps its cached sessions.
    pub(super) fn queue_armed_cached_user_session_deletion(
        &self,
        user_id: FieldValue,
        references: FieldValue,
        transaction: &dyn crate::store::AuthTransaction<S>,
    ) -> AuthResult<std::sync::Arc<std::sync::atomic::AtomicBool>> {
        let armed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let runtime = self.clone();
        let deleted = armed.clone();
        transaction.queue_after_commit(Box::pin(async move {
            if !deleted.load(std::sync::atomic::Ordering::Acquire) {
                return Ok(());
            }
            runtime
                .delete_committed_cached_sessions(&user_id, &references)
                .await
        }))?;
        Ok(armed)
    }

    async fn delete_committed_cached_sessions(
        &self,
        user_id: &FieldValue,
        references: &FieldValue,
    ) -> AuthResult<()> {
        // Upstream applies this onError policy both after commit and without a transaction.
        if let Err(error) = self.delete_cached_sessions_value(user_id, references).await {
            self.config.logger()?.error(
                "Failed to delete committed user sessions from secondary storage",
                &[crate::observability::LogArgument::Error(&error)],
            )?;
        }
        Ok(())
    }

    async fn delete_cached_sessions_value(
        &self,
        user_id: &FieldValue,
        references: &FieldValue,
    ) -> AuthResult<()> {
        let deleted_tokens =
            references::iter(&references::tokens(references)?)?.collect::<AuthResult<Vec<_>>>()?;
        for reference in references::iter(references)? {
            self.secondary()?
                .clone()
                .invoke_delete_native(reference?.model_property("token")?)?
                .await?;
        }
        let key = active_sessions_key(user_id)?;
        let current = self.references_value(user_id).await?;
        let now = self.now();
        let remaining = references::filter(&current, move |reference| {
            let live = crate::query::field_number(&reference.model_property("expiresAt")?)?
                > now.timestamp_millis() as f64;
            if !live {
                return Ok(false);
            }
            let token = reference.model_property("token")?;
            Ok(!deleted_tokens
                .iter()
                .any(|deleted| deleted.same_value_zero(&token)))
        })?;
        let _ = references::sort(&remaining)?;
        let furthest = references::last_expiration(&remaining)?;
        if furthest.is_truthy() {
            self.write_references(&key, &remaining, furthest, now).await
        } else {
            self.secondary()?.clone().invoke_delete_native(key)?.await
        }
    }

    async fn cached_user_session_snapshots(
        &self,
        user_id: &FieldValue,
    ) -> AuthResult<Vec<(SessionView, Option<SessionView>)>> {
        let mut seen: Vec<FieldValue> = Vec::new();
        let mut sessions = Vec::new();
        let raw = self
            .secondary()?
            .clone()
            .invoke_get_native(active_sessions_key(user_id)?)?
            .await?;
        if !raw.as_ref().is_some_and(FieldValue::is_truthy) {
            return Ok(sessions);
        }
        let references = cache::decode(raw)?.unwrap_or_else(references::empty);
        let now = self.now().timestamp_millis() as f64;
        for reference in references::iter(&references)? {
            let reference = reference?;
            let token = reference.model_property("token")?;
            let expires_at = reference.model_property("expiresAt")?;
            if crate::query::field_number(&expires_at)? <= now
                || seen.iter().any(|seen| seen.same_value_zero(&token))
            {
                continue;
            }
            seen.push(token.clone());
            let raw = self.secondary()?.clone().invoke_get_native(token)?.await?;
            let Ok(Some(cached)) = cache::parse(raw) else {
                continue;
            };
            // Upstream listSessions skips malformed cache records; single-session reads expose malformed records.
            let session = (|| {
                if !cached.model_property("session")?.is_truthy() {
                    return Ok(None);
                }
                let mut session = cache::session(cache::dated_fields(
                    || cached.model_property("session"),
                    &["expiresAt"],
                )?)?;
                session.filter_returned_fields(&self.config.session)?;
                Ok::<_, AuthError>(Some(session))
            })();
            if let Ok(Some(session)) = session {
                let view = session.clone();
                sessions.push((session, Some(view)));
            }
        }
        Ok(sessions)
    }

    fn cached_session_snapshot(
        &self,
        cached: &FieldValue,
    ) -> AuthResult<crate::session::SessionData<UserView>> {
        let mut session = cache::session(cache::dated_fields(
            || cached.model_property("session"),
            &["expiresAt", "createdAt", "updatedAt"],
        )?)?;
        session.filter_returned_fields(&self.config.session)?;
        let mut user = cache::user(cached)?;
        user.filter_cached_fields(&self.config.user)?;
        Ok(crate::session::SessionData { session, user })
    }
}

#[async_trait]
impl<S: AuthSchema> SessionStore<S> for SecondaryStore<S> {
    async fn update_session_with_writer(
        &self,
        token: &str,
        update: SessionUpdate,
        secondary: Option<SessionUpdateWriter>,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        self.inner
            .update_session_with_writer(token, update, secondary)
            .await
    }

    async fn update_session_with_writer_by_token_value(
        &self,
        token: &FieldValue,
        update: SessionUpdate,
        secondary: Option<SessionUpdateWriter>,
    ) -> AuthResult<Option<SessionView>> {
        self.inner
            .update_session_with_writer_by_token_value(token, update, secondary)
            .await
    }

    async fn update_session_fields_by_token_value(
        &self,
        token: &FieldValue,
        fields: FieldMap,
    ) -> AuthResult<Option<SessionView>> {
        if self.storage.is_none() {
            return self
                .inner
                .update_session_fields_by_token_value(token, fields)
                .await;
        }
        self.update_runtime_session_by_token_value(
            token,
            SessionUpdate {
                additional_fields: fields,
                ..Default::default()
            },
        )
        .await
    }

    async fn get_session_by_token_value(
        &self,
        token: &FieldValue,
    ) -> AuthResult<Option<SessionView>> {
        if self.storage.is_none() {
            return self.inner.get_session_by_token_value(token).await;
        }
        let raw = self
            .secondary()?
            .clone()
            .invoke_get_native(token.clone())?
            .await?;
        if raw.as_ref().is_some_and(FieldValue::is_truthy) {
            let Some(cached) = cache::decode(raw)? else {
                return Ok(None);
            };
            return Ok(Some(self.cached_session_snapshot(&cached)?.session));
        }
        if !self.database_sessions() || self.config.session.preserve_session_in_database() {
            return Ok(None);
        }
        self.inner.get_session_by_token_value(token).await
    }

    async fn delete_user_sessions_optional(
        &self,
        user_id: &str,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        self.delete_user_sessions_optional_value(&user_id.into(), preserve)
            .await
    }

    async fn delete_user_sessions_optional_value(
        &self,
        user_id: &FieldValue,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        self.inner
            .delete_user_sessions_optional_value(user_id, preserve)
            .await
    }

    async fn create_session(&self, input: CreateSession) -> AuthResult<crate::wire::SessionView> {
        self.create_session_optional(input)
            .await?
            .ok_or_else(|| AuthError::forbidden("session creation returned no record"))
    }
    async fn create_session_optional(
        &self,
        input: CreateSession,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        let writer = self.session_create_writer(input.user_id.clone(), false, None);
        self.inner.create_session_with_writer(input, writer).await
    }

    async fn create_session_with_writer(
        &self,
        input: CreateSession,
        writer: Option<crate::store::SessionCreateWriter>,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        self.inner.create_session_with_writer(input, writer).await
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<crate::wire::SessionView>> {
        Ok(self
            .get_session_snapshot(token)
            .await?
            .map(|(session, _)| session))
    }

    async fn get_session_snapshot(
        &self,
        token: &str,
    ) -> AuthResult<
        Option<(
            crate::wire::SessionView,
            Option<crate::session::SessionData<crate::store::JoinValue<UserView>>>,
        )>,
    > {
        self.get_session_snapshot_value(&token.into()).await
    }

    async fn get_session_snapshot_value(
        &self,
        token: &FieldValue,
    ) -> AuthResult<
        Option<(
            crate::wire::SessionView,
            Option<crate::session::SessionData<crate::store::JoinValue<UserView>>>,
        )>,
    > {
        if self.storage.is_none() {
            return self.inner.get_session_snapshot_value(token).await;
        }
        let raw = self
            .secondary()?
            .clone()
            .invoke_get_native(token.clone())?
            .await?;
        if raw.as_ref().is_some_and(FieldValue::is_truthy) {
            let Some(cached) = cache::decode(raw)? else {
                return Ok(None);
            };
            let snapshot = self.cached_session_snapshot(&cached)?;
            return Ok(Some((snapshot.session.clone(), Some(snapshot.into()))));
        }
        if !self.database_sessions() || self.config.session.preserve_session_in_database() {
            return Ok(None);
        }
        self.inner.get_session_snapshot_value(token).await
    }

    async fn get_session_snapshots(
        &self,
        tokens: &[String],
        only_active: bool,
    ) -> AuthResult<
        Vec<(
            SessionView,
            Option<crate::session::SessionData<crate::store::JoinValue<UserView>>>,
        )>,
    > {
        if self.storage.is_none() {
            return self.inner.get_session_snapshots(tokens, only_active).await;
        }
        let mut sessions = Vec::new();
        for token in tokens {
            let raw = self
                .secondary()?
                .clone()
                .invoke_get_native(token.as_str().into())?
                .await?;
            let Ok(Some(cached)) = cache::parse(raw) else {
                continue;
            };
            // Upstream batch reads skip malformed cache entries and never fall back to the database.
            let data = (|| {
                let expires_at = crate::query::field_date(
                    &cached
                        .model_property("session")?
                        .model_property("expiresAt")?,
                )?;
                if only_active && expires_at.milliseconds() <= self.now().timestamp_millis() as f64
                {
                    return Ok(None);
                }
                let session = cache::session(cache::dated_fields(
                    || cached.model_property("session"),
                    &["expiresAt"],
                )?)?;
                let user = cache::user(&cached)?;
                Ok::<_, AuthError>(Some(crate::session::SessionData { session, user }))
            })();
            let Ok(Some(data)) = data else {
                continue;
            };
            sessions.push((data.session.clone(), Some(data.into())));
        }
        Ok(sessions)
    }

    async fn update_session_fields(
        &self,
        token: &str,
        fields: FieldMap,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        if self.storage.is_none() {
            return self.inner.update_session_fields(token, fields).await;
        }
        self.update_runtime_session(
            token,
            SessionUpdate {
                additional_fields: fields,
                ..Default::default()
            },
        )
        .await
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<crate::wire::SessionView>> {
        self.get_user_sessions_value(&user_id.into()).await
    }

    async fn get_user_sessions_value(&self, user_id: &FieldValue) -> AuthResult<Vec<SessionView>> {
        if self.storage.is_none() {
            return self.inner.get_user_sessions_value(user_id).await;
        }
        Ok(self
            .cached_user_session_snapshots(user_id)
            .await?
            .into_iter()
            .map(|(session, _)| session)
            .collect())
    }

    async fn get_user_session_snapshots(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<(crate::wire::SessionView, Option<SessionView>)>> {
        self.get_user_session_snapshots_value(&user_id.into(), false)
            .await
    }

    async fn get_user_session_snapshots_value(
        &self,
        user_id: &FieldValue,
        only_active: bool,
    ) -> AuthResult<Vec<(SessionView, Option<SessionView>)>> {
        if self.storage.is_none() {
            return self
                .inner
                .get_user_session_snapshots_value(user_id, only_active)
                .await;
        }
        self.cached_user_session_snapshots(user_id).await
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<crate::wire::SessionView> {
        if self.storage.is_none() {
            return self.inner.update_session_expiry(token, expires_at).await;
        }
        self.update_runtime_session(
            token,
            SessionUpdate {
                expires_at: Some(expires_at.into()),
                updated_at: Some(self.now().into()),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        self.delete_session_by_token_value(&token.into()).await
    }

    async fn delete_session_by_token_value(&self, token: &FieldValue) -> AuthResult<()> {
        self.delete_runtime_session(token).await
    }

    async fn end_session_by_token_value(&self, token: &FieldValue) -> AuthResult<()> {
        self.inner.end_session_by_token_value(token).await
    }

    async fn delete_sessions(&self, tokens: &[String]) -> AuthResult<()> {
        let Some(storage) = self.storage.clone() else {
            return self.inner.delete_sessions(tokens).await;
        };
        super::session_tokens::delete_cached_tokens(storage, tokens.to_vec()).await?;
        if !self.database_sessions() {
            return Ok(());
        }
        if self.config.session.preserve_session_in_database() {
            self.inner.end_sessions(tokens).await
        } else {
            self.inner.delete_sessions(tokens).await
        }
    }

    async fn end_sessions(&self, tokens: &[String]) -> AuthResult<()> {
        self.inner.end_sessions(tokens).await
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        self.delete_user_sessions_by_user_value(&user_id.into())
            .await
    }

    async fn delete_user_sessions_by_user_value(&self, user_id: &FieldValue) -> AuthResult<()> {
        if self.storage.is_none() {
            return self.inner.delete_user_sessions_by_user_value(user_id).await;
        }
        let references = self.references_value(user_id).await?;
        if self.database_sessions()
            && self
                .inner
                .delete_user_sessions_optional_value(
                    user_id,
                    self.config.session.preserve_session_in_database(),
                )
                .await?
                .is_none()
        {
            return Ok(());
        }
        self.queue_cached_user_session_deletion_value(user_id.clone(), references, None)
            .await
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        if self.database_sessions() && !self.config.session.preserve_session_in_database() {
            self.inner.delete_expired_sessions().await
        } else {
            Ok(0)
        }
    }

    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<crate::wire::SessionView> {
        if self.storage.is_none() {
            return self.inner.update_session_active_team(token, team_id).await;
        }
        self.update_runtime_session(
            token,
            SessionUpdate {
                active_team_id: Some(team_id.map(str::to_owned)),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<crate::wire::SessionView> {
        if self.storage.is_none() {
            return self
                .inner
                .update_session_active_organization(token, organization_id)
                .await;
        }
        self.update_runtime_session(
            token,
            SessionUpdate {
                active_organization_id: Some(organization_id.map(str::to_owned)),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }

    async fn accept_invitation_with_teams(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: Option<&str>,
        teams_enabled: bool,
        maximum: TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Invitation, Option<crate::wire::SessionView>)> {
        let token = session_token.map(FieldValue::from);
        self.accept_invitation_with_teams_by_token_value(
            invitation_id,
            user_id,
            token.as_ref(),
            teams_enabled,
            maximum,
        )
        .await
    }

    async fn accept_invitation_with_teams_by_token_value(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: Option<&FieldValue>,
        teams_enabled: bool,
        maximum: TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Invitation, Option<SessionView>)> {
        self.accept_invitation_with_teams_values(
            &invitation_id.into(),
            &user_id.into(),
            session_token,
            teams_enabled,
            maximum,
        )
        .await
    }

    async fn accept_invitation_with_teams_values(
        &self,
        invitation_id: &crate::FieldValue,
        user_id: &crate::FieldValue,
        session_token: Option<&FieldValue>,
        teams_enabled: bool,
        maximum: TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Invitation, Option<SessionView>)> {
        self.accept_invitation_with_session_effects_values(
            invitation_id,
            user_id,
            session_token,
            teams_enabled,
            maximum,
            Default::default(),
        )
        .await
    }

    async fn accept_invitation_with_session_effects_values(
        &self,
        invitation_id: &FieldValue,
        user_id: &FieldValue,
        session_token: Option<&FieldValue>,
        teams_enabled: bool,
        maximum: TeamMemberLimits<'_>,
        mut effects: SessionWriteEffects<S>,
    ) -> AuthResult<(Member, Invitation, Option<SessionView>)> {
        effects.secondary = effects
            .secondary
            .or_else(|| self.session_update_writer_factory());
        if let Some(effect) = effects.after_output.take() {
            let runtime = self.clone();
            effects.after_output = Some(Box::new(move |session, transaction| {
                effect(session, runtime.wrap_transaction(transaction))
            }));
        }
        self.inner
            .accept_invitation_with_session_effects_values(
                invitation_id,
                user_id,
                session_token,
                teams_enabled,
                maximum,
                effects,
            )
            .await
    }
}
