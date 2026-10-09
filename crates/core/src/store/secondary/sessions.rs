use super::{SecondaryStore, cache};
use crate::entity::AuthSession;
use crate::store::database_hooks::SessionUpdate;
use crate::store::{SessionStore, SessionUpdateWriter, TeamMemberLimits};
use crate::types::{CreateSession, Invitation, Member};
use crate::wire::{SessionView, UserView};
use crate::{AuthError, AuthResult, AuthSchema, FieldMap, FieldValue};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

mod deletion;

#[derive(Clone)]
pub(super) struct SessionReference {
    pub token: crate::SchemaValue<String>,
    pub expires_at: crate::SchemaValue<f64>,
}

impl SessionReference {
    fn fields(&self) -> FieldValue {
        FieldMap::from([
            ("token".into(), self.token.field_value()),
            ("expiresAt".into(), self.expires_at.field_value()),
        ])
        .into()
    }
}

fn encode_references(references: &[SessionReference]) -> AuthResult<String> {
    cache::stringify(
        &references
            .iter()
            .map(SessionReference::fields)
            .collect::<Vec<_>>()
            .into(),
    )
}

impl<S: AuthSchema> SecondaryStore<S> {
    pub(super) async fn session_fields(
        &self,
        session: &crate::wire::SessionView,
    ) -> AuthResult<FieldMap> {
        let mut config = self.config.session.clone();
        for field in config.fields_mut().values_mut() {
            field.returned = Some(true);
            if !self.database_sessions() {
                field.transform.get_or_insert_default().output = None;
            }
        }
        let mut view = SessionView::with_fields_for_adapter(
            session,
            &config,
            !self.database_sessions() || self.inner.supports_native_json(),
        )
        .await?;
        view.visible_fields = Some(
            SessionView::active_plugin_fields(&self.metadata)
                .filter(|field| {
                    session
                        .field_presence()
                        .is_none_or(|fields| fields.contains(*field))
                })
                .map(str::to_owned)
                .collect(),
        );
        let mut fields: FieldMap = view.into();
        if !self.database_sessions() {
            for name in self
                .config
                .session
                .fields()
                .keys()
                .map(String::as_str)
                .chain(["impersonatedBy", "activeOrganizationId", "activeTeamId"])
            {
                let has_default = self.config.session.fields().get(name).is_some_and(|field| {
                    field.default_value.is_some() || field.default_value_fn.is_some()
                });
                if !has_default && fields.get(name).is_some_and(FieldValue::is_null) {
                    let _ = fields.remove(name);
                }
            }
        }
        Ok(fields)
    }

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
                            crate::observability::logger::current().error(
                                "Failed to mirror committed session to secondary storage",
                                &[crate::observability::LogArgument::Error(&error)],
                            );
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
        let user_id = owner.display_string()?;
        let token = original.get("token").cloned().unwrap_or_default();
        let mut references = self.references(&user_id).await?;
        let now = self.now();
        retain_references(&mut references, |reference| {
            Ok(
                crate::query::field_number(&reference.expires_at.field_value())?
                    > now.timestamp_millis() as f64
                    && !reference.token.field_value().strict_equals(&token),
            )
        })?;
        let expiry = crate::SchemaValue::<crate::FieldDate>::from_field(
            original.get("expiresAt").cloned().unwrap_or_default(),
        );
        let expires_at = expiry.date_milliseconds()?;
        references.push(SessionReference {
            token: crate::SchemaValue::from_field(token.clone()),
            expires_at: expires_at.into(),
        });
        sort_references(&mut references)?;
        let furthest = match references.last() {
            Some(reference)
                if !reference.expires_at.field_value().is_null()
                    && !reference.expires_at.is_undefined() =>
            {
                crate::query::field_number(&reference.expires_at.field_value())?
            }
            _ => expires_at,
        };
        let seconds =
            crate::SchemaValue::<crate::FieldDate>::from_field(furthest.into()).cache_ttl(now)?;
        if seconds > 0.0 {
            self.secondary()?
                .set_native(
                    &format!("active-sessions-{user_id}").into(),
                    &encode_references(&references)?,
                    Some(seconds),
                )
                .await?;
        }
        let user = match transaction {
            Some(transaction) => transaction.get_user_by_id_field(owner).await?,
            None => self.inner.get_user_by_id_field(owner).await?,
        };
        let user = match user {
            Some(user) => Some(
                UserView::with_internal_fields_for_adapter(
                    &user,
                    &self.config.user,
                    &self.metadata,
                    self.inner.supports_native_json(),
                )
                .await?,
            ),
            None => None,
        };
        let seconds = expiry.cache_ttl(now)?;
        if seconds > 0.0 {
            let value = cache::session_envelope(session.clone(), user);
            self.secondary()?
                .set_native(&token, &cache::stringify(&value)?, Some(seconds))
                .await?;
        }
        Ok(())
    }

    pub(super) async fn references(&self, user_id: &str) -> AuthResult<Vec<SessionReference>> {
        Ok(cache::decode(
            self.secondary()?
                .get_native(&format!("active-sessions-{user_id}").into())
                .await?,
        )
        .and_then(|value| {
            value
                .as_array()?
                .iter()
                .map(|value| {
                    let fields = value.as_object()?;
                    Some(SessionReference {
                        token: crate::SchemaValue::from_field(
                            fields.get("token").cloned().unwrap_or_default(),
                        ),
                        expires_at: crate::SchemaValue::from_field(
                            fields.get("expiresAt").cloned().unwrap_or_default(),
                        ),
                    })
                })
                .collect::<Option<Vec<_>>>()
        })
        .unwrap_or_default())
    }

    async fn write_references(
        &self,
        user_id: &str,
        mut references: Vec<SessionReference>,
    ) -> AuthResult<()> {
        sort_references(&mut references)?;
        let key = format!("active-sessions-{user_id}");
        if let Some(last) = references.last() {
            let seconds =
                crate::SchemaValue::<crate::FieldDate>::from_field(last.expires_at.field_value())
                    .cache_ttl(self.now())?;
            self.secondary()?
                .set_native(&key.into(), &encode_references(&references)?, Some(seconds))
                .await
        } else {
            self.secondary()?.delete(&key).await
        }
    }

    async fn add_reference(&self, session: &crate::wire::SessionView) -> AuthResult<()> {
        let now = self.now().timestamp_millis() as f64;
        let mut references = self.references(&session.user_id.display_string()?).await?;
        retain_references(&mut references, |reference| {
            Ok(
                crate::query::field_number(&reference.expires_at.field_value())? > now
                    && !reference
                        .token
                        .field_value()
                        .strict_equals(&session.token.field_value()),
            )
        })?;
        references.push(SessionReference {
            token: session.token.clone(),
            expires_at: session.expires_at().date_milliseconds()?.into(),
        });
        self.write_references(&session.user_id.display_string()?, references)
            .await
    }

    pub(super) async fn mirror_session(
        &self,
        session: &crate::wire::SessionView,
    ) -> AuthResult<()> {
        self.mirror_session_in_transaction(session, None).await
    }

    pub(super) async fn mirror_session_in_transaction(
        &self,
        session: &crate::wire::SessionView,
        transaction: Option<&dyn crate::store::AuthTransaction<S>>,
    ) -> AuthResult<()> {
        if self.storage.is_none() {
            return Ok(());
        }
        let seconds = session.expires_at().cache_ttl(self.now())?;
        if seconds <= 0.0 {
            return Ok(());
        }
        self.add_reference(session).await?;
        let user = match transaction {
            Some(transaction) => transaction.get_user_by_id_field(&session.user_id).await?,
            None => self.inner.get_user_by_id_field(&session.user_id).await?,
        };
        let user = match user {
            Some(user) => Some(
                UserView::with_internal_fields_for_adapter(
                    &user,
                    &self.config.user,
                    &self.metadata,
                    self.inner.supports_native_json(),
                )
                .await?,
            ),
            None => None,
        };
        let value = cache::session_envelope(self.session_fields(session).await?, user);
        self.secondary()?
            .set_native(
                &session.token().field_value(),
                &cache::stringify(&value)?,
                Some(seconds),
            )
            .await
    }

    async fn update_cached_session(
        &self,
        token: &FieldValue,
        update: SessionUpdate,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        let Some(mut cached) = cache::decode(self.secondary()?.get_native(token).await?)
            .and_then(|value| value.as_object().cloned())
        else {
            return Ok(None);
        };
        let Some(session) = cached.get("session").and_then(FieldValue::as_object) else {
            return Ok(None);
        };
        let original = cache::session(session.clone(), &[])?;
        let created_at = original.created_at.clone();
        let mut fields = FieldMap::from(original);
        let mut patch = update.into_public_fields()?;
        // Upstream uses nullish date defaults before parsing the cached session.
        for name in ["expiresAt", "updatedAt"] {
            if patch
                .get(name)
                .is_some_and(|value| value.is_null() || value.is_undefined())
            {
                let _ = patch.remove(name);
            }
        }
        fields.extend(patch);
        // Upstream retains the cached creation date, even when a before hook patches it.
        let _ = fields.insert("createdAt".into(), created_at.into_field_value());
        let mut updated = cache::session(fields, &["expiresAt", "createdAt", "updatedAt"])?;
        updated.filter_returned_fields(&self.config.session)?;
        let _ = cached.insert("session".into(), FieldMap::from(updated.clone()).into());
        let seconds = updated.expires_at().converted_cache_ttl(self.now())?;
        if seconds > 0.0 {
            self.secondary()?
                .set_native(token, &cache::stringify(&cached.into())?, Some(seconds))
                .await?;
            let now = self.now().timestamp_millis();
            let mut references = self.references(&updated.user_id.display_string()?).await?;
            retain_references(&mut references, |reference| {
                Ok(
                    crate::query::field_number(&reference.expires_at.field_value())? > now as f64
                        && !reference.token.field_value().strict_equals(token),
                )
            })?;
            references.push(super::sessions::SessionReference {
                token: crate::SchemaValue::from_field(token.clone()),
                expires_at: updated
                    .expires_at()
                    .converted_date()?
                    .date_milliseconds()?
                    .into(),
            });
            self.write_references(&updated.user_id.display_string()?, references)
                .await?;
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
        let runtime = self.clone();
        let lookup = token.clone();
        self.inner
            .update_session_with_writer_by_token_value(
                token,
                update,
                Some(SessionUpdateWriter {
                    write_database: self.database_sessions(),
                    write: Box::new(move |update| {
                        Box::pin(
                            async move { runtime.update_cached_session(&lookup, update).await },
                        )
                    }),
                }),
            )
            .await
    }

    pub(super) async fn queue_cached_user_session_deletion(
        &self,
        user_id: String,
        references: Vec<SessionReference>,
        transaction: Option<&dyn crate::store::AuthTransaction<S>>,
    ) -> AuthResult<()> {
        let runtime = self.clone();
        let effect = Box::pin(async move {
            // Upstream applies this onError policy both after commit and without a transaction.
            if let Err(error) = runtime.delete_cached_sessions(&user_id, &references).await {
                crate::observability::logger::current().error(
                    "Failed to delete committed user sessions from secondary storage",
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

    pub(super) async fn delete_cached_sessions(
        &self,
        user_id: &str,
        references: &[SessionReference],
    ) -> AuthResult<()> {
        for reference in references {
            self.secondary()?
                .delete_native(&reference.token.field_value())
                .await?;
        }
        let now = self.now().timestamp_millis() as f64;
        let mut remaining = self.references(user_id).await?;
        retain_references(&mut remaining, |reference| {
            Ok(
                crate::query::field_number(&reference.expires_at.field_value())? > now
                    && !references.iter().any(|deleted| {
                        deleted
                            .token
                            .field_value()
                            .strict_equals(&reference.token.field_value())
                    }),
            )
        })?;
        self.write_references(user_id, remaining).await
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
        let raw = self.secondary()?.get_native(token).await?;
        if raw.is_some() {
            let Some(mut cached) = cache::decode(raw).and_then(|value| value.as_object().cloned())
            else {
                return Ok(None);
            };
            let fields = cache::object(&cached.remove("session").unwrap_or(FieldValue::Null))?;
            let session = cache::session(fields, &["expiresAt", "createdAt", "updatedAt"])?;
            let _ = cache::user(&cached.remove("user").unwrap_or(FieldValue::Null))?;
            return Ok(Some(session));
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
        self.inner
            .delete_user_sessions_optional(user_id, preserve)
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
        if self.storage.is_none() {
            return self.inner.get_session_snapshot(token).await;
        }
        let raw = self.secondary()?.get_native(&token.into()).await?;
        if raw.is_some() {
            let Some(mut cached) = cache::decode(raw).and_then(|value| value.as_object().cloned())
            else {
                return Ok(None);
            };
            let fields = cache::object(&cached.remove("session").unwrap_or(FieldValue::Null))?;
            let session = cache::session(fields, &["expiresAt", "createdAt", "updatedAt"])?;
            let mut view = session.clone();
            view.active = true;
            let user = cache::user(&cached.remove("user").unwrap_or(FieldValue::Null))?;
            return Ok(Some((
                session,
                Some(crate::session::SessionData {
                    session: view,
                    user: crate::store::JoinValue::One(Some(user)),
                }),
            )));
        }
        if !self.database_sessions() || self.config.session.preserve_session_in_database() {
            return Ok(None);
        }
        self.inner.get_session_snapshot(token).await
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
            let raw = self.secondary()?.get_native(&token.as_str().into()).await?;
            let Ok(Some(cached)) = cache::parse(raw) else {
                continue;
            };
            // Upstream batch reads skip malformed cache entries and never fall back to the database.
            let data = (|| {
                let mut fields = cache::object(&cached)?;
                let session = cache::session(
                    cache::object(&fields.remove("session").unwrap_or_default())?,
                    &["expiresAt"],
                )?;
                let user = cache::user(&fields.remove("user").unwrap_or_default())?;
                Ok::<_, AuthError>(crate::session::SessionData { session, user })
            })();
            let Ok(mut data) = data else {
                continue;
            };
            if only_active
                && data
                    .session
                    .expires_at
                    .clone()
                    .converted_date()?
                    .is_before_or_equal(self.now())?
            {
                continue;
            }
            data.session.active = true;
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
        Ok(self
            .get_user_session_snapshots(user_id)
            .await?
            .into_iter()
            .map(|(session, _)| session)
            .collect())
    }

    async fn get_user_session_snapshots(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<(crate::wire::SessionView, Option<SessionView>)>> {
        if self.storage.is_none() {
            return self.inner.get_user_session_snapshots(user_id).await;
        }
        let mut seen: Vec<FieldValue> = Vec::new();
        let mut sessions = Vec::new();
        for reference in self.references(user_id).await? {
            if crate::query::field_number(&reference.expires_at.field_value())?
                <= self.now().timestamp_millis() as f64
                || seen
                    .iter()
                    .any(|token| token.same_value_zero(&reference.token.field_value()))
            {
                continue;
            }
            seen.push(reference.token.field_value());
            let raw = self
                .secondary()?
                .get_native(&reference.token.field_value())
                .await?;
            let Ok(Some(cached)) = cache::parse(raw) else {
                continue;
            };
            let Some(fields) = cached
                .as_object()
                .and_then(|cached| cached.get("session"))
                .and_then(FieldValue::as_object)
            else {
                continue;
            };
            // Upstream listSessions skips malformed cache records; single-session reads expose malformed records.
            if let Ok(session) = cache::session(fields.clone(), &["expiresAt"]) {
                let view = session.clone();
                sessions.push((session, Some(view)));
            }
        }
        Ok(sessions)
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
        if self.storage.is_none() {
            return self.inner.delete_user_sessions(user_id).await;
        }
        let references = self.references(user_id).await?;
        if self.database_sessions()
            && self
                .inner
                .delete_user_sessions_optional(
                    user_id,
                    self.config.session.preserve_session_in_database(),
                )
                .await?
                .is_none()
        {
            return Ok(());
        }
        self.queue_cached_user_session_deletion(user_id.to_owned(), references, None)
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
        let database_token = session_token.filter(|_| self.database_sessions());
        let (member, invitation, snapshot) = self
            .inner
            .accept_invitation_with_teams_by_token_value(
                invitation_id,
                user_id,
                database_token,
                teams_enabled,
                maximum,
            )
            .await?;
        let Some(token) = session_token else {
            return Ok((member, invitation, snapshot));
        };
        if self.database_sessions() {
            if let Some(session) = self.inner.get_session_by_token_value(token).await? {
                self.mirror_session(&session).await?;
            }
            return Ok((member, invitation, snapshot));
        }
        let team_ids: Vec<_> = invitation
            .team_id
            .typed()?
            .as_deref()
            .filter(|_| teams_enabled)
            .unwrap_or("")
            .split(',')
            .filter(|id| !id.is_empty())
            .collect();
        let snapshot = if let [team] = team_ids.as_slice() {
            Some(
                self.update_session_active_team_by_token_value(token, Some(&(*team).into()))
                    .await?,
            )
        } else {
            None
        };
        let _ = self
            .update_session_active_organization_by_token_value(
                token,
                Some(&invitation.organization_id.field_value()),
            )
            .await?;
        Ok((member, invitation, snapshot))
    }
}

fn retain_references(
    references: &mut Vec<SessionReference>,
    keep: impl Fn(&SessionReference) -> AuthResult<bool>,
) -> AuthResult<()> {
    let selected = references
        .iter()
        .map(keep)
        .collect::<AuthResult<Vec<_>>>()?;
    *references = std::mem::take(references)
        .into_iter()
        .zip(selected)
        .filter_map(|(reference, keep)| keep.then_some(reference))
        .collect();
    Ok(())
}

fn sort_references(references: &mut Vec<SessionReference>) -> AuthResult<()> {
    let mut sorted = std::mem::take(references)
        .into_iter()
        .map(|reference| {
            Ok((
                crate::query::field_number(&reference.expires_at.field_value())?,
                reference,
            ))
        })
        .collect::<AuthResult<Vec<_>>>()?;
    sorted.sort_by(|(left, _), (right, _)| {
        left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal)
    });
    *references = sorted.into_iter().map(|(_, reference)| reference).collect();
    Ok(())
}
