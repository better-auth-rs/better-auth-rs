use super::{SecondaryStore, decode, object, ttl};
use crate::entity::AuthSession;
use crate::store::database_hooks::SessionUpdate;
use crate::store::{SessionStore, SessionUpdateWriter, TeamMemberLimits};
use crate::types::{CreateSession, Invitation, Member};
use crate::wire::{SessionView, UserView};
use crate::{AuthError, AuthResult, AuthSchema, FieldMap, FieldValue, FromFieldMap, SchemaField};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashSet;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SessionReference {
    pub token: String,
    pub expires_at: i64,
}

impl<S: AuthSchema> SecondaryStore<S> {
    pub(super) fn hydrate_session(&self, fields: FieldMap) -> AuthResult<SessionView> {
        let mut session = SessionView::from_field_values(fields)?;
        session.active = true;
        Ok(session)
    }

    fn read_cached_session(&self, fields: Map<String, Value>) -> AuthResult<SessionView> {
        let mut session: SessionView = serde_json::from_value(Value::Object(fields))?;
        session.active = true;
        Ok(session)
    }

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
            [
                ("admin.enabled", "impersonatedBy"),
                ("organization.enabled", "activeOrganizationId"),
                ("organization.teams_enabled", "activeTeamId"),
            ]
            .into_iter()
            .filter(|(plugin, _)| self.metadata.get(*plugin).and_then(Value::as_bool) == Some(true))
            .filter(|(_, field)| {
                session
                    .field_presence()
                    .is_none_or(|fields| fields.contains(*field))
            })
            .map(|(_, field)| field.to_owned())
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

    pub(super) fn prepare_session(&self, input: &mut CreateSession) -> AuthResult<()> {
        let _ = input.additional_fields.remove("id");
        let id = self
            .config
            .advanced
            .generate_id("session", None)?
            .unwrap_or_else(|| crate::id::random_id(None));
        let mut fields = FieldMap::new();
        if !id.is_empty() {
            let _ = fields.insert("id".into(), id.into());
        }
        fields.extend(self.config.session.default_fields());
        fields.extend(std::mem::take(&mut input.additional_fields));
        input.additional_fields = fields;
        Ok(())
    }

    pub(super) fn new_session(&self, input: CreateSession) -> AuthResult<crate::wire::SessionView> {
        let now = Utc::now();
        let user_id_missing = input.user_id.is_undefined();
        let mut fields = FieldMap::from_iter([
            ("token".into(), crate::id::random_id(None).into()),
            ("userId".into(), input.user_id.into_field_value()),
            ("expiresAt".into(), input.expires_at.into()),
            ("createdAt".into(), now.into()),
            ("updatedAt".into(), now.into()),
            (
                "ipAddress".into(),
                input.ip_address.unwrap_or_default().into(),
            ),
            (
                "userAgent".into(),
                input.user_agent.unwrap_or_default().into(),
            ),
            ("impersonatedBy".into(), input.impersonated_by.into_field()),
            (
                "activeOrganizationId".into(),
                input.active_organization_id.into_field(),
            ),
            ("activeTeamId".into(), FieldValue::Null),
        ]);
        if user_id_missing {
            let _ = fields.remove("userId");
        }
        fields.extend(input.additional_fields);
        self.hydrate_session(fields)
    }

    pub(super) async fn references(&self, user_id: &str) -> AuthResult<Vec<SessionReference>> {
        Ok(decode(
            self.secondary()?
                .get(&format!("active-sessions-{user_id}"))
                .await?,
        )
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default())
    }

    async fn write_references(
        &self,
        user_id: &str,
        mut references: Vec<SessionReference>,
    ) -> AuthResult<()> {
        references.sort_by_key(|reference| reference.expires_at);
        let key = format!("active-sessions-{user_id}");
        if let Some(last) = references.last() {
            let seconds =
                u64::try_from((last.expires_at - Utc::now().timestamp_millis()).div_euclid(1000))
                    .unwrap_or(0);
            self.secondary()?
                .set(&key, &serde_json::to_string(&references)?, Some(seconds))
                .await
        } else {
            self.secondary()?.delete(&key).await
        }
    }

    async fn add_reference(&self, session: &crate::wire::SessionView) -> AuthResult<()> {
        let now = Utc::now().timestamp_millis();
        let mut references = self.references(&session.user_id.display_string()?).await?;
        references
            .retain(|reference| reference.expires_at > now && reference.token != session.token());
        references.push(SessionReference {
            token: session.token().to_owned(),
            expires_at: session.expires_at().milliseconds() as i64,
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
        if self.storage.is_none() || ttl(session.expires_at()) == 0 {
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
        let value = json!({ "session": self.session_fields(session).await?.json()?, "user": user });
        self.secondary()?
            .set(
                session.token(),
                &serde_json::to_string(&value)?,
                Some(ttl(session.expires_at())),
            )
            .await
    }

    async fn update_cached_session(
        &self,
        token: &str,
        update: SessionUpdate,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        let Some(mut cached) = decode(self.secondary()?.get(token).await?) else {
            return Ok(None);
        };
        let Some(session) = cached.get_mut("session").and_then(Value::as_object_mut) else {
            return Ok(None);
        };
        let original = self.read_cached_session(session.clone())?;
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
        let _ = fields.insert("createdAt".into(), created_at.into());
        let mut updated = self.hydrate_session(fields)?;
        updated.filter_returned_fields(&self.config.session);
        *session = FieldMap::from(updated.clone()).json()?;
        let seconds = ttl(updated.expires_at());
        if seconds > 0 {
            self.secondary()?
                .set(token, &serde_json::to_string(&cached)?, Some(seconds))
                .await?;
            let now = Utc::now().timestamp_millis();
            let mut references = self.references(&updated.user_id.display_string()?).await?;
            references.retain(|reference| reference.expires_at > now && reference.token != token);
            references.push(super::sessions::SessionReference {
                token: token.to_owned(),
                expires_at: updated.expires_at().milliseconds() as i64,
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
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        let runtime = self.clone();
        let lookup = token.to_owned();
        self.inner
            .update_session_with_writer(
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
            self.secondary()?.delete(&reference.token).await?;
        }
        let tokens: HashSet<_> = references
            .iter()
            .map(|reference| reference.token.as_str())
            .collect();
        let now = Utc::now().timestamp_millis();
        let mut remaining = self.references(user_id).await?;
        remaining.retain(|reference| {
            reference.expires_at > now && !tokens.contains(reference.token.as_str())
        });
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
            .ok_or_else(|| AuthError::forbidden("session creation cancelled by database hook"))
    }
    async fn create_session_optional(
        &self,
        mut input: CreateSession,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        let request = crate::hooks::current_request_hook_context();
        let session = if self.database_sessions() {
            let Some(session) = self.inner.create_session_optional(input).await? else {
                return Ok(None);
            };
            session
        } else {
            self.prepare_session(&mut input)?;
            if !self
                .inner
                .before_create_runtime_session_optional(&mut input)
                .await?
            {
                return Ok(None);
            }
            self.new_session(input)?
        };
        self.mirror_session(&session).await?;
        if !self.database_sessions() {
            self.inner
                .after_create_runtime_session(&session, request)
                .await?;
        }
        Ok(Some(session))
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
            Option<crate::session::SessionData>,
        )>,
    > {
        if self.storage.is_none() {
            return self.inner.get_session_snapshot(token).await;
        }
        let raw = self.secondary()?.get(token).await?;
        if raw.is_some() {
            let Some(mut cached) = decode(raw).and_then(|value| value.as_object().cloned()) else {
                return Ok(None);
            };
            let fields = object(cached.remove("session").unwrap_or(Value::Null))?;
            let session = self.read_cached_session(fields)?;
            let mut view = session.clone();
            view.active = true;
            let user: UserView =
                serde_json::from_value(cached.remove("user").unwrap_or(Value::Null))?;
            return Ok(Some((
                session,
                Some(crate::session::SessionData {
                    session: view,
                    user,
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
    ) -> AuthResult<Vec<(SessionView, Option<crate::session::SessionData>)>> {
        if self.storage.is_none() {
            return self.inner.get_session_snapshots(tokens, only_active).await;
        }
        let mut sessions = Vec::new();
        for token in tokens {
            let Some(cached) = decode(self.secondary()?.get(token).await?) else {
                continue;
            };
            // Upstream batch reads skip malformed cache entries and never fall back to the database.
            let Ok(mut data) = serde_json::from_value::<crate::session::SessionData>(cached) else {
                continue;
            };
            if only_active
                && data.session.expires_at.milliseconds() <= Utc::now().timestamp_millis() as f64
            {
                continue;
            }
            data.session.active = true;
            sessions.push((data.session.clone(), Some(data)));
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
        let mut seen = HashSet::new();
        let mut sessions = Vec::new();
        for reference in self.references(user_id).await? {
            if reference.expires_at <= Utc::now().timestamp_millis()
                || !seen.insert(reference.token.clone())
            {
                continue;
            }
            let Some(cached) = decode(self.secondary()?.get(&reference.token).await?) else {
                continue;
            };
            let Some(fields) = cached.get("session").and_then(Value::as_object) else {
                continue;
            };
            // Upstream listSessions skips malformed cache records; single-session reads expose malformed records.
            if let Ok(session) = self.read_cached_session(fields.clone()) {
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
                updated_at: Some(Utc::now().into()),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        if self.storage.is_none() {
            return self.inner.delete_session(token).await;
        }
        let cached = self.secondary()?.get(token).await?;
        if cached
            .as_ref()
            .map(|value| FieldValue::from_json(value.clone()))
            .transpose()?
            .is_some_and(|value| value.is_truthy())
        {
            let cached = decode(cached);
            if let Some(user_id) = cached
                .as_ref()
                .and_then(|cached| cached.get("session"))
                .and_then(|session| session.get("userId"))
                .and_then(Value::as_str)
            {
                let references = self
                    .secondary()?
                    .get(&format!("active-sessions-{user_id}"))
                    .await?;
                if references
                    .as_ref()
                    .map(|value| FieldValue::from_json(value.clone()))
                    .transpose()?
                    .is_some_and(|value| value.is_truthy())
                {
                    let mut references: Vec<SessionReference> = decode(references)
                        .and_then(|value| serde_json::from_value(value).ok())
                        .unwrap_or_default();
                    references.retain(|reference| {
                        reference.token != token
                            && reference.expires_at > Utc::now().timestamp_millis()
                    });
                    self.write_references(user_id, references).await?;
                } else {
                    crate::observability::logger::current()
                        .error("Active sessions list not found in secondary storage", &[]);
                }
            } else {
                crate::observability::logger::current()
                    .error("Session not found in secondary storage", &[]);
                return Ok(());
            }
        }
        self.secondary()?.delete(token).await?;
        if !self.database_sessions() {
            return Ok(());
        }
        if self.config.session.preserve_session_in_database() {
            self.inner.end_session(token).await
        } else {
            self.inner.delete_session(token).await
        }
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
        let database_token = session_token.filter(|_| self.database_sessions());
        let (member, invitation, snapshot) = self
            .inner
            .accept_invitation_with_teams(
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
            if let Some(session) = self.inner.get_session(token).await? {
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
            Some(self.update_session_active_team(token, Some(team)).await?)
        } else {
            None
        };
        let _ = self
            .update_session_active_organization(token, Some(invitation.organization_id.typed()?))
            .await?;
        Ok((member, invitation, snapshot))
    }
}
