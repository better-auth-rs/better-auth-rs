use super::{SecondaryStore, decode, object, ttl};
use crate::entity::AuthSession;
use crate::store::{SessionStore, TeamMemberLimits};
use crate::types::{CreateSession, Invitation, Member};
use crate::wire::{SessionView, UserView};
use crate::{AuthError, AuthResult, AuthSchema};
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
    pub(super) fn hydrate_session(&self, mut fields: Map<String, Value>) -> AuthResult<S::Session> {
        for (name, field) in &self.config.session.additional_fields {
            if let Some(storage) = &field.field_name
                && storage != name
                && let Some(value) = fields.remove(name)
            {
                let _ = fields.insert(storage.clone(), value);
            }
        }
        S::Session::from_runtime_fields(fields)
    }

    pub(super) fn session_fields(&self, session: &S::Session) -> AuthResult<Map<String, Value>> {
        let mut config = self.config.session.clone();
        for field in config.additional_fields.values_mut() {
            field.returned = true;
            if !self.database_sessions() {
                field.output_transform = None;
            }
        }
        let mut view = SessionView::with_fields_for_adapter(
            session,
            &config,
            !self.database_sessions() || self.inner.supports_native_json(),
        )?;
        view.visible_fields = Some(
            [
                ("admin.enabled", "impersonatedBy"),
                ("organization.enabled", "activeOrganizationId"),
                ("organization.teams_enabled", "activeTeamId"),
            ]
            .into_iter()
            .filter(|(plugin, _)| self.metadata.get(*plugin).and_then(Value::as_bool) == Some(true))
            .map(|(_, field)| field.to_owned())
            .collect(),
        );
        let mut fields: Map<String, Value> = view.into();
        if !self.database_sessions() {
            for name in self
                .config
                .session
                .additional_fields
                .keys()
                .map(String::as_str)
                .chain(["impersonatedBy", "activeOrganizationId", "activeTeamId"])
            {
                let has_default =
                    self.config
                        .session
                        .additional_fields
                        .get(name)
                        .is_some_and(|field| {
                            field.default_value.is_some() || field.default_value_fn.is_some()
                        });
                if !has_default && fields.get(name).is_some_and(Value::is_null) {
                    let _ = fields.remove(name);
                }
            }
        }
        Ok(fields)
    }

    pub(super) fn new_session(&self, input: CreateSession) -> AuthResult<S::Session> {
        let now = Utc::now();
        let mut fields = object(json!({
            "id": uuid::Uuid::new_v4().to_string(), "token": format!("session_{}", uuid::Uuid::new_v4()),
            "userId": input.user_id, "expiresAt": input.expires_at, "createdAt": now, "updatedAt": now,
            "ipAddress": input.ip_address.unwrap_or_default(), "userAgent": input.user_agent.unwrap_or_default(),
            "impersonatedBy": input.impersonated_by, "activeOrganizationId": input.active_organization_id,
            "activeTeamId": null,
        }))?;
        fields.extend(self.config.session.default_fields());
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

    async fn add_reference(&self, session: &S::Session) -> AuthResult<()> {
        let now = Utc::now().timestamp_millis();
        let mut references = self.references(&session.user_id()).await?;
        references
            .retain(|reference| reference.expires_at > now && reference.token != session.token());
        references.push(SessionReference {
            token: session.token().to_owned(),
            expires_at: session.expires_at().timestamp_millis(),
        });
        self.write_references(&session.user_id(), references).await
    }

    pub(super) async fn mirror_session(&self, session: &S::Session) -> AuthResult<()> {
        self.mirror_session_in_transaction(session, None).await
    }

    pub(super) async fn mirror_session_in_transaction(
        &self,
        session: &S::Session,
        transaction: Option<&dyn crate::store::AuthTransaction<S>>,
    ) -> AuthResult<()> {
        if self.storage.is_none() || ttl(session.expires_at()) == 0 {
            return Ok(());
        }
        self.add_reference(session).await?;
        let user = match transaction {
            Some(transaction) => transaction.get_user_by_id(&session.user_id()).await?,
            None => self.inner.get_user_by_id(&session.user_id()).await?,
        }
        .map(|user| {
            UserView::with_internal_fields_for_adapter(
                &user,
                &self.config.user,
                &self.metadata,
                self.inner.supports_native_json(),
            )
        })
        .transpose()?;
        let value = json!({ "session": self.session_fields(session)?, "user": user });
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
        fields: Map<String, Value>,
    ) -> AuthResult<Option<S::Session>> {
        if self.storage.is_none() {
            return Ok(None);
        }
        let Some(mut cached) = decode(self.secondary()?.get(token).await?) else {
            return Ok(None);
        };
        let Some(session) = cached.get_mut("session").and_then(Value::as_object_mut) else {
            return Ok(None);
        };
        session.extend(fields);
        let mut view = SessionView::try_from(session.clone())?;
        view.filter_returned_fields(&self.config.session);
        *session = view.into();
        let updated = self.hydrate_session(session.clone())?;
        let seconds = ttl(updated.expires_at());
        if seconds > 0 {
            self.secondary()?
                .set(token, &serde_json::to_string(&cached)?, Some(seconds))
                .await?;
            self.add_reference(&updated).await?;
        }
        Ok(Some(updated))
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
    async fn create_session(&self, mut input: CreateSession) -> AuthResult<S::Session> {
        let session = if self.database_sessions() {
            self.inner.create_session(input).await?
        } else {
            self.inner.before_create_runtime_session(&mut input).await?;
            self.new_session(input)?
        };
        self.mirror_session(&session).await?;
        if !self.database_sessions() {
            self.inner.after_create_runtime_session(&session).await?;
        }
        Ok(session)
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<S::Session>> {
        Ok(self
            .get_session_snapshot(token)
            .await?
            .map(|(session, _)| session))
    }

    async fn get_session_snapshot(
        &self,
        token: &str,
    ) -> AuthResult<Option<(S::Session, Option<crate::session::SessionData>)>> {
        if self.storage.is_none() {
            return self.inner.get_session_snapshot(token).await;
        }
        let raw = self.secondary()?.get(token).await?;
        if raw.is_some() {
            let Some(mut cached) = decode(raw).and_then(|value| value.as_object().cloned()) else {
                return Ok(None);
            };
            let fields = object(cached.remove("session").unwrap_or(Value::Null))?;
            let session = self.hydrate_session(fields.clone())?;
            let mut view = SessionView::try_from(fields)?;
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
        if !self.database_sessions() || self.config.session.preserve_session_in_database {
            return Ok(None);
        }
        Ok(self
            .inner
            .get_session(token)
            .await?
            .map(|session| (session, None)))
    }

    async fn update_session_fields(
        &self,
        token: &str,
        fields: Map<String, Value>,
    ) -> AuthResult<Option<S::Session>> {
        let mut public = fields.clone();
        let _ = public.insert("updatedAt".into(), json!(Utc::now()));
        let cached = self.update_cached_session(token, public).await?;
        if self.database_sessions() {
            self.inner.update_session_fields(token, fields).await
        } else {
            Ok(cached)
        }
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>> {
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
    ) -> AuthResult<Vec<(S::Session, Option<SessionView>)>> {
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
            if let Ok(session) = self.hydrate_session(fields.clone())
                && let Ok(mut view) = SessionView::try_from(fields.clone())
            {
                view.active = true;
                sessions.push((session, Some(view)));
            }
        }
        Ok(sessions)
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<S::Session> {
        let cached = self
            .update_cached_session(
                token,
                object(json!({ "expiresAt": expires_at, "updatedAt": Utc::now() }))?,
            )
            .await?;
        if self.database_sessions() {
            self.inner.update_session_expiry(token, expires_at).await
        } else {
            cached.ok_or(AuthError::SessionNotFound)
        }
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        if self.storage.is_none() {
            return self.inner.delete_session(token).await;
        }
        if let Some(cached) = decode(self.secondary()?.get(token).await?) {
            if let Some(user_id) = cached
                .get("session")
                .and_then(|session| session.get("userId"))
                .and_then(Value::as_str)
            {
                let mut references = self.references(user_id).await?;
                references.retain(|reference| {
                    reference.token != token && reference.expires_at > Utc::now().timestamp_millis()
                });
                self.write_references(user_id, references).await?;
            } else {
                tracing::error!("Session not found in secondary storage");
                return Ok(());
            }
        }
        self.secondary()?.delete(token).await?;
        if !self.database_sessions() {
            return Ok(());
        }
        if self.config.session.preserve_session_in_database {
            if let Some(session) = self.inner.get_session(token).await?
                && session.expires_at() > Utc::now()
            {
                self.inner.end_session(token).await?;
            }
            Ok(())
        } else {
            self.inner.delete_session(token).await
        }
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        if self.storage.is_none() {
            return self.inner.delete_user_sessions(user_id).await;
        }
        let references = self.references(user_id).await?;
        if self.database_sessions() {
            if self.config.session.preserve_session_in_database {
                for session in self.inner.get_user_sessions(user_id).await? {
                    if session.expires_at() > Utc::now() {
                        self.inner.end_session(session.token()).await?;
                    }
                }
            } else {
                self.inner.delete_user_sessions(user_id).await?;
            }
        }
        self.delete_cached_sessions(user_id, &references).await
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        if self.database_sessions() && !self.config.session.preserve_session_in_database {
            self.inner.delete_expired_sessions().await
        } else {
            Ok(0)
        }
    }

    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        let cached = self
            .update_cached_session(
                token,
                object(json!({ "activeTeamId": team_id, "updatedAt": Utc::now() }))?,
            )
            .await?;
        if self.database_sessions() {
            self.inner.update_session_active_team(token, team_id).await
        } else {
            cached.ok_or(AuthError::SessionNotFound)
        }
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        let cached = self
            .update_cached_session(
                token,
                object(
                    json!({ "activeOrganizationId": organization_id, "updatedAt": Utc::now() }),
                )?,
            )
            .await?;
        if self.database_sessions() {
            self.inner
                .update_session_active_organization(token, organization_id)
                .await
        } else {
            cached.ok_or(AuthError::SessionNotFound)
        }
    }

    async fn accept_invitation_with_teams(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: Option<&str>,
        teams_enabled: bool,
        maximum: TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Invitation, Option<S::Session>)> {
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
