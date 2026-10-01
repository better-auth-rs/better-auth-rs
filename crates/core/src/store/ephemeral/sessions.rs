use super::hooks::CommittedWrite;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, SessionUpdate};
#[cfg(test)]
use crate::user_fields::UserFieldTransform;
use better_auth_schema_registry::EntityRole;
use serde_json::{Map, json};

impl EphemeralStore {
    pub(super) async fn output_session(&self, session: SessionView) -> AuthResult<SessionView> {
        // Projection preserves the one input row.
        Ok(self.output_sessions(vec![session]).await?.remove(0))
    }

    pub(super) async fn output_sessions(
        &self,
        sessions: Vec<SessionView>,
    ) -> AuthResult<Vec<SessionView>> {
        let mut rows: Vec<_> = sessions
            .into_iter()
            .map(|mut session| {
                let storage: Map<String, serde_json::Value> = session.clone().into();
                session.additional_fields.clear();
                (session, storage)
            })
            .collect();
        crate::user_fields::project_fields(
            &mut rows,
            &self.session_config.additional_fields,
            |(session, storage), name, field| {
                Box::pin(async move {
                    let value = storage
                        .get(field.field_name.as_deref().unwrap_or(name))
                        .or_else(|| storage.get(name))
                        .cloned();
                    if let Some(value) = field.adapter_output(value, true).await? {
                        let _ = session.additional_fields.insert(name.to_owned(), value);
                    }
                    Ok(())
                })
            },
        )
        .await?;
        Ok(rows.into_iter().map(|(session, _)| session).collect())
    }
}

#[async_trait]
impl SessionStore<StatelessSchema> for EphemeralStore {
    async fn update_session_with_writer(
        &self,
        token: &str,
        update: SessionUpdate,
        secondary: Option<crate::store::SessionUpdateWriter>,
    ) -> AuthResult<Option<SessionView>> {
        EphemeralStore::update_session_with_writer(self, token, update, secondary).await
    }

    async fn end_session(&self, token: &str) -> AuthResult<()> {
        self.delete_sessions_with_hooks(|row| row.token == token, true)
            .await
            .map(|_| ())
    }

    async fn accept_invitation_with_teams(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: Option<&str>,
        teams_enabled: bool,
        maximum: crate::store::TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Invitation, Option<SessionView>)> {
        let invitation_snapshot = {
            let state = self.lock()?;
            let mut invitation = state
                .invitations
                .get_mut(invitation_id)?
                .filter(|invitation| invitation.is_pending())
                .ok_or_else(|| AuthError::bad_request("Invitation not found"))?;
            *invitation = self.store_record(
                EntityRole::Invitation,
                invitation.clone(),
                Some(
                    [("status".into(), json!(InvitationStatus::Accepted))]
                        .into_iter()
                        .collect(),
                ),
                Map::new(),
            )?;
            invitation.clone()
        };
        let accepted = self.output_invitation(invitation_snapshot.clone())?;
        let result = async {
            let mut limits = std::collections::HashMap::new();
            for team_id in invitation_snapshot
                .team_id
                .typed()?
                .as_deref()
                .filter(|_| teams_enabled)
                .unwrap_or("")
                .split(',')
                .filter(|id| !id.is_empty())
            {
                {
                    let state = self.lock()?;
                    if !state.teams.get(team_id)?.is_some_and(|team| {
                        team.organization_id == invitation_snapshot.organization_id
                    }) {
                        return Err(AuthError::bad_request("Team not found"));
                    }
                }
                let limit = maximum.maximum(team_id).await?;
                {
                    let state = self.lock()?;
                    let members = state.team_members.snapshot()?;
                    if !members
                        .iter()
                        .any(|member| member.team_id == team_id && member.user_id == user_id)
                        && limit.is_some_and(|limit| {
                            members
                                .iter()
                                .filter(|member| member.team_id == team_id)
                                .count()
                                >= limit
                        })
                    {
                        return Err(AuthError::forbidden("Team member limit reached"));
                    }
                }
                let _ = limits.insert(team_id.to_owned(), limit);
            }
            let mut state = self.lock()?;
            let invitation = state
                .invitations
                .get(invitation_id)?
                .filter(|invitation| invitation.status == InvitationStatus::Accepted)
                .ok_or_else(|| AuthError::bad_request("Invitation not found"))?;
            let team_ids: Vec<_> = invitation
                .team_id
                .typed()?
                .as_deref()
                .filter(|_| teams_enabled)
                .unwrap_or("")
                .split(',')
                .filter(|id| !id.is_empty())
                .collect();
            let session = session_token
                .map(|token| {
                    state
                        .sessions
                        .find(|row| row.token == token)?
                        .ok_or(AuthError::SessionNotFound)
                })
                .transpose()?;
            if state.members.snapshot()?.iter().any(|member| {
                member.organization_id == invitation.organization_id && member.user_id == user_id
            }) {
                return Err(AuthError::bad_request("User is already a member"));
            }
            let mut reserved_teams = HashMap::new();
            for team_id in &team_ids {
                let team = state
                    .teams
                    .get(*team_id)?
                    .filter(|team| team.organization_id == invitation.organization_id)
                    .ok_or_else(|| AuthError::bad_request("Team not found"))?;
                if !state
                    .team_members
                    .snapshot()?
                    .iter()
                    .any(|member| member.team_id == *team_id && member.user_id == user_id)
                    && !reserved_teams.contains_key(*team_id)
                {
                    let actual = state
                        .team_members
                        .snapshot()?
                        .iter()
                        .filter(|member| member.team_id == *team_id)
                        .count();
                    let (team, reserved) = self.reserve_team_seat(
                        team.clone(),
                        actual,
                        *limits.get(*team_id).ok_or_else(|| {
                            AuthError::internal("Invitation teams changed while resolving capacity")
                        })?,
                    )?;
                    if !reserved {
                        return Err(AuthError::forbidden("Team member limit reached"));
                    }
                    let _ = reserved_teams.insert((*team_id).to_owned(), team);
                }
            }
            let organization_id = invitation.organization_id.typed()?.clone();
            let member = Member {
                additional_fields: Default::default(),
                id: self
                    .generated_id("member", None, state.members.len())?
                    .map(crate::SchemaValue::Typed)
                    .unwrap_or_default(),
                organization_id: invitation.organization_id.clone(),
                user_id: (user_id.to_owned()).into(),
                role: invitation.role,
                created_at: (Utc::now()).into(),
            };
            let member: Member = self.store_record(EntityRole::Member, member, None, Map::new())?;
            let member_output = self.output_member(member.clone())?;
            for team_id in &team_ids {
                if !state
                    .team_members
                    .snapshot()?
                    .iter()
                    .any(|member| member.team_id == *team_id && member.user_id == user_id)
                {
                    let id = self
                        .generated_id("teamMember", None, state.team_members.len())?
                        .map(crate::SchemaValue::Typed)
                        .unwrap_or_default();
                    state.team_members.push(crate::TeamMember {
                        id,
                        team_id: (*team_id).to_owned().into(),
                        user_id: user_id.to_owned(),
                        created_at: Utc::now(),
                    });
                }
            }
            for (id, team) in reserved_teams {
                let _ = state.teams.replace(&id, team)?;
            }
            state.members.push(member.clone());
            let Some(mut session) = session else {
                return Ok((member_output, None));
            };
            let cookie_session = if let [team_id] = team_ids.as_slice() {
                session.active_team_id = Some((*team_id).to_owned());
                if let Some(fields) = &mut session.visible_fields {
                    let _ = fields.insert("activeTeamId".into());
                }
                session.updated_at = Utc::now();
                Some(session.clone())
            } else {
                None
            };
            session.active_organization_id = Some(organization_id);
            if let Some(fields) = &mut session.visible_fields {
                let _ = fields.insert("activeOrganizationId".into());
            }
            session.updated_at = Utc::now();
            let mut stored = state
                .sessions
                .find_mut(|row| row.token == session.token)?
                .ok_or(AuthError::SessionNotFound)?;
            *stored = session;
            Ok((member_output, cookie_session))
        }
        .await;
        match result {
            Ok((member, session)) => Ok((member, accepted, session)),
            Err(error) => {
                let restored = {
                    let state = self.lock()?;
                    if let Some(mut invitation) = state
                        .invitations
                        .get_mut(invitation_id)?
                        .filter(|invitation| invitation.status == InvitationStatus::Accepted)
                    {
                        *invitation = self.store_record(
                            EntityRole::Invitation,
                            invitation.clone(),
                            Some(
                                [("status".into(), json!(InvitationStatus::Pending))]
                                    .into_iter()
                                    .collect(),
                            ),
                            Map::new(),
                        )?;
                        Some(invitation.clone())
                    } else {
                        None
                    }
                };
                if let Some(restored) = restored {
                    let _ = self.output_invitation(restored)?;
                }
                Err(error)
            }
        }
    }

    async fn before_create_runtime_session(&self, input: &mut CreateSession) -> AuthResult<()> {
        if self.before_create_runtime_session_optional(input).await? {
            Ok(())
        } else {
            Err(AuthError::forbidden(
                "session creation cancelled by database hook",
            ))
        }
    }
    async fn before_create_runtime_session_optional(
        &self,
        input: &mut CreateSession,
    ) -> AuthResult<bool> {
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeCreateSession,
                hook.before_create_session(input, &context),
            )
            .await?
                == DatabaseHookControl::Cancel
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn after_create_runtime_session(
        &self,
        session: &SessionView,
        request: Option<crate::hooks::RequestHookContext>,
    ) -> AuthResult<()> {
        self.after_with_request(CommittedWrite::SessionCreated(session.clone()), request)
            .await
    }

    async fn create_session(&self, input: CreateSession) -> AuthResult<SessionView> {
        self.create_session_optional(input)
            .await?
            .ok_or_else(|| AuthError::forbidden("session creation cancelled by database hook"))
    }
    async fn create_session_optional(
        &self,
        mut create_session: CreateSession,
    ) -> AuthResult<Option<SessionView>> {
        if !self
            .before_create_runtime_session_optional(&mut create_session)
            .await?
        {
            return Ok(None);
        }
        let now = Utc::now();
        let token = crate::id::random_id(None);
        let mut fields = self.session_config.default_fields();
        fields.extend(create_session.additional_fields);
        let mut plugin_fields = serde_json::Map::new();
        for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
            if let Some(value) = fields.remove(name) {
                let _ = plugin_fields.insert(name.into(), value);
            }
        }
        let id = self
            .generated_id("session", None, self.lock()?.sessions.len())?
            .map(crate::SchemaValue::Typed)
            .unwrap_or_default();
        let mut session = SessionView {
            visible_fields: Some(
                [
                    ("impersonatedBy", create_session.impersonated_by.is_some()),
                    (
                        "activeOrganizationId",
                        create_session.active_organization_id.is_some(),
                    ),
                ]
                .into_iter()
                .filter(|(_, present)| *present)
                .map(|(name, _)| name.to_owned())
                .collect(),
            ),
            id,
            expires_at: create_session.expires_at,
            token: token.clone(),
            created_at: now,
            updated_at: now,
            ip_address: create_session.ip_address.or_else(|| Some(String::new())),
            user_agent: create_session.user_agent.or_else(|| Some(String::new())),
            user_id: create_session.user_id,
            impersonated_by: create_session.impersonated_by,
            active_organization_id: create_session.active_organization_id,
            active_team_id: None,
            active: true,
            additional_fields: self
                .session_config
                .field_schema()
                .storage_fields(fields, true)
                .await?,
        };
        for (field, target) in [
            ("impersonatedBy", &mut session.impersonated_by),
            ("activeOrganizationId", &mut session.active_organization_id),
            ("activeTeamId", &mut session.active_team_id),
        ] {
            if let Some(value) = plugin_fields.remove(field) {
                *target = serde_json::from_value(value)?;
                if let Some(visible) = &mut session.visible_fields {
                    let _ = visible.insert(field.into());
                }
            }
        }
        self.raw("session", "create", |state| {
            state.sessions.push(session.clone());
            Ok(())
        })
        .await?;
        let session = self.output_session(session).await?;
        self.after_create_runtime_session(&session, crate::hooks::current_request_hook_context())
            .await?;
        Ok(Some(session))
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<SessionView>> {
        let session = self
            .raw("session", "findOne", |state| {
                state.sessions.find(|row| row.token == token)
            })
            .await?;
        futures_util::future::OptionFuture::from(
            session.map(|session| self.output_session(session)),
        )
        .await
        .transpose()
    }

    async fn get_session_snapshots(
        &self,
        tokens: &[String],
        only_active: bool,
    ) -> AuthResult<Vec<(SessionView, Option<crate::session::SessionData>)>> {
        let now = Utc::now();
        let sessions = self
            .raw("session", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state
                        .sessions
                        .snapshot()?
                        .into_iter()
                        .filter(|session| {
                            tokens.contains(&session.token)
                                && (!only_active || session.expires_at > now)
                        })
                        .collect(),
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                ))
            })
            .await?;
        Ok(self
            .output_sessions(sessions)
            .await?
            .into_iter()
            .map(|session| (session, None))
            .collect())
    }

    async fn update_session_fields(
        &self,
        token: &str,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<Option<SessionView>> {
        self.update_session_with_hooks(
            token,
            SessionUpdate {
                additional_fields: fields,
                ..Default::default()
            },
        )
        .await
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<SessionView>> {
        let sessions: Vec<_> = self
            .raw("session", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state
                        .sessions
                        .snapshot()?
                        .iter()
                        .filter(|session| session.user_id == user_id)
                        .cloned()
                        .collect(),
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                ))
            })
            .await?;
        self.output_sessions(sessions).await
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<SessionView> {
        self.update_session_with_hooks(
            token,
            SessionUpdate {
                expires_at: Some(expires_at),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        let session = self
            .raw("session", "findOne", |state| {
                state.sessions.find(|row| row.token == token)
            })
            .await?;
        // A failed single-row snapshot prevents deletion, unlike a failed batch snapshot.
        let Some(session) = (match session {
            Some(row) => self.output_session(row).await.ok(),
            None => None,
        }) else {
            return Ok(());
        };
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeDeleteSession,
                hook.before_delete_session(&session, &context),
            )
            .await?
                == DatabaseHookControl::Cancel
            {
                return Ok(());
            }
        }
        self.raw("session", "delete", |state| {
            let _ = state.sessions.remove_first(|row| row.token == token)?;
            Ok(())
        })
        .await?;
        self.after(CommittedWrite::SessionDeleted(session)).await?;
        Ok(())
    }

    async fn delete_sessions(&self, tokens: &[String]) -> AuthResult<()> {
        self.delete_sessions_with_hooks(|row| tokens.contains(&row.token), false)
            .await
            .map(|_| ())
    }

    async fn end_sessions(&self, tokens: &[String]) -> AuthResult<()> {
        self.delete_sessions_with_hooks(|row| tokens.contains(&row.token), true)
            .await
            .map(|_| ())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        self.delete_user_sessions_optional(user_id, false)
            .await
            .map(|_| ())
    }

    async fn delete_user_sessions_optional(
        &self,
        user_id: &str,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        self.delete_sessions_with_hooks(|row| row.user_id == user_id, preserve)
            .await
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        let now = Utc::now();
        self.delete_sessions_with_hooks(|row| row.expires_at <= now || !row.active, false)
            .await
            .map(Option::unwrap_or_default)
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<SessionView> {
        self.update_session_with_hooks(
            token,
            SessionUpdate {
                active_organization_id: Some(organization_id.map(str::to_owned)),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<SessionView> {
        self.update_session_with_hooks(
            token,
            SessionUpdate {
                active_team_id: Some(team_id.map(str::to_owned)),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }
}

#[tokio::test]
async fn invitation_fields_update_atomically_with_team_membership() {
    use crate::{
        CreateTeam,
        organization_fields::OrganizationFields,
        store::{TeamMemberLimits, TeamStore},
        user_fields::{UserConfig, UserFieldConfig},
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, Ordering};
    let reject = Arc::new(AtomicBool::new(true));
    let rejection = reject.clone();
    let field = UserFieldConfig {
        required: Some(false),
        returned: false,
        field_name: Some("stored_marker".into()),
        default_value: Some(json!("created")),
        on_update: Some(Arc::new(|| json!("updated"))),
        input_transform: Some(UserFieldTransform::new(move |value| {
            if rejection.load(Ordering::SeqCst) && value == Some(json!("updated")) {
                return Err(AuthError::bad_request("transform failed"));
            }
            Ok(value.map(|value| json!(format!("{}:in", value.as_str().unwrap()))))
        })),
        output_transform: Some(UserFieldTransform::new(|value| {
            Ok(value.map(|value| json!(format!("{}:out", value.as_str().unwrap()))))
        })),
        ..Default::default()
    };
    let schema = UserConfig {
        additional_fields: [("marker".into(), field)].into(),
    };
    let store = EphemeralStore::new(test_config());
    store
        .configure_organization_fields(OrganizationFields {
            member: schema.clone(),
            invitation: schema,
            ..Default::default()
        })
        .unwrap();
    let organization = store
        .create_organization(CreateOrganization::new("Organization", "organization"))
        .await
        .unwrap();
    let team = store
        .create_team(CreateTeam {
            name: "Team".into(),
            organization_id: organization.id.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut input = CreateInvitation::new(
        organization.id.typed().unwrap(),
        "member@example.com",
        "member",
        "owner",
        Utc::now() + chrono::Duration::days(1),
    );
    input.team_id = Some(team.id.typed().unwrap().clone());
    let invitation = store.create_invitation(input).await.unwrap();
    let session = store
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id: "member".into(),
            expires_at: Utc::now() + chrono::Duration::days(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    assert!(
        store
            .accept_invitation_with_teams(
                invitation.id.typed().unwrap(),
                "member",
                Some(&session.token),
                true,
                TeamMemberLimits::Fixed(None)
            )
            .await
            .is_err()
    );
    assert!(
        store
            .list_team_members(team.id.typed().unwrap())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .get_member(organization.id.typed().unwrap(), "member")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_invitation_by_id(invitation.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .is_pending()
    );
    reject.store(false, Ordering::SeqCst);
    let (member, accepted, _) = store
        .accept_invitation_with_teams(
            invitation.id.typed().unwrap(),
            "member",
            Some(&session.token),
            true,
            TeamMemberLimits::Fixed(None),
        )
        .await
        .unwrap();
    assert_eq!(
        member.additional_fields.get("marker"),
        Some(&json!("created:in:out"))
    );
    assert_eq!(
        accepted.additional_fields.get("marker"),
        Some(&json!("updated:in:out"))
    );
    assert_eq!(
        store
            .get_invitation_by_id(invitation.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .additional_fields,
        accepted.additional_fields
    );
    assert_eq!(
        store
            .list_team_members(team.id.typed().unwrap())
            .await
            .unwrap()
            .len(),
        1
    );
}
