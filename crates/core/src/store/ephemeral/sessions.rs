use super::hooks::CommittedWrite;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, SessionUpdate};
use better_auth_schema_registry::EntityRole;
use serde_json::{Map, json};

impl EphemeralStore {
    pub(super) fn output_session(&self, mut session: SessionView) -> AuthResult<SessionView> {
        let mut output = Map::new();
        for (name, field) in &self.session_config.additional_fields {
            let value = session
                .additional_fields
                .get(field.field_name.as_ref().unwrap_or(name))
                .cloned();
            if let Some(value) = field.adapter_output(value, true)? {
                let _ = output.insert(name.clone(), value);
            }
        }
        session.additional_fields = output;
        Ok(session)
    }
}

#[async_trait]
impl SessionStore<StatelessSchema> for EphemeralStore {
    async fn update_session_with_writer(
        &self,
        token: &str,
        update: SessionUpdate,
        secondary: Option<crate::store::SessionUpdateWriter<StatelessSchema>>,
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
            let mut state = self.lock()?;
            let invitation = state
                .invitations
                .get_mut(invitation_id)
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
                    if !state.teams.get(team_id).is_some_and(|team| {
                        team.organization_id == invitation_snapshot.organization_id
                    }) {
                        return Err(AuthError::bad_request("Team not found"));
                    }
                }
                let limit = maximum.maximum(team_id).await?;
                {
                    let state = self.lock()?;
                    if !state
                        .team_members
                        .iter()
                        .any(|member| member.team_id == team_id && member.user_id == user_id)
                        && limit.is_some_and(|limit| {
                            state
                                .team_members
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
                .get(invitation_id)
                .filter(|invitation| invitation.status == InvitationStatus::Accepted)
                .cloned()
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
                        .get(token)
                        .cloned()
                        .ok_or(AuthError::SessionNotFound)
                })
                .transpose()?;
            if state.members.values().any(|member| {
                member.organization_id == invitation.organization_id && member.user_id == user_id
            }) {
                return Err(AuthError::bad_request("User is already a member"));
            }
            let mut reserved_teams = HashMap::new();
            for team_id in &team_ids {
                let team = state
                    .teams
                    .get(*team_id)
                    .filter(|team| team.organization_id == invitation.organization_id)
                    .ok_or_else(|| AuthError::bad_request("Team not found"))?;
                if !state
                    .team_members
                    .iter()
                    .any(|member| member.team_id == *team_id && member.user_id == user_id)
                    && !reserved_teams.contains_key(*team_id)
                {
                    let actual = state
                        .team_members
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
                id: uuid::Uuid::new_v4().to_string(),
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
                    .iter()
                    .any(|member| member.team_id == *team_id && member.user_id == user_id)
                {
                    state.team_members.push(crate::TeamMember {
                        id: uuid::Uuid::new_v4().to_string(),
                        team_id: (*team_id).to_owned(),
                        user_id: user_id.to_owned(),
                        created_at: Utc::now(),
                    });
                }
            }
            state.teams.extend(reserved_teams);
            let _ = state.members.insert(member.id.clone(), member.clone());
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
            let _ = state.sessions.insert(session.token.clone(), session);
            Ok((member_output, cookie_session))
        }
        .await;
        match result {
            Ok((member, session)) => Ok((member, accepted, session)),
            Err(error) => {
                let restored = {
                    let mut state = self.lock()?;
                    if let Some(invitation) = state
                        .invitations
                        .get_mut(invitation_id)
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
        let transaction = EphemeralTransaction { store: self };
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
                return Err(AuthError::forbidden(
                    "session creation cancelled by database hook",
                ));
            }
        }
        Ok(())
    }

    async fn after_create_runtime_session(&self, session: &SessionView) -> AuthResult<()> {
        self.after(CommittedWrite::SessionCreated(session.clone()))
            .await
    }

    async fn create_session(&self, mut create_session: CreateSession) -> AuthResult<SessionView> {
        self.before_create_runtime_session(&mut create_session)
            .await?;
        let now = Utc::now();
        let token = format!("session_{}", uuid::Uuid::new_v4());
        let session = SessionView {
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
            id: uuid::Uuid::new_v4().to_string(),
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
                .storage_fields(self.session_config.default_fields(), true)?,
        };
        self.raw("session", "create", |state| {
            let _ = state.sessions.insert(token, session.clone());
            Ok(())
        })
        .await?;
        let session = self.output_session(session)?;
        self.after_create_runtime_session(&session).await?;
        Ok(session)
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<SessionView>> {
        self.raw("session", "findOne", |state| {
            Ok(state.sessions.get(token).cloned())
        })
        .await?
        .map(|session| self.output_session(session))
        .transpose()
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
                Ok(state
                    .sessions
                    .values()
                    .filter(|session| session.user_id == user_id)
                    .cloned()
                    .collect())
            })
            .await?;
        sessions
            .into_iter()
            .map(|session| self.output_session(session))
            .collect()
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
                Ok(state.sessions.get(token).cloned())
            })
            .await?;
        // A failed single-row snapshot prevents deletion, unlike a failed batch snapshot.
        let Some(session) = session.and_then(|row| self.output_session(row).ok()) else {
            return Ok(());
        };
        let transaction = EphemeralTransaction { store: self };
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
            let _ = state.sessions.shift_remove(token);
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
        input_transform: Some(Arc::new(move |value| {
            if rejection.load(Ordering::SeqCst) && value == Some(json!("updated")) {
                return Err(AuthError::bad_request("transform failed"));
            }
            Ok(value.map(|value| json!(format!("{}:in", value.as_str().unwrap()))))
        })),
        output_transform: Some(Arc::new(|value| {
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
        &organization.id,
        "member@example.com",
        "member",
        "owner",
        Utc::now() + chrono::Duration::days(1),
    );
    input.team_id = Some(team.id.clone());
    let invitation = store.create_invitation(input).await.unwrap();
    let session = store
        .create_session(CreateSession {
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
                &invitation.id,
                "member",
                Some(&session.token),
                true,
                TeamMemberLimits::Fixed(None)
            )
            .await
            .is_err()
    );
    assert!(store.list_team_members(&team.id).await.unwrap().is_empty());
    assert!(
        store
            .get_member(&organization.id, "member")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_invitation_by_id(&invitation.id)
            .await
            .unwrap()
            .unwrap()
            .is_pending()
    );
    reject.store(false, Ordering::SeqCst);
    let (member, accepted, _) = store
        .accept_invitation_with_teams(
            &invitation.id,
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
            .get_invitation_by_id(&invitation.id)
            .await
            .unwrap()
            .unwrap()
            .additional_fields,
        accepted.additional_fields
    );
    assert_eq!(store.list_team_members(&team.id).await.unwrap().len(), 1);
}
