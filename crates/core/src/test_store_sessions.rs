use super::*;

#[async_trait]
impl SessionStore<BundledSchema> for MemoryStore {
    async fn accept_invitation_with_teams(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: &str,
        teams_enabled: bool,
        maximum: crate::store::TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Invitation, Option<SessionView>)> {
        let fields = self
            .organization_fields()
            .invitation
            .storage_fields(Default::default(), false)?;
        let invitation_snapshot = {
            let mut state = self.lock();
            let invitation = state
                .invitations
                .get_mut(invitation_id)
                .filter(|invitation| invitation.is_pending())
                .ok_or_else(|| AuthError::bad_request("Invitation not found"))?;
            invitation.status = InvitationStatus::Accepted;
            invitation.additional_fields.extend(fields);
            invitation.clone()
        };
        let accepted = self.output_invitation(invitation_snapshot.clone())?;
        let result = async {
            let mut limits = std::collections::HashMap::new();
            for team_id in invitation_snapshot
                .team_id
                .as_deref()
                .filter(|_| teams_enabled)
                .unwrap_or("")
                .split(',')
                .filter(|id| !id.is_empty())
            {
                {
                    let state = self.lock();
                    if !state.teams.get(team_id).is_some_and(|team| {
                        team.organization_id == invitation_snapshot.organization_id
                    }) {
                        return Err(AuthError::bad_request("Team not found"));
                    }
                }
                let limit = maximum.maximum(team_id).await?;
                {
                    let state = self.lock();
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
                limits.insert(team_id.to_owned(), limit);
            }
            let mut state = self.lock();
            let invitation = state
                .invitations
                .get(invitation_id)
                .filter(|invitation| invitation.status == InvitationStatus::Accepted)
                .cloned()
                .ok_or_else(|| AuthError::bad_request("Invitation not found"))?;
            let team_ids: Vec<_> = invitation
                .team_id
                .as_deref()
                .filter(|_| teams_enabled)
                .unwrap_or("")
                .split(',')
                .filter(|id| !id.is_empty())
                .collect();
            if !state.sessions.contains_key(session_token) {
                return Err(AuthError::SessionNotFound);
            }
            if state.members.values().any(|member| {
                member.organization_id == invitation.organization_id && member.user_id == user_id
            }) {
                return Err(AuthError::bad_request("User is already a member"));
            }
            for team_id in &team_ids {
                if !state
                    .teams
                    .get(*team_id)
                    .is_some_and(|team| team.organization_id == invitation.organization_id)
                {
                    return Err(AuthError::bad_request("Team not found"));
                }
                if !state
                    .team_members
                    .iter()
                    .any(|member| member.team_id == *team_id && member.user_id == user_id)
                    && limits[*team_id].is_some_and(|limit| {
                        state
                            .team_members
                            .iter()
                            .filter(|member| member.team_id == *team_id)
                            .count()
                            >= limit
                    })
                {
                    return Err(AuthError::forbidden("Team member limit reached"));
                }
            }
            let member_fields =
                Self::create_fields(&self.organization_fields().member, Default::default())?;
            let member = Member {
                additional_fields: member_fields,
                id: uuid::Uuid::new_v4().to_string(),
                organization_id: invitation.organization_id.clone(),
                user_id: user_id.to_owned(),
                role: invitation.role,
                created_at: Utc::now(),
            };
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
            state.members.insert(member.id.clone(), member.clone());
            let session = state.sessions.get_mut(session_token).unwrap();
            let cookie_session = if let [team_id] = team_ids.as_slice() {
                session.active_team_id = Some((*team_id).to_owned());
                session.updated_at = Utc::now();
                Some(session.clone())
            } else {
                None
            };
            session.active_organization_id = Some(invitation.organization_id);
            session.updated_at = Utc::now();
            Ok((member_output, cookie_session))
        }
        .await;
        match result {
            Ok((member, session)) => Ok((member, accepted, session)),
            Err(error) => {
                let fields = self
                    .organization_fields()
                    .invitation
                    .storage_fields(Default::default(), false)?;
                let restored = {
                    let mut state = self.lock();
                    state
                        .invitations
                        .get_mut(invitation_id)
                        .filter(|invitation| invitation.status == InvitationStatus::Accepted)
                        .map(|invitation| {
                            invitation.status = InvitationStatus::Pending;
                            invitation.additional_fields.extend(fields);
                            invitation.clone()
                        })
                };
                if let Some(restored) = restored {
                    let _ = self.output_invitation(restored)?;
                }
                Err(error)
            }
        }
    }

    async fn create_session(&self, create_session: CreateSession) -> AuthResult<SessionView> {
        let now = Utc::now();
        let token = format!("session_{}", uuid::Uuid::new_v4());
        let session = SessionView {
            visible_fields: None,
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
            additional_fields: Default::default(),
        };
        self.lock().sessions.insert(token, session.clone());
        Ok(session)
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<SessionView>> {
        Ok(self.lock().sessions.get(token).cloned())
    }

    async fn update_session_fields(
        &self,
        token: &str,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<Option<SessionView>> {
        let mut data = self.lock();
        let Some(session) = data.sessions.get_mut(token) else {
            return Ok(None);
        };
        session.additional_fields.extend(fields);
        session.updated_at = Utc::now();
        Ok(Some(session.clone()))
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<SessionView>> {
        Ok(self
            .lock()
            .sessions
            .values()
            .filter(|session| session.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        if let Some(session) = self.lock().sessions.get_mut(token) {
            session.expires_at = expires_at;
            session.updated_at = Utc::now();
            Ok(())
        } else {
            Err(AuthError::SessionNotFound)
        }
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        self.lock().sessions.remove(token);
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        self.lock()
            .sessions
            .retain(|_, session| session.user_id != user_id);
        Ok(())
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        let now = Utc::now();
        let mut state = self.lock();
        let before = state.sessions.len();
        state
            .sessions
            .retain(|_, session| session.expires_at > now && session.active);
        Ok(before - state.sessions.len())
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<SessionView> {
        let mut state = self.lock();
        let session = state
            .sessions
            .get_mut(token)
            .ok_or(AuthError::SessionNotFound)?;
        session.active_organization_id = organization_id.map(str::to_owned);
        session.updated_at = Utc::now();
        Ok(session.clone())
    }
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<SessionView> {
        let mut state = self.lock();
        let session = state
            .sessions
            .get_mut(token)
            .ok_or(AuthError::SessionNotFound)?;
        session.active_team_id = team_id.map(str::to_owned);
        session.updated_at = Utc::now();
        Ok(session.clone())
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
    let store = MemoryStore::new(test_config());
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
                &session.token,
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
            &session.token,
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
