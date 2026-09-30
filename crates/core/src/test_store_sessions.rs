use super::*;

#[async_trait]
impl SessionStore<BundledSchema> for MemoryStore {
    async fn accept_invitation_with_teams(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: &str,
        maximum: Option<usize>,
    ) -> AuthResult<(Member, Option<SessionView>)> {
        let mut state = self.lock();
        let invitation = state
            .invitations
            .get(invitation_id)
            .filter(|invitation| invitation.is_pending())
            .cloned()
            .ok_or_else(|| AuthError::bad_request("Invitation not found"))?;
        let team_ids: Vec<_> = invitation
            .team_id
            .as_deref()
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
                && maximum.is_some_and(|limit| {
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
        let member = Member {
            id: uuid::Uuid::new_v4().to_string(),
            organization_id: invitation.organization_id.clone(),
            user_id: user_id.to_owned(),
            role: invitation.role,
            created_at: Utc::now(),
        };
        state.members.insert(member.id.clone(), member.clone());
        state.invitations.get_mut(invitation_id).unwrap().status = InvitationStatus::Accepted;
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
        Ok((member, cookie_session))
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
