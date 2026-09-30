use super::*;
#[async_trait]
impl OrganizationStore for MemoryStore {
    async fn create_organization(&self, input: CreateOrganization) -> AuthResult<Organization> {
        let mut state = self.lock();
        if state
            .organizations
            .values()
            .any(|org| org.slug == input.slug)
        {
            return Err(AuthError::bad_request("Organization already exists"));
        }
        let org = Organization {
            id: input.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            name: input.name,
            slug: input.slug,
            logo: input.logo,
            metadata: input.metadata,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        state.organizations.insert(org.id.clone(), org.clone());
        Ok(org)
    }
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        Ok(self.lock().organizations.get(id).cloned())
    }
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        Ok(self
            .lock()
            .organizations
            .values()
            .find(|org| org.slug == slug)
            .cloned())
    }
    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        Ok(self
            .lock()
            .organizations
            .values()
            .filter(|org| ids.contains(&org.id))
            .cloned()
            .collect())
    }
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let mut state = self.lock();
        let org = state
            .organizations
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Organization not found"))?;
        if let Some(name) = update.name {
            org.name = name;
        }
        if let Some(slug) = update.slug {
            org.slug = slug;
        }
        if let Some(logo) = update.logo {
            org.logo = Some(logo);
        }
        if let Some(metadata) = update.metadata {
            org.metadata = Some(metadata);
        }
        org.updated_at = Utc::now();
        Ok(org.clone())
    }
    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        let mut state = self.lock();
        state.organizations.remove(id);
        state
            .members
            .retain(|_, member| member.organization_id != id);
        state
            .invitations
            .retain(|_, invitation| invitation.organization_id != id);
        state
            .organization_roles
            .retain(|_, role| role.organization_id != id);
        let team_ids: Vec<_> = state
            .teams
            .values()
            .filter(|team| team.organization_id == id)
            .map(|team| team.id.clone())
            .collect();
        state
            .team_members
            .retain(|member| !team_ids.contains(&member.team_id));
        state.teams.retain(|_, team| team.organization_id != id);
        Ok(())
    }
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        let state = self.lock();
        Ok(state
            .members
            .values()
            .filter(|member| member.user_id == user_id)
            .filter_map(|member| state.organizations.get(&member.organization_id).cloned())
            .collect())
    }
}
#[async_trait]
impl MemberStore for MemoryStore {
    async fn create_member(&self, input: CreateMember) -> AuthResult<Member> {
        let mut state = self.lock();
        if state.members.values().any(|member| {
            member.organization_id == input.organization_id && member.user_id == input.user_id
        }) {
            return Err(AuthError::bad_request("User is already a member"));
        }
        let member = Member {
            id: uuid::Uuid::new_v4().to_string(),
            organization_id: input.organization_id,
            user_id: input.user_id,
            role: input.role,
            created_at: Utc::now(),
        };
        state.members.insert(member.id.clone(), member.clone());
        Ok(member)
    }
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        Ok(self
            .lock()
            .members
            .values()
            .find(|member| member.organization_id == organization_id && member.user_id == user_id)
            .cloned())
    }
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        Ok(self.lock().members.get(id).cloned())
    }
    async fn update_member_role(&self, id: &str, role: &str) -> AuthResult<Member> {
        let mut state = self.lock();
        let member = state
            .members
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Member not found"))?;
        member.role = role.to_owned();
        Ok(member.clone())
    }
    async fn delete_member(&self, id: &str) -> AuthResult<()> {
        let mut state = self.lock();
        if let Some(member) = state.members.remove(id) {
            let ids: Vec<_> = state
                .teams
                .values()
                .filter(|team| team.organization_id == member.organization_id)
                .map(|team| team.id.clone())
                .collect();
            state.team_members.retain(|team_member| {
                team_member.user_id != member.user_id || !ids.contains(&team_member.team_id)
            });
        }
        Ok(())
    }
    async fn list_organization_members(&self, org: &str) -> AuthResult<Vec<Member>> {
        Ok(self
            .lock()
            .members
            .values()
            .filter(|member| member.organization_id == org)
            .cloned()
            .collect())
    }
    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        let mut members = self
            .list_organization_members(&params.organization_id)
            .await?;
        let value = |member: &Member, field: &str| -> Option<String> {
            match field {
                "id" => Some(member.id.clone()),
                "organizationId" => Some(member.organization_id.clone()),
                "userId" => Some(member.user_id.clone()),
                "role" => Some(member.role.clone()),
                "createdAt" => Some(member.created_at.to_rfc3339()),
                _ => None,
            }
        };
        if let (Some(field), Some(expected)) = (&params.filter_field, &params.filter_value) {
            members.retain(|member| {
                let Some(actual) = value(member, field) else {
                    return true;
                };
                let expected = if field == "createdAt" {
                    match chrono::DateTime::parse_from_rfc3339(expected) {
                        Ok(date) => date.with_timezone(&Utc).to_rfc3339(),
                        Err(_) => return false,
                    }
                } else {
                    expected.clone()
                };
                match params.filter_operator.as_deref().unwrap_or("eq") {
                    "eq" => actual == expected,
                    "ne" => actual != expected,
                    "contains" => actual.contains(&expected),
                    "gt" => actual > expected,
                    "gte" => actual >= expected,
                    "lt" => actual < expected,
                    "lte" => actual <= expected,
                    _ => true,
                }
            });
        }
        let field = params.sort_by.as_deref().unwrap_or("createdAt");
        members.sort_by_key(|member| value(member, field));
        if params.sort_direction.as_deref() == Some("desc") {
            members.reverse();
        }
        let total = members.len();
        Ok((
            members
                .into_iter()
                .skip(params.offset.unwrap_or(0))
                .take(params.limit.unwrap_or(usize::MAX))
                .collect(),
            total,
        ))
    }
    async fn count_organization_members(&self, org: &str) -> AuthResult<i64> {
        Ok(self
            .lock()
            .members
            .values()
            .filter(|member| member.organization_id == org)
            .count() as i64)
    }
    async fn count_organization_owners(&self, org: &str) -> AuthResult<i64> {
        Ok(self
            .lock()
            .members
            .values()
            .filter(|member| {
                member.organization_id == org && member.role.split(',').any(|role| role == "owner")
            })
            .count() as i64)
    }
}
#[async_trait]
impl InvitationStore for MemoryStore {
    async fn create_invitation(&self, input: CreateInvitation) -> AuthResult<Invitation> {
        let invitation = Invitation {
            id: uuid::Uuid::new_v4().to_string(),
            organization_id: input.organization_id,
            email: input.email,
            role: input.role,
            status: InvitationStatus::Pending,
            inviter_id: input.inviter_id,
            team_id: input.team_id,
            expires_at: input.expires_at,
            created_at: Utc::now(),
        };
        self.lock()
            .invitations
            .insert(invitation.id.clone(), invitation.clone());
        Ok(invitation)
    }
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        Ok(self.lock().invitations.get(id).cloned())
    }
    async fn get_pending_invitation(
        &self,
        org: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        Ok(self
            .lock()
            .invitations
            .values()
            .find(|invitation| {
                invitation.organization_id == org
                    && invitation.email.eq_ignore_ascii_case(email)
                    && invitation.is_pending()
                    && !invitation.is_expired()
            })
            .cloned())
    }
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        let mut state = self.lock();
        let invitation = state
            .invitations
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
        invitation.status = status;
        Ok(invitation.clone())
    }
    async fn update_invitation_expiry(
        &self,
        id: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<Invitation> {
        let mut state = self.lock();
        let invitation = state
            .invitations
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
        invitation.expires_at = expires_at;
        Ok(invitation.clone())
    }
    async fn list_organization_invitations(&self, org: &str) -> AuthResult<Vec<Invitation>> {
        Ok(self
            .lock()
            .invitations
            .values()
            .filter(|invitation| invitation.organization_id == org)
            .cloned()
            .collect())
    }
    async fn count_pending_organization_invitations(&self, org: &str) -> AuthResult<i64> {
        Ok(self
            .lock()
            .invitations
            .values()
            .filter(|invitation| {
                invitation.organization_id == org
                    && invitation.is_pending()
                    && !invitation.is_expired()
            })
            .count() as i64)
    }
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>> {
        Ok(self
            .lock()
            .invitations
            .values()
            .filter(|invitation| {
                invitation.email.eq_ignore_ascii_case(email)
                    && invitation.is_pending()
                    && !invitation.is_expired()
            })
            .cloned()
            .collect())
    }
}
