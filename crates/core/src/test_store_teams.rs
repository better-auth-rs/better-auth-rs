use super::*;
use crate::{
    CreateOrganizationRole, CreateTeam, OrganizationRole, Team, TeamMember, UpdateOrganizationRole,
    store::{OrganizationRoleStore, TeamStore},
};
#[async_trait]
impl TeamStore for MemoryStore {
    async fn create_team(&self, input: CreateTeam) -> AuthResult<Team> {
        let team = Team {
            id: uuid::Uuid::new_v4().to_string(),
            name: input.name,
            organization_id: input.organization_id,
            created_at: Utc::now(),
            updated_at: input.updated_at,
        };
        self.lock().teams.insert(team.id.clone(), team.clone());
        Ok(team)
    }
    async fn get_team(&self, id: &str) -> AuthResult<Option<Team>> {
        Ok(self.lock().teams.get(id).cloned())
    }
    async fn update_team(&self, id: &str, name: &str) -> AuthResult<Team> {
        let mut state = self.lock();
        let team = state
            .teams
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Team not found"))?;
        team.name = name.to_owned();
        Ok(team.clone())
    }
    async fn delete_team(&self, id: &str) -> AuthResult<()> {
        let mut state = self.lock();
        state.teams.remove(id);
        for invitation in state
            .invitations
            .values_mut()
            .filter(|invitation| invitation.is_pending())
        {
            if let Some(ids) = invitation.team_id.as_ref() {
                let retained: Vec<_> = ids.split(',').filter(|team_id| *team_id != id).collect();
                invitation.team_id = (!retained.is_empty()).then(|| retained.join(","));
            }
        }
        state.team_members.retain(|member| member.team_id != id);
        Ok(())
    }
    async fn list_organization_teams(&self, organization_id: &str) -> AuthResult<Vec<Team>> {
        let mut teams: Vec<_> = self
            .lock()
            .teams
            .values()
            .filter(|team| team.organization_id == organization_id)
            .cloned()
            .collect();
        teams.sort_by_key(|team| team.created_at);
        Ok(teams)
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        let state = self.lock();
        Ok(state
            .team_members
            .iter()
            .filter(|member| member.user_id == user_id)
            .filter_map(|member| state.teams.get(&member.team_id).cloned())
            .collect())
    }
    async fn get_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<TeamMember>> {
        Ok(self
            .lock()
            .team_members
            .iter()
            .find(|member| member.team_id == team_id && member.user_id == user_id)
            .cloned())
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<TeamMember>> {
        Ok(self
            .lock()
            .team_members
            .iter()
            .filter(|member| member.team_id == team_id)
            .cloned()
            .collect())
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<Option<TeamMember>> {
        let mut state = self.lock();
        if !state.teams.contains_key(team_id) {
            return Err(AuthError::not_found("Team not found"));
        }
        if let Some(member) = state
            .team_members
            .iter()
            .find(|member| member.team_id == team_id && member.user_id == user_id)
        {
            return Ok(Some(member.clone()));
        }
        if maximum.is_some_and(|max| {
            state
                .team_members
                .iter()
                .filter(|member| member.team_id == team_id)
                .count()
                >= max
        }) {
            return Ok(None);
        }
        let member = TeamMember {
            id: uuid::Uuid::new_v4().to_string(),
            team_id: team_id.to_owned(),
            user_id: user_id.to_owned(),
            created_at: Utc::now(),
        };
        state.team_members.push(member.clone());
        Ok(Some(member))
    }
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<()> {
        self.lock()
            .team_members
            .retain(|member| member.team_id != team_id || member.user_id != user_id);
        Ok(())
    }
}
#[async_trait]
impl OrganizationRoleStore for MemoryStore {
    async fn create_organization_role(
        &self,
        input: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let mut state = self.lock();
        if state
            .organization_roles
            .values()
            .any(|role| role.organization_id == input.organization_id && role.role == input.role)
        {
            return Err(AuthError::bad_request("Role already exists"));
        }
        let role = OrganizationRole {
            id: uuid::Uuid::new_v4().to_string(),
            organization_id: input.organization_id,
            role: input.role,
            permission: input.permission,
            created_at: Utc::now(),
            updated_at: None,
        };
        state
            .organization_roles
            .insert(role.id.clone(), role.clone());
        Ok(role)
    }
    async fn get_organization_role(&self, id: &str) -> AuthResult<Option<OrganizationRole>> {
        Ok(self.lock().organization_roles.get(id).cloned())
    }
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>> {
        let mut roles: Vec<_> = self
            .lock()
            .organization_roles
            .values()
            .filter(|role| role.organization_id == organization_id)
            .cloned()
            .collect();
        roles.sort_by_key(|role| role.created_at);
        Ok(roles)
    }
    async fn update_organization_role(
        &self,
        id: &str,
        update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let mut state = self.lock();
        let role = state
            .organization_roles
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Role not found"))?;
        if let Some(name) = update.role {
            role.role = name;
        }
        if let Some(permission) = update.permission {
            role.permission = permission;
        }
        role.updated_at = Some(Utc::now());
        Ok(role.clone())
    }
    async fn delete_organization_role(&self, id: &str) -> AuthResult<()> {
        self.lock().organization_roles.remove(id);
        Ok(())
    }
}

#[tokio::test]
async fn memory_organization_deletion_cleans_teams_and_roles() {
    let store = MemoryStore::new(test_config());
    let org = store
        .create_organization(CreateOrganization::new("one", "one"))
        .await
        .unwrap();
    let team = store
        .create_team(CreateTeam {
            name: "one".into(),
            organization_id: org.id.clone(),
            updated_at: None,
        })
        .await
        .unwrap();
    let first = store
        .add_team_member(&team.id, "user-one", Some(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .add_team_member(&team.id, "user-one", Some(1))
            .await
            .unwrap()
            .unwrap()
            .id,
        first.id
    );
    assert!(
        store
            .add_team_member(&team.id, "user-two", Some(1))
            .await
            .unwrap()
            .is_none()
    );
    let role = store
        .create_organization_role(CreateOrganizationRole {
            organization_id: org.id.clone(),
            role: "editor".into(),
            permission: serde_json::json!({"team":["create"]}),
        })
        .await
        .unwrap();
    store.delete_organization(&org.id).await.unwrap();
    assert!(store.get_team(&team.id).await.unwrap().is_none());
    assert!(store.list_team_members(&team.id).await.unwrap().is_empty());
    assert!(
        store
            .get_organization_role(&role.id)
            .await
            .unwrap()
            .is_none()
    );
}
