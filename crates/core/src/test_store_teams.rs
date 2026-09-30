use super::*;
use crate::{
    CreateOrganizationRole, CreateTeam, OrganizationRole, Team, TeamMember, UpdateOrganizationRole,
    UpdateTeam,
    store::{OrganizationRoleStore, TeamStore},
};
use better_auth_schema_registry::EntityRole;
use serde_json::{Map, json};
#[async_trait]
impl TeamStore for MemoryStore {
    async fn create_team(&self, input: CreateTeam) -> AuthResult<Team> {
        let team = Team {
            additional_fields: Default::default(),
            id: input.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            name: input.name,
            organization_id: input.organization_id,
            created_at: input.created_at.unwrap_or_else(Utc::now),
            updated_at: input.updated_at,
        };
        let team: Team =
            self.store_record(EntityRole::Team, team, None, input.additional_fields)?;
        self.lock().teams.insert(team.id.clone(), team.clone());
        self.output_team(team)
    }
    async fn get_team(&self, id: &str) -> AuthResult<Option<Team>> {
        self.lock()
            .teams
            .get(id)
            .cloned()
            .map(|value| self.output_team(value))
            .transpose()
    }
    async fn update_team(&self, id: &str, update: UpdateTeam) -> AuthResult<Team> {
        let mut patch = Map::new();
        if let Some(name) = update.name {
            let _ = patch.insert("name".into(), json!(name));
        }
        if let Some(organization_id) = update.organization_id {
            let _ = patch.insert("organizationId".into(), json!(organization_id));
        }
        if let Some(created_at) = update.created_at {
            let _ = patch.insert("createdAt".into(), json!(created_at));
        }
        if let Some(updated_at) = update.updated_at {
            let _ = patch.insert("updatedAt".into(), json!(updated_at));
        } else if !self
            .organization_fields()
            .team
            .additional_fields
            .contains_key("updatedAt")
        {
            let _ = patch.insert("updatedAt".into(), json!(Utc::now()));
        }
        let mut state = self.lock();
        let team = state
            .teams
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Team not found"))?;
        *team = self.store_record(
            EntityRole::Team,
            team.clone(),
            Some(patch),
            update.additional_fields,
        )?;
        self.output_team(team.clone())
    }
    async fn delete_team(&self, id: &str) -> AuthResult<()> {
        let mut state = self.lock();
        let organization_id = &state
            .teams
            .get(id)
            .ok_or_else(|| AuthError::not_found("Team not found"))?
            .organization_id;
        let pending = state
            .invitations
            .values()
            .filter(|invitation| {
                invitation.organization_id == *organization_id && invitation.is_pending()
            })
            .cloned()
            .map(|invitation| self.output_invitation(invitation))
            .collect::<AuthResult<Vec<_>>>()?;
        let mut updates = Vec::new();
        for invitation in pending
            .into_iter()
            .filter(|row| row.expires_at > Utc::now())
        {
            let Some(ids) = invitation.team_id.as_ref() else {
                continue;
            };
            let retained: Vec<_> = ids.split(',').filter(|team_id| *team_id != id).collect();
            if retained.len() == ids.split(',').count() {
                continue;
            }
            let mut updated = state
                .invitations
                .get(&invitation.id)
                .cloned()
                .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
            updated = self.store_record(
                EntityRole::Invitation,
                updated,
                Some(
                    [(
                        "teamId".into(),
                        json!((!retained.is_empty()).then(|| retained.join(","))),
                    )]
                    .into_iter()
                    .collect(),
                ),
                Map::new(),
            )?;
            let _ = self.output_invitation(updated.clone())?;
            updates.push(updated);
        }
        // Keep changes staged until every transform succeeds, matching transaction rollback.
        state.teams.remove(id);
        state.team_members.retain(|member| member.team_id != id);
        for invitation in updates {
            state.invitations.insert(invitation.id.clone(), invitation);
        }
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
        teams
            .into_iter()
            .map(|value| self.output_team(value))
            .collect()
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        let state = self.lock();
        state
            .team_members
            .iter()
            .filter(|member| member.user_id == user_id)
            .filter_map(|member| state.teams.get(&member.team_id).cloned())
            .map(|value| self.output_team(value))
            .collect()
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
            additional_fields: Default::default(),
            id: uuid::Uuid::new_v4().to_string(),
            organization_id: input.organization_id,
            role: input.role,
            permission: input.permission,
            created_at: Utc::now(),
            updated_at: None,
        };
        let role: OrganizationRole = self.store_record(
            EntityRole::OrganizationRole,
            role,
            None,
            input.additional_fields,
        )?;
        state
            .organization_roles
            .insert(role.id.clone(), role.clone());
        self.output_organization_role(role)
    }
    async fn get_organization_role(&self, id: &str) -> AuthResult<Option<OrganizationRole>> {
        self.lock()
            .organization_roles
            .get(id)
            .cloned()
            .map(|value| self.output_organization_role(value))
            .transpose()
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
        roles
            .into_iter()
            .map(|value| self.output_organization_role(value))
            .collect()
    }
    async fn update_organization_role(
        &self,
        id: &str,
        update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let mut patch = Map::new();
        if let Some(name) = update.role {
            let _ = patch.insert("role".into(), json!(name));
        }
        if let Some(permission) = update.permission {
            let _ = patch.insert("permission".into(), permission);
        }
        if !self
            .organization_fields()
            .organization_role
            .additional_fields
            .contains_key("updatedAt")
        {
            let _ = patch.insert("updatedAt".into(), json!(Utc::now()));
        }
        let mut state = self.lock();
        let role = state
            .organization_roles
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Role not found"))?;
        *role = self.store_record(
            EntityRole::OrganizationRole,
            role.clone(),
            Some(patch),
            update.additional_fields,
        )?;
        self.output_organization_role(role.clone())
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
            ..Default::default()
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
            additional_fields: Default::default(),
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

#[tokio::test]
async fn memory_team_deletion_rolls_back_invitation_output_errors() {
    use crate::{
        organization_fields::OrganizationFields,
        user_fields::{UserConfig, UserFieldConfig},
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    for failure_stage in ["expired", "unassigned", "updated"] {
        let store = MemoryStore::new(test_config());
        let config = OrganizationFields {
            invitation: UserConfig {
                additional_fields: [(
                    "marker".into(),
                    UserFieldConfig {
                        required: Some(false),
                        default_value: Some(json!("created")),
                        ..Default::default()
                    },
                )]
                .into(),
            },
            ..Default::default()
        };
        store.configure_organization_fields(config.clone()).unwrap();
        let org = store
            .create_organization(CreateOrganization::new("organization", "organization"))
            .await
            .unwrap();
        let team = store
            .create_team(CreateTeam {
                name: "team".into(),
                organization_id: org.id.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        let _ = store
            .add_team_member(&team.id, "owner", None)
            .await
            .unwrap();
        let expires = Utc::now() + chrono::Duration::days(1);
        let mut live = Vec::new();
        for _ in 0..2 {
            let mut input =
                CreateInvitation::new(&org.id, "recipient@example.com", "member", "owner", expires);
            input.team_id = Some(team.id.clone());
            live.push(store.create_invitation(input).await.unwrap().id);
        }
        if failure_stage != "updated" {
            let mut input =
                CreateInvitation::new(&org.id, "other@example.com", "member", "owner", expires);
            if failure_stage == "expired" {
                input.team_id = Some(team.id.clone());
                input.expires_at = Utc::now() - chrono::Duration::days(1);
            }
            let _ = input
                .additional_fields
                .insert("marker".into(), json!("read-fail"));
            let _ = store.create_invitation(input).await.unwrap();
        }
        let updates = Arc::new(AtomicUsize::new(0));
        let count = updates.clone();
        let mut failing = config.clone();
        let marker = failing
            .invitation
            .additional_fields
            .get_mut("marker")
            .unwrap();
        marker.on_update = Some(Arc::new(move || {
            json!(format!(
                "updated-{}",
                count.fetch_add(1, Ordering::SeqCst) + 1
            ))
        }));
        marker.output_transform = Some(Arc::new(|value| {
            if value == Some(json!("read-fail")) || value == Some(json!("updated-2")) {
                Err(AuthError::bad_request("invitation output failed"))
            } else {
                Ok(value)
            }
        }));
        store.configure_organization_fields(failing).unwrap();
        let error = store.delete_team(&team.id).await.unwrap_err();
        assert!(error.to_string().contains("invitation output failed"));
        assert_eq!(
            updates.load(Ordering::SeqCst),
            if failure_stage == "updated" { 2 } else { 0 }
        );
        store.configure_organization_fields(config).unwrap();
        assert!(store.get_team(&team.id).await.unwrap().is_some());
        assert_eq!(store.list_team_members(&team.id).await.unwrap().len(), 1);
        for id in live {
            let row = store.get_invitation_by_id(&id).await.unwrap().unwrap();
            assert_eq!(row.team_id.as_deref(), Some(team.id.as_str()));
            assert_eq!(row.additional_fields.get("marker"), Some(&json!("created")));
        }
    }
}
