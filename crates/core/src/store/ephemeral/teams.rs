use super::*;
#[cfg(test)]
use crate::user_fields::UserFieldTransform;
use crate::{
    CreateOrganizationRole, CreateTeam, OrganizationRole, Team, TeamMember, UpdateOrganizationRole,
    UpdateTeam,
    store::{OrganizationRoleStore, TeamStore},
};
use better_auth_schema_registry::EntityRole;
#[async_trait]
impl TeamStore for EphemeralStore {
    async fn create_team(&self, mut input: CreateTeam) -> AuthResult<Team> {
        let team = Team {
            additional_fields: [("memberCount".into(), Value::Number(0.0))]
                .into_iter()
                .collect(),
            id: self
                .generated_id("team", input.id, self.lock()?.teams.len())?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            name: input.name,
            organization_id: input.organization_id,
            created_at: input
                .additional_fields
                .remove("createdAt")
                .map(crate::SchemaValue::from_field)
                .unwrap_or_else(|| input.created_at.unwrap_or_else(|| Utc::now().into()).into()),
            updated_at: input
                .additional_fields
                .remove("updatedAt")
                .map(crate::SchemaValue::from_field)
                .unwrap_or_else(|| input.updated_at.into()),
        };
        let mut team: Team = self
            .store_record(EntityRole::Team, team, None, input.additional_fields)
            .await?;
        {
            let mut state = self.lock()?;
            if let Some(id) = self.next_serial_id(state.teams.len()) {
                team.id = crate::SchemaValue::from_field(id);
            }
            state.teams.push(team.clone());
        }
        self.output_team(team).await
    }
    async fn get_team(&self, id: &str) -> AuthResult<Option<Team>> {
        let id = self.organization_query(EntityRole::Team, "id", Value::from(id))?;
        let row = self.lock()?.teams.get(&id)?;
        match row {
            Some(row) => self.output_team(row).await.map(Some),
            None => Ok(None),
        }
    }
    async fn get_team_value(&self, id: &Value) -> AuthResult<Option<Team>> {
        let id = self.organization_query(EntityRole::Team, "id", id.clone())?;
        let rows = self.lock()?.teams.snapshot()?;
        match rows.into_iter().find(|row| row.id == id) {
            Some(row) => self.output_team(row).await.map(Some),
            None => Ok(None),
        }
    }
    async fn update_team(&self, id: &str, update: UpdateTeam) -> AuthResult<Team> {
        let id = self.organization_query(EntityRole::Team, "id", Value::from(id))?;
        let mut patch = FieldMap::new();
        if let Some(name) = update.name {
            let _ = patch.insert("name".into(), name.into_field());
        }
        if let Some(organization_id) = update.organization_id {
            let _ = patch.insert("organizationId".into(), Value::from(organization_id));
        }
        if let Some(created_at) = update.created_at {
            let _ = patch.insert("createdAt".into(), Value::from(created_at));
        }
        if let Some(updated_at) = update.updated_at {
            let _ = patch.insert("updatedAt".into(), updated_at.into_field());
        } else if !self
            .organization_fields()?
            .team
            .fields()
            .contains_key("updatedAt")
        {
            let _ = patch.insert("updatedAt".into(), Value::from(Utc::now()));
        }
        let patch = self
            .prepare_record_patch(EntityRole::Team, patch, update.additional_fields)
            .await?;
        let team = {
            let state = self.lock()?;
            let mut team = state
                .teams
                .get_mut(&id)?
                .ok_or_else(|| AuthError::not_found("Team not found"))?;
            *team = patch.apply(team.clone())?;
            team.clone()
        };
        self.output_team(team).await
    }
    async fn delete_team(&self, id: &str) -> AuthResult<()> {
        let id = self.organization_query(EntityRole::Team, "id", Value::from(id))?;
        let public_id = Self::project_id(&id)?;
        let public_id = public_id.typed()?;
        let (organization_id, snapshot) = {
            let state = self.lock()?;
            let organization_id = state
                .teams
                .get(&id)?
                .ok_or_else(|| AuthError::not_found("Team not found"))?
                .organization_id;
            let invitation_org = self.organization_query(
                EntityRole::Invitation,
                "organizationId",
                organization_id.field_value(),
            )?;
            let pending: Vec<_> = state
                .invitations
                .snapshot()?
                .into_iter()
                .filter(|row| {
                    row.organization_id
                        .field_value()
                        .strict_equals(&invitation_org.field_value())
                        && row.is_pending()
                })
                .collect();
            (organization_id, pending)
        };
        let invitation_org = self.organization_query(
            EntityRole::Invitation,
            "organizationId",
            organization_id.field_value(),
        )?;
        let pending = self
            .output_records(EntityRole::Invitation, snapshot.clone())
            .await?;
        let mut updates = Vec::new();
        for invitation in pending {
            if invitation.expires_at.typed()?.milliseconds() <= Utc::now().timestamp_millis() as f64
            {
                continue;
            }
            let Some(ids) = invitation.team_id.typed()?.as_ref() else {
                continue;
            };
            let retained: Vec<_> = ids
                .split(',')
                .filter(|team_id| *team_id != public_id)
                .collect();
            if retained.len() == ids.split(',').count() {
                continue;
            }
            let patch = self
                .prepare_record_patch(
                    EntityRole::Invitation,
                    [(
                        "teamId".into(),
                        (!retained.is_empty())
                            .then(|| retained.join(","))
                            .into_field(),
                    )]
                    .into_iter()
                    .collect(),
                    FieldMap::new(),
                )
                .await?;
            let invitation_id = self.organization_primary_id(&invitation.id)?;
            let current = self
                .lock()?
                .invitations
                .get(&invitation_id)?
                .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
            let _ = self
                .output_invitation(patch.clone().apply(current)?)
                .await?;
            updates.push((invitation_id, patch));
        }
        let mut state = self.lock()?;
        let team = state
            .teams
            .get(&id)?
            .ok_or_else(|| AuthError::not_found("Team not found"))?;
        let pending: Vec<_> = state
            .invitations
            .snapshot()?
            .into_iter()
            .filter(|row| {
                row.organization_id
                    .field_value()
                    .strict_equals(&invitation_org.field_value())
                    && row.is_pending()
            })
            .collect();
        let unchanged = pending.len() == snapshot.len()
            && pending.iter().zip(&snapshot).all(|(a, b)| {
                a.id == b.id && a.team_id == b.team_id && a.expires_at == b.expires_at
            });
        if !team
            .organization_id
            .field_value()
            .strict_equals(&organization_id.field_value())
            || !unchanged
        {
            return Err(AuthError::conflict(
                "Team invitations changed while field transforms were pending",
            ));
        }
        let updates = updates
            .into_iter()
            .map(|(id, patch)| {
                let row = state
                    .invitations
                    .get(&id)?
                    .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
                Ok((id, patch.apply(row)?))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let _ = state.teams.remove(&id)?;
        state.team_members.retain(|member| member.team_id != id)?;
        for (id, invitation) in updates {
            let _ = state.invitations.replace(&id, invitation)?;
        }
        Ok(())
    }
    async fn list_organization_teams(&self, organization_id: &str) -> AuthResult<Vec<Team>> {
        self.list_organization_teams_value(&Value::from(organization_id))
            .await
    }
    async fn list_organization_teams_value(
        &self,
        organization_id: &Value,
    ) -> AuthResult<Vec<Team>> {
        let organization_id =
            self.organization_query(EntityRole::Team, "organizationId", organization_id.clone())?;
        let rows = self
            .lock()?
            .teams
            .snapshot()?
            .into_iter()
            .filter(|row| {
                row.organization_id
                    .field_value()
                    .strict_equals(&organization_id.field_value())
            })
            .collect();
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        self.output_records(EntityRole::Team, rows).await
    }
    async fn count_organization_teams(&self, organization_id: &str) -> AuthResult<u64> {
        self.count_organization_teams_value(&Value::from(organization_id))
            .await
    }
    async fn count_organization_teams_value(&self, organization_id: &Value) -> AuthResult<u64> {
        let organization_id =
            self.organization_query(EntityRole::Team, "organizationId", organization_id.clone())?;
        Ok(self
            .lock()?
            .teams
            .snapshot()?
            .iter()
            .filter(|row| {
                row.organization_id
                    .field_value()
                    .strict_equals(&organization_id.field_value())
            })
            .count() as u64)
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        if self.config.advanced.database.joins == Some(true) {
            return self.joined_user_teams(user_id).await;
        }
        let user_id = self.memory_primary_id_query(&Value::from(user_id))?;
        let rows = self
            .lock()?
            .team_members
            .snapshot()?
            .into_iter()
            .filter(|row| row.user_id.field_value().strict_equals(&user_id))
            .collect();
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        let mut teams = Vec::new();
        for member in rows {
            if let Some(team) = self
                .lock()?
                .teams
                .first_ref(|row| row.id == member.team_id)?
            {
                teams.push(team);
            }
        }
        self.output_record_refs(EntityRole::Team, teams).await
    }
    async fn get_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<TeamMember>> {
        self.get_team_member_value(&Value::from(team_id), &Value::from(user_id))
            .await
    }
    async fn get_team_member_value(
        &self,
        team_id: &Value,
        user_id: &Value,
    ) -> AuthResult<Option<TeamMember>> {
        let user_id = self.memory_primary_id_query(user_id)?;
        let team_id = self.organization_query(EntityRole::Team, "id", team_id.clone())?;
        self.lock()?
            .team_members
            .snapshot()?
            .iter()
            .find(|member| {
                member.team_id == team_id && member.user_id.field_value().strict_equals(&user_id)
            })
            .cloned()
            .map(Self::output_team_member)
            .transpose()
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<TeamMember>> {
        self.list_team_members_value(&Value::from(team_id)).await
    }
    async fn list_team_members_value(&self, team_id: &Value) -> AuthResult<Vec<TeamMember>> {
        let team_id = self.organization_query(EntityRole::Team, "id", team_id.clone())?;
        let rows = self
            .lock()?
            .team_members
            .snapshot()?
            .into_iter()
            .filter(|row| row.team_id == team_id)
            .collect();
        crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        )
        .into_iter()
        .map(Self::output_team_member)
        .collect()
    }
    async fn count_team_members(&self, team_id: &str) -> AuthResult<u64> {
        let team_id = self.organization_query(EntityRole::Team, "id", Value::from(team_id))?;
        Ok(self
            .lock()?
            .team_members
            .snapshot()?
            .iter()
            .filter(|row| row.team_id == team_id)
            .count() as u64)
    }
    async fn add_team_member(
        &self,
        team_id: &crate::SchemaValue<String>,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<Option<TeamMember>> {
        let user_id = self.memory_reference_id_input(Value::from(user_id))?;
        let team_id = self.organization_primary_id(team_id)?;
        let team_id = &team_id;
        let (team, actual, row_count) = {
            let state = self.lock()?;
            let team = state
                .teams
                .get(team_id)?
                .ok_or_else(|| AuthError::not_found("Team not found"))?;
            let members = state.team_members.snapshot()?;
            if let Some(member) = members
                .iter()
                .find(|member| member.team_id == *team_id && member.user_id == user_id)
            {
                return Self::output_team_member(member.clone()).map(Some);
            }
            (
                team,
                members
                    .iter()
                    .filter(|member| member.team_id == *team_id)
                    .count(),
                members.len(),
            )
        };
        let prepared = self.prepare_team_reservation(team, actual, maximum).await?;
        let reserved = prepared.reserved;
        let id = if reserved {
            self.generated_id("teamMember", None, row_count)?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default()
        } else {
            Default::default()
        };
        let mut state = self.lock()?;
        let team = state
            .teams
            .get(team_id)?
            .ok_or_else(|| AuthError::not_found("Team not found"))?;
        let members = state.team_members.snapshot()?;
        if let Some(member) = members
            .iter()
            .find(|member| member.team_id == *team_id && member.user_id == user_id)
        {
            return Self::output_team_member(member.clone()).map(Some);
        }
        let actual = members
            .iter()
            .filter(|member| member.team_id == *team_id)
            .count();
        if maximum.is_some_and(|maximum| actual >= maximum)
            && !prepared.is_current(&team, actual)?
        {
            return Ok(None);
        }
        let team = prepared.apply(team, actual)?;
        let _ = state.teams.replace(team_id, team)?;
        if !reserved {
            return Ok(None);
        }
        let mut member = TeamMember {
            id,
            team_id: team_id.to_owned(),
            user_id,
            created_at: Utc::now().into(),
        };
        if let Some(id) = self.next_serial_id(state.team_members.len()) {
            member.id = crate::SchemaValue::from_field(id);
        }
        state.team_members.push(member.clone());
        Self::output_team_member(member).map(Some)
    }
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<()> {
        let user_id = self.memory_primary_id_query(&Value::from(user_id))?;
        let team_id = self.organization_query(EntityRole::Team, "id", Value::from(team_id))?;
        let team_id = &team_id;
        let (team, members) = {
            let state = self.lock()?;
            (state.teams.get(team_id)?, state.team_members.snapshot()?)
        };
        let selected: Vec<_> = members
            .into_iter()
            .filter(|row| row.team_id == *team_id)
            .collect();
        let deleted = selected
            .iter()
            .filter(|row| row.user_id.field_value().strict_equals(&user_id))
            .count();
        let prepared = if let Some(team) = team {
            Some(
                self.prepare_team_release(team, selected.len(), deleted)
                    .await?,
            )
        } else {
            None
        };
        let mut state = self.lock()?;
        let current: Vec<_> = state
            .team_members
            .snapshot()?
            .into_iter()
            .filter(|row| row.team_id == *team_id)
            .collect();
        // Serial conversion can store NaN; an unchanged owner must not invalidate the prepared snapshot.
        let unchanged = current.len() == selected.len()
            && current.iter().zip(&selected).all(|(current, selected)| {
                current.id == selected.id
                    && current.team_id == selected.team_id
                    && current.created_at == selected.created_at
                    && current
                        .user_id
                        .field_value()
                        .same_value_zero(&selected.user_id.field_value())
            });
        if !unchanged {
            return Err(AuthError::conflict(
                "Team membership changed while field transforms were pending",
            ));
        }
        if let Some(prepared) = prepared {
            let team = state
                .teams
                .get(team_id)?
                .ok_or_else(|| AuthError::not_found("Team not found"))?;
            let team = prepared.apply(team, current.len())?;
            let _ = state.teams.replace(team_id, team)?;
        }
        state.team_members.retain(|member| {
            member.team_id != *team_id || !member.user_id.field_value().strict_equals(&user_id)
        })?;
        Ok(())
    }
}
#[async_trait]
impl OrganizationRoleStore for EphemeralStore {
    async fn create_organization_role(
        &self,
        mut input: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let organization_id = self.organization_query(
            EntityRole::OrganizationRole,
            "organizationId",
            input.organization_id.field_value(),
        )?;
        let role_name = self.organization_query(
            EntityRole::OrganizationRole,
            "role",
            Value::from(input.role.clone()),
        )?;
        let count = {
            let state = self.lock()?;
            if state.organization_roles.snapshot()?.iter().any(|role| {
                role.organization_id
                    .field_value()
                    .strict_equals(&organization_id.field_value())
                    && role
                        .role
                        .field_value()
                        .strict_equals(&role_name.field_value())
            }) {
                return Err(AuthError::bad_request("Role already exists"));
            }
            state.organization_roles.len()
        };
        let permission = crate::SchemaValue::from_field(
            input
                .permission
                .stringify()?
                .map(Value::String)
                .unwrap_or_default(),
        );
        let mut role = OrganizationRole {
            additional_fields: Default::default(),
            id: self
                .generated_id("organizationRole", None, count)?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            organization_id: input.organization_id,
            role: (input.role).into(),
            permission,
            created_at: (Utc::now()).into(),
            updated_at: (None).into(),
        };
        if let Some(value) = input.additional_fields.remove("organizationId") {
            role.organization_id = crate::SchemaValue::from_field(value);
        }
        if let Some(value) = input.additional_fields.remove("role") {
            role.role = crate::SchemaValue::from_field(value);
        }
        if let Some(value) = input.additional_fields.remove("permission") {
            role.permission = crate::SchemaValue::Dynamic(value);
        }
        if let Some(value) = input.additional_fields.remove("createdAt") {
            role.created_at = crate::SchemaValue::from_field(value);
        }
        if let Some(value) = input.additional_fields.remove("updatedAt") {
            role.updated_at = crate::SchemaValue::from_field(value);
        }
        let mut role: OrganizationRole = self
            .store_record(
                EntityRole::OrganizationRole,
                role,
                None,
                input.additional_fields,
            )
            .await?;
        {
            let mut state = self.lock()?;
            if state.organization_roles.snapshot()?.iter().any(|role| {
                role.organization_id
                    .field_value()
                    .strict_equals(&organization_id.field_value())
                    && role
                        .role
                        .field_value()
                        .strict_equals(&role_name.field_value())
            }) {
                return Err(AuthError::bad_request("Role already exists"));
            }
            if let Some(id) = self.next_serial_id(state.organization_roles.len()) {
                role.id = crate::SchemaValue::from_field(id);
            }
            state.organization_roles.push(role.clone());
        }
        self.output_organization_role(role).await
    }
    async fn get_organization_role(&self, id: &str) -> AuthResult<Option<OrganizationRole>> {
        let id = self.organization_query(EntityRole::OrganizationRole, "id", Value::from(id))?;
        let row = self.lock()?.organization_roles.get(&id)?;
        match row {
            Some(row) => self.output_organization_role(row).await.map(Some),
            None => Ok(None),
        }
    }
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>> {
        self.list_organization_roles_value(&Value::from(organization_id))
            .await
    }
    async fn list_organization_roles_value(
        &self,
        organization_id: &Value,
    ) -> AuthResult<Vec<OrganizationRole>> {
        let organization_id = self.organization_query(
            EntityRole::OrganizationRole,
            "organizationId",
            organization_id.clone(),
        )?;
        let rows = self
            .lock()?
            .organization_roles
            .snapshot()?
            .into_iter()
            .filter(|row| {
                row.organization_id
                    .field_value()
                    .strict_equals(&organization_id.field_value())
            })
            .collect();
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        self.output_records(EntityRole::OrganizationRole, rows)
            .await
    }
    async fn query_organization_roles(
        &self,
        organization_id: &str,
        names: &[String],
    ) -> AuthResult<Vec<OrganizationRole>> {
        self.query_organization_roles_value(&Value::from(organization_id), names)
            .await
    }
    async fn query_organization_roles_value(
        &self,
        organization_id: &Value,
        names: &[String],
    ) -> AuthResult<Vec<OrganizationRole>> {
        let names = names
            .iter()
            .map(|name| {
                self.organization_query(
                    EntityRole::OrganizationRole,
                    "role",
                    Value::from(name.as_str()),
                )
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let organization_id = self.organization_query(
            EntityRole::OrganizationRole,
            "organizationId",
            organization_id.clone(),
        )?;
        let rows = self
            .lock()?
            .organization_roles
            .snapshot()?
            .into_iter()
            .filter(|row| {
                row.organization_id
                    .field_value()
                    .strict_equals(&organization_id.field_value())
                    && names
                        .iter()
                        .any(|name| name.field_value().same_value_zero(&row.role.field_value()))
            })
            .collect();
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        self.output_records(EntityRole::OrganizationRole, rows)
            .await
    }
    async fn find_organization_role(
        &self,
        organization_id: &str,
        key: crate::store::OrganizationRoleKey<'_>,
    ) -> AuthResult<Option<OrganizationRole>> {
        self.find_organization_role_value(&Value::from(organization_id), key)
            .await
    }
    async fn find_organization_role_value(
        &self,
        organization_id: &Value,
        key: crate::store::OrganizationRoleKey<'_>,
    ) -> AuthResult<Option<OrganizationRole>> {
        let (key_field, key_value) = match key {
            crate::store::OrganizationRoleKey::Id(id) => ("id", Value::from(id)),
            crate::store::OrganizationRoleKey::Name(name) => ("role", Value::from(name)),
        };
        let key_value =
            self.organization_query(EntityRole::OrganizationRole, key_field, key_value)?;
        let organization_id = self.organization_query(
            EntityRole::OrganizationRole,
            "organizationId",
            organization_id.clone(),
        )?;
        let rows = self.lock()?.organization_roles.snapshot()?;
        let row = rows.into_iter().find(|row| {
            row.organization_id
                .field_value()
                .strict_equals(&organization_id.field_value())
                && match key {
                    crate::store::OrganizationRoleKey::Id(_) => row.id == key_value,
                    crate::store::OrganizationRoleKey::Name(_) => row
                        .role
                        .field_value()
                        .strict_equals(&key_value.field_value()),
                }
        });
        match row {
            Some(row) => self.output_organization_role(row).await.map(Some),
            None => Ok(None),
        }
    }
    async fn count_organization_roles(&self, organization_id: &str) -> AuthResult<u64> {
        self.count_organization_roles_value(&Value::from(organization_id))
            .await
    }
    async fn count_organization_roles_value(&self, organization_id: &Value) -> AuthResult<u64> {
        let organization_id = self.organization_query(
            EntityRole::OrganizationRole,
            "organizationId",
            organization_id.clone(),
        )?;
        Ok(self
            .lock()?
            .organization_roles
            .snapshot()?
            .iter()
            .filter(|row| {
                row.organization_id
                    .field_value()
                    .strict_equals(&organization_id.field_value())
            })
            .count() as u64)
    }
    async fn update_organization_role(
        &self,
        id: &str,
        mut update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let id = self.organization_query(EntityRole::OrganizationRole, "id", Value::from(id))?;
        let mut patch = FieldMap::new();
        if let Some(name) = update.role {
            let _ = patch.insert("role".into(), Value::from(name));
        }
        if let Some(permission) = update.permission {
            let value = permission
                .stringify()?
                .map(Value::String)
                .unwrap_or_default();
            let _ = patch.insert("permission".into(), value);
        }
        if !self
            .organization_fields()?
            .organization_role
            .fields()
            .contains_key("updatedAt")
        {
            let _ = patch.insert("updatedAt".into(), Value::from(Utc::now()));
        }
        for name in ["id", "organizationId", "role", "createdAt", "updatedAt"] {
            if let Some(value) = update.additional_fields.remove(name) {
                let _ = patch.entry(name.to_owned()).or_insert(value);
            }
        }
        let patch = self
            .prepare_record_patch(
                EntityRole::OrganizationRole,
                patch,
                update.additional_fields,
            )
            .await?;
        let role = {
            let mut state = self.lock()?;
            let role = state
                .organization_roles
                .get(&id)?
                .ok_or_else(|| AuthError::not_found("Role not found"))?;
            let role: OrganizationRole = patch.apply(role)?;
            let _ = state.organization_roles.replace(&id, role.clone())?;
            role
        };
        self.output_organization_role(role).await
    }
    async fn delete_organization_role(&self, id: &str) -> AuthResult<()> {
        let id = self.organization_query(EntityRole::OrganizationRole, "id", Value::from(id))?;
        let _ = self.lock()?.organization_roles.remove(&id)?;
        Ok(())
    }
}

#[tokio::test]
async fn memory_organization_deletion_cleans_teams_and_roles() {
    let store = EphemeralStore::new(test_config());
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
            permission: Value::from_json(serde_json::json!({"team":["create"]})).unwrap(),
        })
        .await
        .unwrap();
    store
        .delete_organization(org.id.typed().unwrap())
        .await
        .unwrap();
    assert!(
        store
            .get_team(team.id.typed().unwrap())
            .await
            .unwrap()
            .is_none()
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
            .get_organization_role(role.id.typed().unwrap())
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    for (failure_stage, asynchronous) in [
        ("expired", false),
        ("unassigned", false),
        ("updated", false),
        ("expired", true),
        ("unassigned", true),
        ("updated", true),
    ] {
        let store = EphemeralStore::new(test_config());
        let config = OrganizationFields {
            invitation: UserConfig {
                additional_fields: Some(
                    [(
                        "marker".into(),
                        UserFieldConfig {
                            required: Some(false),
                            default_value: Some(Value::from("created")),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
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
            let mut input = CreateInvitation::new(
                org.id.typed().unwrap(),
                "recipient@example.com",
                "member",
                "owner",
                expires.into(),
            );
            input.team_id = Some(team.id.typed().unwrap().clone());
            live.push(store.create_invitation(input).await.unwrap().id);
        }
        if failure_stage != "updated" {
            let mut input = CreateInvitation::new(
                org.id.typed().unwrap(),
                "other@example.com",
                "member",
                "owner",
                expires.into(),
            );
            if failure_stage == "expired" {
                input.team_id = Some(team.id.typed().unwrap().clone());
                input.expires_at = (Utc::now() - chrono::Duration::days(1)).into();
            }
            let _ = input
                .additional_fields
                .insert("marker".into(), Value::from("read-fail"));
            let _ = store.create_invitation(input).await.unwrap();
        }
        let updates = Arc::new(AtomicUsize::new(0));
        let count = updates.clone();
        let mut failing = config.clone();
        let marker = failing.invitation.fields_mut().get_mut("marker").unwrap();
        marker.on_update = Some(Arc::new(move || {
            Ok(Value::from(format!(
                "updated-{}",
                count.fetch_add(1, Ordering::SeqCst) + 1
            )))
        }));
        let output = |value| {
            if value == Value::from("read-fail") || value == Value::from("updated-2") {
                Err(AuthError::bad_request("invitation output failed"))
            } else {
                Ok(value)
            }
        };
        marker.transform.get_or_insert_default().output = Some(if asynchronous {
            UserFieldTransform::new_async(move |value| async move { output(value) })
        } else {
            UserFieldTransform::new(output)
        });
        store.configure_organization_fields(failing).unwrap();
        let error = store
            .delete_team(team.id.typed().unwrap())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("invitation output failed"));
        assert_eq!(
            updates.load(Ordering::SeqCst),
            if failure_stage == "updated" { 2 } else { 0 }
        );
        store.configure_organization_fields(config).unwrap();
        assert!(
            store
                .get_team(team.id.typed().unwrap())
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            store
                .list_team_members(team.id.typed().unwrap())
                .await
                .unwrap()
                .len(),
            1
        );
        for id in live {
            let row = store
                .get_invitation_by_id(id.typed().unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.team_id.typed().unwrap().as_deref(), team.id.as_str());
            assert_eq!(
                row.additional_fields.get("marker"),
                Some(&Value::from("created"))
            );
        }
    }
}
