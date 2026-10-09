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
                .unwrap_or_else(|| {
                    input
                        .updated_at
                        .map(|value| Some(value).into())
                        .unwrap_or_default()
                }),
        };
        let mut team = self
            .store_record(EntityRole::Team, team, None, input.additional_fields)
            .await?;
        {
            let mut state = self.lock()?;
            if let Some(id) = self.next_serial_id(state.teams.len()) {
                let _ = team.insert("id".into(), id);
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
        match rows.into_iter().find(|row| organization_id(row) == id) {
            Some(row) => self.output_team(row).await.map(Some),
            None => Ok(None),
        }
    }
    async fn update_team(&self, id: &str, update: UpdateTeam) -> AuthResult<Team> {
        self.update_team_value(&id.into(), update).await
    }
    async fn update_team_value(&self, id: &Value, update: UpdateTeam) -> AuthResult<Team> {
        let id = self.organization_query(EntityRole::Team, "id", id.clone())?;
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
            *team = patch.apply(team.clone());
            team.clone()
        };
        self.output_team(team).await
    }
    async fn delete_team(&self, id: &str) -> AuthResult<()> {
        self.delete_team_value(&id.into()).await
    }
    async fn delete_team_value(&self, id: &Value) -> AuthResult<()> {
        let team_schema = self.field_config(EntityRole::Team)?;
        let invitation_schema = self.field_config(EntityRole::Invitation)?;
        let id = self.organization_query(EntityRole::Team, "id", id.clone())?;
        let (organization_id, public_id, snapshot) = {
            let state = self.lock()?;
            let team = state
                .teams
                .get(&id)?
                .ok_or_else(|| AuthError::not_found("Team not found"))?;
            let organization_id = crate::SchemaValue::<String>::from_field(organization_value(
                &team,
                &team_schema,
                "organizationId",
            ));
            let public_id = Self::project_id(&super::organization_rows::id(&team))?.field_value();
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
                    organization_value(row, &invitation_schema, "organizationId")
                        .strict_equals(&invitation_org.field_value())
                        && organization_value(row, &invitation_schema, "status")
                            .strict_equals(&"pending".into())
                })
                .collect();
            (organization_id, public_id, pending)
        };
        let invitation_org = self.organization_query(
            EntityRole::Invitation,
            "organizationId",
            organization_id.field_value(),
        )?;
        let pending = self
            .output_records::<Invitation>(EntityRole::Invitation, snapshot.clone())
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
                .filter(|team_id| !Value::from(*team_id).strict_equals(&public_id))
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
            let _ = self.output_invitation(patch.clone().apply(current)).await?;
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
                organization_value(row, &invitation_schema, "organizationId")
                    .strict_equals(&invitation_org.field_value())
                    && organization_value(row, &invitation_schema, "status")
                        .strict_equals(&"pending".into())
            })
            .collect();
        let unchanged = pending.len() == snapshot.len()
            && pending.iter().zip(&snapshot).all(|(a, b)| {
                super::organization_rows::id(a) == super::organization_rows::id(b)
                    && ["teamId", "expiresAt"].iter().all(|name| {
                        organization_value(a, &invitation_schema, name)
                            == organization_value(b, &invitation_schema, name)
                    })
            });
        if !organization_value(&team, &team_schema, "organizationId")
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
                Ok((id, patch.apply(row)))
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
        let schema = self.field_config(EntityRole::Team)?;
        let organization_id =
            self.organization_query(EntityRole::Team, "organizationId", organization_id.clone())?;
        let rows = self
            .lock()?
            .teams
            .snapshot()?
            .into_iter()
            .filter(|row| {
                organization_value(row, &schema, "organizationId")
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
        let schema = self.field_config(EntityRole::Team)?;
        let organization_id =
            self.organization_query(EntityRole::Team, "organizationId", organization_id.clone())?;
        Ok(self
            .lock()?
            .teams
            .snapshot()?
            .iter()
            .filter(|row| {
                organization_value(row, &schema, "organizationId")
                    .strict_equals(&organization_id.field_value())
            })
            .count() as u64)
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        self.list_user_teams_value(&user_id.into()).await
    }
    async fn list_user_teams_value(&self, user_id: &Value) -> AuthResult<Vec<Team>> {
        if self.config.advanced.database.joins == Some(true) {
            return self.joined_user_teams(user_id).await;
        }
        let user_id = self.memory_primary_id_query(user_id)?;
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
                .first_ref(|row| organization_id(row) == member.team_id)?
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
        self.count_team_members_value(&team_id.into()).await
    }
    async fn count_team_members_value(&self, team_id: &Value) -> AuthResult<u64> {
        let team_id = self.organization_query(EntityRole::Team, "id", team_id.clone())?;
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
        self.add_team_member_value(&team_id.field_value(), &user_id.into(), maximum)
            .await
    }
    async fn add_team_member_value(
        &self,
        team_id: &Value,
        user_id: &Value,
        maximum: Option<usize>,
    ) -> AuthResult<Option<TeamMember>> {
        let user_id = self.memory_reference_id_input(user_id.clone())?;
        let team_id = self.organization_query(EntityRole::Team, "id", team_id.clone())?;
        let team_id = &team_id;
        let (team, actual, row_count) = {
            let state = self.lock()?;
            let team = state
                .teams
                .first_ref(|row| organization_id(row) == *team_id)?
                .ok_or_else(|| AuthError::not_found("Team not found"))?;
            let members = state.team_members.snapshot()?;
            if let Some(member) = members.iter().find(|member| {
                member
                    .team_id
                    .field_value()
                    .strict_equals(&team_id.field_value())
                    && member
                        .user_id
                        .field_value()
                        .strict_equals(&user_id.field_value())
            }) {
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
        let members = state.team_members.snapshot()?;
        if let Some(member) = members.iter().find(|member| {
            member
                .team_id
                .field_value()
                .strict_equals(&team_id.field_value())
                && member
                    .user_id
                    .field_value()
                    .strict_equals(&user_id.field_value())
        }) {
            return Self::output_team_member(member.clone()).map(Some);
        }
        let actual = members
            .iter()
            .filter(|member| member.team_id == *team_id)
            .count();
        if maximum.is_some_and(|maximum| actual >= maximum)
            && !prepared.is_current(&state.teams, actual)?
        {
            return Ok(None);
        }
        let (source, fields) = prepared.apply(&state.teams, actual)?;
        source.write(|row| {
            *row = fields;
            Ok(())
        })?;
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
        self.remove_team_member_value(&team_id.into(), &user_id.into())
            .await
    }
    async fn remove_team_member_value(&self, team_id: &Value, user_id: &Value) -> AuthResult<()> {
        let user_id = self.memory_primary_id_query(user_id)?;
        let team_id = self.organization_query(EntityRole::Team, "id", team_id.clone())?;
        let team_id = &team_id;
        let (team, members) = {
            let state = self.lock()?;
            (
                state
                    .teams
                    .first_ref(|row| organization_id(row) == *team_id)?,
                state.team_members.snapshot()?,
            )
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
            let (source, fields) = prepared.apply(&state.teams, current.len())?;
            source.write(|row| {
                *row = fields;
                Ok(())
            })?;
        }
        state.team_members.retain(|member| {
            member.team_id != *team_id || !member.user_id.field_value().strict_equals(&user_id)
        })?;
        Ok(())
    }
}
impl EphemeralStore {
    fn organization_role_selectors(
        &self,
        selectors: &FieldMap,
    ) -> AuthResult<Vec<(String, Value)>> {
        let schema = self.field_config(EntityRole::OrganizationRole)?;
        selectors
            .iter()
            .map(|(name, value)| {
                let key = if name == "id" {
                    name.clone()
                } else if schema.fields().contains_key(name) {
                    schema.record_storage_key(name).to_owned()
                } else {
                    return Err(AuthError::config(format!(
                        "Unknown organization role field {name}"
                    )));
                };
                Ok((
                    key,
                    self.organization_query(EntityRole::OrganizationRole, name, value.clone())?
                        .field_value(),
                ))
            })
            .collect()
    }

    fn organization_role_matches(
        fields: &FieldMap,
        selectors: &[(String, Value)],
    ) -> AuthResult<bool> {
        Ok(selectors.iter().all(|(name, expected)| {
            fields
                .get(name)
                .unwrap_or(&Value::Undefined)
                .strict_equals(expected)
        }))
    }

    async fn organization_role_patch(
        &self,
        mut update: UpdateOrganizationRole,
    ) -> AuthResult<super::fields::PreparedOrganizationFields> {
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
        for field in better_auth_schema_registry::core_fields(EntityRole::OrganizationRole) {
            let name = better_auth_schema_registry::canonical_field_name(
                EntityRole::OrganizationRole,
                field.name,
            );
            if let Some(value) = update.additional_fields.remove(&name) {
                let _ = patch.entry(name).or_insert(value);
            }
        }
        self.prepare_record_patch(
            EntityRole::OrganizationRole,
            patch,
            update.additional_fields,
        )
        .await
    }
}

#[async_trait]
impl OrganizationRoleStore for EphemeralStore {
    async fn create_organization_role(
        &self,
        mut input: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let schema = self.field_config(EntityRole::OrganizationRole)?;
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
                organization_value(role, &schema, "organizationId")
                    .strict_equals(&organization_id.field_value())
                    && organization_value(role, &schema, "role")
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
            updated_at: Default::default(),
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
        let mut role = self
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
                organization_value(role, &schema, "organizationId")
                    .strict_equals(&organization_id.field_value())
                    && organization_value(role, &schema, "role")
                        .strict_equals(&role_name.field_value())
            }) {
                return Err(AuthError::bad_request("Role already exists"));
            }
            if let Some(id) = self.next_serial_id(state.organization_roles.len()) {
                let _ = role.insert("id".into(), id);
            }
            state.organization_roles.push(role.clone());
        }
        self.output_organization_role(role).await
    }
    async fn get_organization_role(&self, id: &str) -> AuthResult<Option<OrganizationRole>> {
        self.find_organization_role_by_fields(&[("id".into(), Value::from(id))].into())
            .await
    }
    async fn find_organization_role_by_fields(
        &self,
        selectors: &FieldMap,
    ) -> AuthResult<Option<OrganizationRole>> {
        let selectors = self.organization_role_selectors(selectors)?;
        let row = self
            .lock()?
            .organization_roles
            .try_select_refs(|row| Self::organization_role_matches(row, &selectors))?
            .into_iter()
            .next();
        match row {
            Some(row) => Ok(self
                .output_record_refs(EntityRole::OrganizationRole, vec![row])
                .await?
                .pop()),
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
        let schema = self.field_config(EntityRole::OrganizationRole)?;
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
                organization_value(row, &schema, "organizationId")
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
        let schema = self.field_config(EntityRole::OrganizationRole)?;
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
                organization_value(row, &schema, "organizationId")
                    .strict_equals(&organization_id.field_value())
                    && names.iter().any(|name| {
                        name.field_value()
                            .same_value_zero(&organization_value(row, &schema, "role"))
                    })
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
        self.find_organization_role_by_fields(
            &[
                ("organizationId".into(), organization_id.clone()),
                (key_field.into(), key_value),
            ]
            .into(),
        )
        .await
    }
    async fn count_organization_roles(&self, organization_id: &str) -> AuthResult<u64> {
        self.count_organization_roles_value(&Value::from(organization_id))
            .await
    }
    async fn count_organization_roles_value(&self, organization_id: &Value) -> AuthResult<u64> {
        let schema = self.field_config(EntityRole::OrganizationRole)?;
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
                organization_value(row, &schema, "organizationId")
                    .strict_equals(&organization_id.field_value())
            })
            .count() as u64)
    }
    async fn update_organization_role(
        &self,
        id: &str,
        update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        self.update_organization_role_value(&id.into(), update)
            .await
    }
    async fn update_organization_role_value(
        &self,
        id: &Value,
        update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let selectors = self.organization_role_selectors(&[("id".into(), id.clone())].into())?;
        let patch = self.organization_role_patch(update).await?;
        let role = self
            .lock()?
            .organization_roles
            .try_select_refs(|row| Self::organization_role_matches(row, &selectors))?
            .into_iter()
            .next()
            .ok_or_else(|| AuthError::not_found("Role not found"))?;
        role.write(|row| {
            *row = patch.apply(row.clone());
            Ok(())
        })?;
        self.output_record_refs(EntityRole::OrganizationRole, vec![role])
            .await?
            .pop()
            .ok_or_else(|| AuthError::not_found("Role not found"))
    }
    async fn update_organization_roles(
        &self,
        selectors: &FieldMap,
        update: UpdateOrganizationRole,
    ) -> AuthResult<u64> {
        let selectors = self.organization_role_selectors(selectors)?;
        let patch = self.organization_role_patch(update).await?;
        let mut count = 0;
        self.lock()?.organization_roles.update_each(|row| {
            if Self::organization_role_matches(row, &selectors)? {
                *row = patch.clone().apply(row.clone());
                count += 1;
            }
            Ok(())
        })?;
        Ok(count)
    }
    async fn delete_organization_role(&self, id: &str) -> AuthResult<()> {
        self.delete_organization_role_by_fields(&[("id".into(), Value::from(id))].into())
            .await
    }
    async fn delete_organization_role_by_fields(&self, selectors: &FieldMap) -> AuthResult<()> {
        let selectors = self.organization_role_selectors(selectors)?;
        self.lock()?.organization_roles.try_retain(|row| {
            Self::organization_role_matches(row, &selectors).map(|matches| !matches)
        })
    }
}

#[tokio::test]
async fn organization_role_batch_matches_native_scope_and_does_not_project_writes() {
    use crate::user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldType};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let outputs = Arc::new(AtomicUsize::new(0));
    let counter = outputs.clone();
    let store = EphemeralStore::new(test_config());
    store
        .configure_organization_fields(crate::organization_fields::OrganizationFields {
            organization_role: UserConfig {
                additional_fields: Some(
                    [
                        (
                            "organizationId".into(),
                            UserFieldConfig {
                                field_type: UserFieldType::Number,
                                ..Default::default()
                            },
                        ),
                        (
                            "permission".into(),
                            UserFieldConfig {
                                transform: Some(FieldTransforms {
                                    input: None,
                                    output: Some(UserFieldTransform::new(move |value| {
                                        counter.fetch_add(1, Ordering::SeqCst);
                                        Ok(value)
                                    })),
                                }),
                                ..Default::default()
                            },
                        ),
                    ]
                    .into(),
                ),
            },
            ..Default::default()
        })
        .unwrap();
    let _ = store
        .create_organization_role(CreateOrganizationRole {
            organization_id: crate::SchemaValue::from_field(Value::Number(7.0)),
            role: "editor".into(),
            permission: FieldMap::new().into(),
            additional_fields: FieldMap::new(),
        })
        .await
        .unwrap();
    {
        let mut state = store.lock().unwrap();
        let mut duplicate = state.organization_roles.snapshot().unwrap().pop().unwrap();
        let _ = duplicate.insert("id".into(), "second".into());
        state.organization_roles.push(duplicate.clone());
        let _ = duplicate.insert("id".into(), "other-tenant".into());
        let _ = duplicate.insert("organizationId".into(), Value::Number(8.0));
        state.organization_roles.push(duplicate);
    }
    outputs.store(0, Ordering::SeqCst);
    let selectors: FieldMap = [
        ("organizationId".into(), Value::Number(7.0)),
        ("role".into(), "editor".into()),
    ]
    .into();
    assert_eq!(
        store
            .update_organization_roles(
                &selectors,
                UpdateOrganizationRole {
                    role: Some("writer".into()),
                    ..Default::default()
                }
            )
            .await
            .unwrap(),
        2
    );
    assert_eq!(outputs.load(Ordering::SeqCst), 0);
    let rows = store.lock().unwrap().organization_roles.snapshot().unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| (row["organizationId"].clone(), row["role"].clone()))
            .collect::<Vec<_>>(),
        vec![
            (Value::Number(7.0), "writer".into()),
            (Value::Number(7.0), "writer".into()),
            (Value::Number(8.0), "editor".into()),
        ]
    );
    assert!(
        store
            .find_organization_role_by_fields(&selectors)
            .await
            .unwrap()
            .is_none()
    );
    let selectors: FieldMap = [
        ("organizationId".into(), Value::Number(7.0)),
        ("role".into(), "writer".into()),
    ]
    .into();
    store
        .delete_organization_role_by_fields(&selectors)
        .await
        .unwrap();
    assert_eq!(
        store
            .count_organization_roles_value(&Value::Number(7.0))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .count_organization_roles_value(&Value::Number(8.0))
            .await
            .unwrap(),
        1
    );
    assert_eq!(outputs.load(Ordering::SeqCst), 0);
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
