use super::*;
use crate::{
    CreateOrganizationRole, CreateTeam, OrganizationRole, Team, TeamMember, UpdateOrganizationRole,
    UpdateTeam,
    store::{OrganizationRoleStore, TeamStore},
};
use better_auth_schema_registry::EntityRole;
#[async_trait]
impl TeamStore for EphemeralStore {
    async fn get_team_details_value(
        &self,
        team_id: &Value,
        organization_id: Option<&Value>,
        include_members: bool,
    ) -> AuthResult<Option<crate::store::TeamDetails>> {
        self.read_team_details(team_id, organization_id, include_members)
            .await
    }
    async fn create_team(&self, mut input: CreateTeam) -> AuthResult<Team> {
        let team = Team {
            field_order: Default::default(),
            additional_fields: [("memberCount".into(), Value::Number(0.0))]
                .into_iter()
                .collect(),
            id: input.id.map(crate::SchemaValue::Typed).unwrap_or_default(),
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
            .create_record(EntityRole::Team, team, input.additional_fields)
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
        let membership_schema = self.field_config(EntityRole::TeamMember)?;
        let invitation_schema = self.field_config(EntityRole::Invitation)?;
        let member_team = self.organization_query(EntityRole::TeamMember, "teamId", id.clone())?;
        let id = self.organization_query(EntityRole::Team, "id", id.clone())?;
        let (organization_id, public_id, selectors, rows, snapshot) = {
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
            let selectors =
                self.pending_invitation_selectors(&organization_id.field_value(), None)?;
            let rows = state
                .invitations
                .select_refs(|row| Self::matches_pending_invitation(row, &selectors))?;
            let snapshot = rows
                .iter()
                .map(|row| row.read(|row| Ok(row.clone())))
                .collect::<AuthResult<Vec<_>>>()?;
            (organization_id, public_id, selectors, rows, snapshot)
        };
        let pending = self.project_pending_invitation_rows(rows).await?;
        let mut updates = Vec::new();
        for invitation in pending {
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
            let invitation_id =
                self.organization_query(EntityRole::Invitation, "id", invitation.id.field_value())?;
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
            .filter(|row| Self::matches_pending_invitation(row, &selectors))
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
        state.team_members.retain(|member| {
            !organization_value(member, &membership_schema, "teamId")
                .strict_equals(&member_team.field_value())
        })?;
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
        let schema = self.field_config(EntityRole::TeamMember)?;
        let team_schema = self.field_config(EntityRole::Team)?;
        let user_id = self.organization_query(EntityRole::TeamMember, "userId", user_id.clone())?;
        let runtime = self.model_fields.organization_join_schema(&self.config);
        let join = crate::store::ResolvedJoin::resolve(
            (EntityRole::TeamMember, "teamMember", &schema),
            (EntityRole::Team, "team", &team_schema),
            &runtime,
            |_, _| false,
        )?;
        let rows = self.lock()?.team_members.select_refs(|row| {
            organization_value(row, &schema, "userId").strict_equals(&user_id.field_value())
        })?;
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        let projected = self
            .output_record_refs_batches_then(
                EntityRole::TeamMember,
                rows,
                |ready: Vec<(usize, FieldMap)>| {
                    let join = &join;
                    let schema = &schema;
                    let team_schema = &team_schema;
                    async move {
                        let mut groups = Vec::new();
                        let mut teams = Vec::new();
                        for (index, member) in ready {
                            let from = join.fallback_from(
                                (EntityRole::TeamMember, "teamMember", schema),
                                &self.model_fields,
                            )?;
                            let owner = member.get(&from).cloned().unwrap_or_default();
                            let rows = if owner.is_null() || owner.is_undefined() {
                                Vec::new()
                            } else {
                                let (logical, physical) = join.fallback_target(
                                    (EntityRole::Team, "team", team_schema),
                                    &self.model_fields,
                                )?;
                                let value = if logical == "id" {
                                    self.memory_primary_id_query(&owner)?
                                } else {
                                    self.memory_field_query(team_schema, &logical, owner)?
                                };
                                let rows = self.lock()?.teams.select_refs(|row| {
                                    row.get(&physical)
                                        .unwrap_or(&Value::Undefined)
                                        .strict_equals(&value)
                                })?;
                                crate::query::paginate_memory(
                                    rows,
                                    Some(if join.many {
                                        self.config.advanced.database.find_many_limit()
                                    } else {
                                        1.0
                                    }),
                                    None,
                                )
                            };
                            groups.push(index);
                            teams.push(rows);
                        }
                        let pages = teams.iter().map(Vec::as_slice).collect();
                        let output = self.output_record_pages(EntityRole::Team, pages).await?;
                        Ok(groups.into_iter().zip(output).collect())
                    }
                },
            )
            .await?;
        projected
            .into_iter()
            .map(|rows| Team::from_membership_join(rows, join.many))
            .collect()
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
        let selectors = self.team_member_selectors(team_id, Some(user_id))?;
        let row = self
            .lock()?
            .team_members
            .first_ref(|row| Self::matches_team_member(row, &selectors))?;
        Ok(self
            .output_record_refs(EntityRole::TeamMember, row.into_iter().collect())
            .await?
            .into_iter()
            .next())
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<TeamMember>> {
        self.list_team_members_value(&Value::from(team_id)).await
    }
    async fn list_team_members_value(&self, team_id: &Value) -> AuthResult<Vec<TeamMember>> {
        let selectors = self.team_member_selectors(team_id, None)?;
        let rows = self
            .lock()?
            .team_members
            .select_refs(|row| Self::matches_team_member(row, &selectors))?;
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        self.output_record_refs(EntityRole::TeamMember, rows).await
    }
    async fn count_team_members(&self, team_id: &str) -> AuthResult<u64> {
        self.count_team_members_value(&team_id.into()).await
    }
    async fn count_team_members_value(&self, team_id: &Value) -> AuthResult<u64> {
        let selectors = self.team_member_selectors(team_id, None)?;
        Ok(self
            .lock()?
            .team_members
            .snapshot()?
            .iter()
            .filter(|row| Self::matches_team_member(row, &selectors))
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
        let key = crate::organization_fields::team_membership_key_values(team_id, user_id)?;
        if let Some(member) = self
            .find_team_member_by_key_or_pair(team_id, user_id, &key)
            .await?
        {
            return Ok(Some(member));
        }
        let id = self.organization_query(EntityRole::Team, "id", team_id.clone())?;
        let selectors = self.team_member_selectors(team_id, None)?;
        let (team, actual) = {
            let state = self.lock()?;
            let team = state
                .teams
                .first_ref(|row| organization_id(row) == id)?
                .ok_or_else(|| AuthError::not_found("Team not found"))?;
            let members = state.team_members.snapshot()?;
            (
                team,
                members
                    .iter()
                    .filter(|member| Self::matches_team_member(member, &selectors))
                    .count(),
            )
        };
        let mut prepared = self.prepare_team_reservation(team, actual, maximum).await?;
        let staged = if prepared.reserved {
            let staged = match self.stage_team_member(team_id, user_id, &key).await {
                Ok(staged) => staged,
                Err(error) => {
                    if maximum.is_some() {
                        self.release_prepared_team_seat(&mut prepared).await?;
                    }
                    return Err(error);
                }
            };
            if maximum.is_some() && !staged.created {
                self.release_prepared_team_seat(&mut prepared).await?;
            } else if maximum.is_none() && staged.created {
                self.increment_prepared_team_seat(&mut prepared).await?;
            }
            Some(staged)
        } else {
            None
        };
        let existing = {
            let mut state = self.lock()?;
            if let Some(row) = self.team_member_by_key_or_pair(&state, team_id, user_id, &key)? {
                Some(row)
            } else {
                let actual = state
                    .team_members
                    .snapshot()?
                    .iter()
                    .filter(|row| Self::matches_team_member(row, &selectors))
                    .count();
                if maximum.is_some_and(|maximum| actual >= maximum)
                    && !prepared.is_current(&state.teams, actual)?
                {
                    return Ok(None);
                }
                if let Some(staged) = &staged
                    && matches!(
                        self.config.advanced.database.generate_id(),
                        crate::id::IdGeneration::Serial
                    )
                    && state.team_members.len() != staged.base.len()
                {
                    return Err(AuthError::conflict(
                        "Team membership allocation changed while field transforms were pending",
                    ));
                }
                let (source, fields) = prepared.apply(&state.teams, actual)?;
                if let Some(staged) = &staged {
                    state
                        .team_members
                        .merge(&staged.base, staged.working.clone())?;
                }
                source.write(|row| {
                    *row = fields;
                    Ok(())
                })?;
                None
            }
        };
        if let Some(existing) = existing {
            return Ok(self
                .output_record_refs(EntityRole::TeamMember, vec![existing])
                .await?
                .into_iter()
                .next());
        }
        Ok(staged.map(|staged| staged.member))
    }
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<()> {
        self.remove_team_member_value(&team_id.into(), &user_id.into())
            .await
    }
    async fn remove_team_member_value(&self, team_id: &Value, user_id: &Value) -> AuthResult<()> {
        let selected_by_pair = self.team_member_selectors(team_id, Some(user_id))?;
        let deleted = {
            let mut state = self.lock()?;
            let before = state.team_members.len();
            state
                .team_members
                .retain(|member| !Self::matches_team_member(member, &selected_by_pair))?;
            before - state.team_members.len()
        };
        self.release_team_seats(team_id, deleted).await
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
        {
            let state = self.lock()?;
            if state.organization_roles.snapshot()?.iter().any(|role| {
                organization_value(role, &schema, "organizationId")
                    .strict_equals(&organization_id.field_value())
                    && organization_value(role, &schema, "role")
                        .strict_equals(&role_name.field_value())
            }) {
                return Err(AuthError::bad_request("Role already exists"));
            }
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
            id: Default::default(),
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
            .create_record(EntityRole::OrganizationRole, role, input.additional_fields)
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
        let names = self
            .organization_query(
                EntityRole::OrganizationRole,
                "role",
                names
                    .iter()
                    .map(|name| Value::from(name.as_str()))
                    .collect::<Vec<_>>()
                    .into(),
            )?
            .field_value();
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
            .try_fold(Vec::new(), |mut selected, row| -> AuthResult<_> {
                // Memory validates the transformed IN operand only when a stored row is evaluated.
                let names = names
                    .as_array()
                    .ok_or_else(|| AuthError::internal("Value must be an array"))?;
                if organization_value(&row, &schema, "organizationId")
                    .strict_equals(&organization_id.field_value())
                    && names.iter().any(|name| {
                        name.same_value_zero(&organization_value(&row, &schema, "role"))
                    })
                {
                    selected.push(row);
                }
                Ok(selected)
            })?;
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

#[cfg(test)]
mod tests;
