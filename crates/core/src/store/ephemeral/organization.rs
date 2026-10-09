use super::*;
use better_auth_schema_registry::EntityRole;

mod invitations;
mod members;
#[cfg(test)]
mod query_tests;

#[async_trait]
impl OrganizationStore for EphemeralStore {
    async fn get_organization_details(
        &self,
        query: crate::store::OrganizationDetailsQuery<'_>,
    ) -> AuthResult<Option<crate::store::OrganizationDetails>> {
        self.read_organization_details(query).await
    }

    async fn insert_organization(&self, mut record: Organization) -> AuthResult<Organization> {
        let fields = std::mem::take(&mut record.additional_fields);
        let mut record = self
            .create_record(EntityRole::Organization, record, fields)
            .await?;
        {
            let mut state = self.lock()?;
            if let Some(id) = self.next_serial_id(state.organizations.len()) {
                let _ = record.insert("id".into(), id);
            }
            state.organizations.push(record.clone());
        }
        self.output_organization(record).await
    }
    async fn delete_organization_records(&self, id: &str) -> AuthResult<()> {
        let member_schema = self.field_config(EntityRole::Member)?;
        let invitation_schema = self.field_config(EntityRole::Invitation)?;
        let member_org =
            self.organization_query(EntityRole::Member, "organizationId", Value::from(id))?;
        let invitation_org =
            self.organization_query(EntityRole::Invitation, "organizationId", Value::from(id))?;
        let id = self.organization_query(EntityRole::Organization, "id", Value::from(id))?;
        self.lock()?.members.retain(|record| {
            !organization_value(record, &member_schema, "organizationId")
                .strict_equals(&member_org.field_value())
        })?;
        self.lock()?.invitations.retain(|record| {
            !organization_value(record, &invitation_schema, "organizationId")
                .strict_equals(&invitation_org.field_value())
        })?;
        let _ = self.lock()?.organizations.remove(&id)?;
        Ok(())
    }

    fn configure_organization_fields(
        &self,
        fields: crate::organization_fields::OrganizationFields,
    ) -> AuthResult<()> {
        let fields = fields.into_storage();
        *self
            .organization_fields
            .write()
            .map_err(|_| AuthError::internal("Ephemeral organization schema lock poisoned"))? =
            fields;
        Ok(())
    }
    async fn create_organization(&self, input: CreateOrganization) -> AuthResult<Organization> {
        let schema = self.field_config(EntityRole::Organization)?;
        let slug =
            self.organization_query(EntityRole::Organization, "slug", input.slug.field_value())?;
        {
            let state = self.lock()?;
            if state.organizations.snapshot()?.iter().any(|org| {
                organization_value(org, &schema, "slug").strict_equals(&slug.field_value())
            }) {
                return Err(AuthError::bad_request("Organization already exists"));
            }
        };
        let metadata = crate::organization_fields::metadata_input(
            (!input.metadata.is_undefined()).then(|| input.metadata.field_value()),
            true,
        )?
        .map(crate::SchemaValue::from_field)
        .unwrap_or_default();
        let org = Organization {
            additional_fields: Default::default(),
            id: input.id.map(crate::SchemaValue::Typed).unwrap_or_default(),
            name: input.name,
            slug: input.slug,
            logo: input.logo,
            metadata,
            created_at: (Utc::now()).into(),
        };
        let mut org = self
            .create_record(EntityRole::Organization, org, input.additional_fields)
            .await?;
        {
            let mut state = self.lock()?;
            if state.organizations.snapshot()?.iter().any(|org| {
                organization_value(org, &schema, "slug").strict_equals(&slug.field_value())
            }) {
                return Err(AuthError::bad_request("Organization already exists"));
            }
            if let Some(id) = self.next_serial_id(state.organizations.len()) {
                let _ = org.insert("id".into(), id);
            }
            state.organizations.push(org.clone());
        }
        self.output_organization(org).await
    }
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        let id = self.organization_query(EntityRole::Organization, "id", Value::from(id))?;
        let value = self.lock()?.organizations.get(&id)?;
        match value {
            Some(value) => self.output_organization(value).await.map(Some),
            None => Ok(None),
        }
    }
    async fn get_organization_by_id_value(&self, id: &Value) -> AuthResult<Option<Organization>> {
        let id = self.organization_query(EntityRole::Organization, "id", id.clone())?;
        let rows = self.lock()?.organizations.snapshot()?;
        match rows.into_iter().find(|row| organization_id(row) == id) {
            Some(value) => self.output_organization(value).await.map(Some),
            None => Ok(None),
        }
    }
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        let schema = self.field_config(EntityRole::Organization)?;
        let slug = self.organization_query(EntityRole::Organization, "slug", Value::from(slug))?;
        let rows = self.lock()?.organizations.snapshot()?;
        match rows
            .into_iter()
            .find(|row| organization_value(row, &schema, "slug").strict_equals(&slug.field_value()))
        {
            Some(value) => self.output_organization(value).await.map(Some),
            None => Ok(None),
        }
    }
    async fn get_organization_by_slug_value(
        &self,
        slug: &Value,
    ) -> AuthResult<Option<Organization>> {
        let schema = self.field_config(EntityRole::Organization)?;
        let slug = self.organization_query(EntityRole::Organization, "slug", slug.clone())?;
        let rows = self.lock()?.organizations.snapshot()?;
        for row in rows {
            if organization_value(&row, &schema, "slug").strict_equals(&slug.field_value()) {
                return self.output_organization(row).await.map(Some);
            }
        }
        Ok(None)
    }
    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        let ids = ids
            .iter()
            .map(|id| {
                self.organization_query(EntityRole::Organization, "id", Value::from(id.as_str()))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let rows = self
            .lock()?
            .organizations
            .snapshot()?
            .into_iter()
            .filter(|org| {
                ids.iter().any(|id| {
                    id.field_value()
                        .same_value_zero(&organization_id(org).field_value())
                })
            })
            .collect();
        self.output_organizations(rows).await
    }
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        self.update_organization_value(&Value::from(id), update)
            .await
    }
    async fn update_organization_value(
        &self,
        id: &Value,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let id = self.organization_query(EntityRole::Organization, "id", id.clone())?;
        let mut patch = FieldMap::new();
        if let Some(name) = update.name {
            let _ = patch.insert("name".into(), Value::from(name));
        }
        if let Some(slug) = update.slug {
            let _ = patch.insert("slug".into(), Value::from(slug));
        }
        if let Some(logo) = update.logo {
            let _ = patch.insert("logo".into(), logo.into_field());
        }
        if let Some(created_at) = update.created_at {
            let _ = patch.insert("createdAt".into(), Value::from(created_at));
        }
        if let Some(new_id) = update.id {
            let _ = patch.insert("id".into(), Value::from(new_id));
        }
        if let Some(value) = crate::organization_fields::metadata_input(update.metadata, false)? {
            let _ = patch.insert("metadata".into(), value);
        }
        let patch = self
            .prepare_record_patch(EntityRole::Organization, patch, update.additional_fields)
            .await?;
        let result = {
            let mut state = self.lock()?;
            let org = state
                .organizations
                .get(&id)?
                .ok_or_else(|| AuthError::not_found("Organization not found"))?;
            let result = patch.apply(org);
            let _ = state.organizations.replace(&id, result.clone())?;
            result
        };
        self.output_organization(result).await
    }
    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        let member_schema = self.field_config(EntityRole::Member)?;
        let invitation_schema = self.field_config(EntityRole::Invitation)?;
        let role_schema = self.field_config(EntityRole::OrganizationRole)?;
        let team_schema = self.field_config(EntityRole::Team)?;
        let team_member_schema = self.field_config(EntityRole::TeamMember)?;
        let member_org =
            self.organization_query(EntityRole::Member, "organizationId", Value::from(id))?;
        let invitation_org =
            self.organization_query(EntityRole::Invitation, "organizationId", Value::from(id))?;
        let role_org = self.organization_query(
            EntityRole::OrganizationRole,
            "organizationId",
            Value::from(id),
        )?;
        let team_org =
            self.organization_query(EntityRole::Team, "organizationId", Value::from(id))?;
        let id = self.organization_query(EntityRole::Organization, "id", Value::from(id))?;
        let mut state = self.lock()?;
        let _ = state.organizations.remove(&id)?;
        state.members.retain(|member| {
            !organization_value(member, &member_schema, "organizationId")
                .strict_equals(&member_org.field_value())
        })?;
        state.invitations.retain(|invitation| {
            !organization_value(invitation, &invitation_schema, "organizationId")
                .strict_equals(&invitation_org.field_value())
        })?;
        state.organization_roles.retain(|role| {
            !organization_value(role, &role_schema, "organizationId")
                .strict_equals(&role_org.field_value())
        })?;
        let team_ids: Vec<_> = state
            .teams
            .snapshot()?
            .iter()
            .filter(|team| {
                organization_value(team, &team_schema, "organizationId")
                    .strict_equals(&team_org.field_value())
            })
            .map(organization_id)
            .collect();
        state.team_members.retain(|member| {
            let team_id = organization_value(member, &team_member_schema, "teamId");
            !team_ids
                .iter()
                .any(|id| id.field_value().strict_equals(&team_id))
        })?;
        state.teams.retain(|team| {
            !organization_value(team, &team_schema, "organizationId")
                .strict_equals(&team_org.field_value())
        })?;
        Ok(())
    }
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        self.list_user_organizations_value(&user_id.into()).await
    }

    async fn list_user_organizations_value(
        &self,
        user_id: &Value,
    ) -> AuthResult<Vec<Organization>> {
        if self.config.advanced.database.joins == Some(true) {
            return self.joined_user_organizations(user_id).await;
        }
        let schema = self.field_config(EntityRole::Member)?;
        let user_id = self.organization_query(EntityRole::Member, "userId", user_id.clone())?;
        let selected = {
            let state = self.lock()?;
            state.members.select_refs(|row| {
                organization_value(row, &schema, "userId").strict_equals(&user_id.field_value())
            })?
        };
        let rows = crate::query::paginate_memory(
            selected,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        self.output_record_refs_batches_then(
            EntityRole::Member,
            rows,
            |ready: Vec<(usize, Member)>| async move {
                let mut indices = Vec::new();
                let mut organizations = Vec::new();
                for (index, member) in ready {
                    let owner = member.organization_id.field_value();
                    if owner.is_null() || owner.is_undefined() {
                        continue;
                    }
                    let id = self.organization_query(
                        EntityRole::Organization,
                        "id",
                        member.organization_id.field_value(),
                    )?;
                    if let Some(organization) = self
                        .lock()?
                        .organizations
                        .first_ref(|row| organization_id(row) == id)?
                    {
                        indices.push(index);
                        organizations.push(organization);
                    }
                }
                Ok(indices
                    .into_iter()
                    .zip(
                        self.output_record_refs(EntityRole::Organization, organizations)
                            .await?,
                    )
                    .collect())
            },
        )
        .await
    }
}
