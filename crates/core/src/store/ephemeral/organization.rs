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
        record.id = self
            .generated_id(
                "organization",
                if record.id.is_undefined() {
                    None
                } else {
                    Some(record.id.typed()?.clone())
                },
                self.lock()?.organizations.len(),
            )?
            .map(crate::SchemaValue::Typed)
            .unwrap_or_default();
        let fields = std::mem::take(&mut record.additional_fields);
        let mut record: Organization = self
            .store_record(EntityRole::Organization, record, None, fields)
            .await?;
        {
            let mut state = self.lock()?;
            if let Some(id) = self.next_serial_id(state.organizations.len()) {
                record.id = crate::SchemaValue::from_field(id);
            }
            state.organizations.push(record.clone());
        }
        self.output_organization(record).await
    }
    async fn delete_organization_records(&self, id: &str) -> AuthResult<()> {
        let member_org =
            self.organization_query(EntityRole::Member, "organizationId", Value::from(id))?;
        let invitation_org =
            self.organization_query(EntityRole::Invitation, "organizationId", Value::from(id))?;
        let id = self.organization_query(EntityRole::Organization, "id", Value::from(id))?;
        self.lock()?.members.retain(|record| {
            !record
                .organization_id
                .field_value()
                .strict_equals(&member_org.field_value())
        })?;
        self.lock()?.invitations.retain(|record| {
            !record
                .organization_id
                .field_value()
                .strict_equals(&invitation_org.field_value())
        })?;
        let _ = self.lock()?.organizations.remove(&id);
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
        let slug =
            self.organization_query(EntityRole::Organization, "slug", input.slug.field_value())?;
        let count = {
            let state = self.lock()?;
            if state
                .organizations
                .snapshot()?
                .iter()
                .any(|org| org.slug.field_value().strict_equals(&slug.field_value()))
            {
                return Err(AuthError::bad_request("Organization already exists"));
            }
            state.organizations.len()
        };
        let metadata = crate::organization_fields::metadata_input(
            (!input.metadata.is_undefined()).then(|| input.metadata.field_value()),
            true,
        )?
        .map(crate::SchemaValue::from_field)
        .unwrap_or_default();
        let org = Organization {
            additional_fields: Default::default(),
            id: self
                .generated_id("organization", input.id, count)?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            name: input.name,
            slug: input.slug,
            logo: input.logo,
            metadata,
            created_at: (Utc::now()).into(),
        };
        let mut org: Organization = self
            .store_record(EntityRole::Organization, org, None, input.additional_fields)
            .await?;
        {
            let mut state = self.lock()?;
            if state
                .organizations
                .snapshot()?
                .iter()
                .any(|org| org.slug.field_value().strict_equals(&slug.field_value()))
            {
                return Err(AuthError::bad_request("Organization already exists"));
            }
            if let Some(id) = self.next_serial_id(state.organizations.len()) {
                org.id = crate::SchemaValue::from_field(id);
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
        match rows.into_iter().find(|row| row.id == id) {
            Some(value) => self.output_organization(value).await.map(Some),
            None => Ok(None),
        }
    }
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        let slug = self.organization_query(EntityRole::Organization, "slug", Value::from(slug))?;
        let rows = self.lock()?.organizations.snapshot()?;
        match rows
            .into_iter()
            .find(|row| row.slug.field_value().strict_equals(&slug.field_value()))
        {
            Some(value) => self.output_organization(value).await.map(Some),
            None => Ok(None),
        }
    }
    async fn get_organization_by_slug_value(
        &self,
        slug: &Value,
    ) -> AuthResult<Option<Organization>> {
        let slug = self.organization_query(EntityRole::Organization, "slug", slug.clone())?;
        let rows = self.lock()?.organizations.snapshot()?;
        for row in rows {
            if row.slug.field_value().strict_equals(&slug.field_value()) {
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
                ids.iter()
                    .any(|id| id.field_value().same_value_zero(&org.id.field_value()))
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
            let result: Organization = patch.apply(org)?;
            let _ = state.organizations.replace(&id, result.clone())?;
            result
        };
        self.output_organization(result).await
    }
    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
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
            !member
                .organization_id
                .field_value()
                .strict_equals(&member_org.field_value())
        })?;
        state.invitations.retain(|invitation| {
            !invitation
                .organization_id
                .field_value()
                .strict_equals(&invitation_org.field_value())
        })?;
        state.organization_roles.retain(|role| {
            !role
                .organization_id
                .field_value()
                .strict_equals(&role_org.field_value())
        })?;
        let team_ids: Vec<_> = state
            .teams
            .snapshot()?
            .iter()
            .filter(|team| {
                team.organization_id
                    .field_value()
                    .strict_equals(&team_org.field_value())
            })
            .map(|team| team.id.clone())
            .collect();
        state
            .team_members
            .retain(|member| !team_ids.contains(&member.team_id))?;
        state.teams.retain(|team| {
            !team
                .organization_id
                .field_value()
                .strict_equals(&team_org.field_value())
        })?;
        Ok(())
    }
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        if self.config.advanced.database.joins == Some(true) {
            return self.joined_user_organizations(user_id).await;
        }
        let user_id =
            self.organization_query(EntityRole::Member, "userId", Value::from(user_id))?;
        let selected = {
            let state = self.lock()?;
            state.members.select_refs(|row| {
                row.user_id
                    .field_value()
                    .strict_equals(&user_id.field_value())
            })?
        };
        let rows = crate::query::paginate_memory(
            selected,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        self.output_record_refs_batches_then(EntityRole::Member, rows, |ready| async move {
            let mut indices = Vec::new();
            let mut organizations = Vec::new();
            for (index, member) in ready {
                let owner = member.organization_id.field_value();
                if owner.is_null() || owner.is_undefined() {
                    continue;
                }
                let id = self.organization_primary_id(&member.organization_id)?;
                if let Some(organization) =
                    self.lock()?.organizations.first_ref(|row| row.id == id)?
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
        })
        .await
    }
}
