use super::*;
use crate::store::schema::resolve_field_name;
#[cfg(test)]
use crate::user_fields::{FieldTransforms, UserFieldTransform};
use better_auth_schema_registry::EntityRole;

fn compare_member_values(left: &Value, right: &Value) -> AuthResult<std::cmp::Ordering> {
    match (left, right) {
        (Value::Null | Value::Undefined, Value::Null | Value::Undefined) => {
            Ok(std::cmp::Ordering::Equal)
        }
        (Value::Null | Value::Undefined, _) => Ok(std::cmp::Ordering::Less),
        (_, Value::Null | Value::Undefined) => Ok(std::cmp::Ordering::Greater),
        _ => Ok(crate::query::field_compare(left, right)?.unwrap_or(std::cmp::Ordering::Equal)),
    }
}

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
            self.assign_insert_serial_id(&mut record.id, state.organizations.len());
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
            self.assign_insert_serial_id(&mut org.id, state.organizations.len());
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
        let id = self.organization_query(EntityRole::Organization, "id", Value::from(id))?;
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
            state
                .members
                .select_refs(|row| {
                    row.user_id
                        .field_value()
                        .strict_equals(&user_id.field_value())
                })?
                .into_iter()
                .map(|row| {
                    let id = row.read(|row| self.organization_primary_id(&row.organization_id))?;
                    Ok((row, id))
                })
                .collect::<AuthResult<Vec<_>>>()?
        };
        let (rows, ids): (Vec<_>, Vec<_>) = crate::query::paginate_memory(
            selected,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        )
        .into_iter()
        .unzip();
        self.output_record_refs_batches_then(EntityRole::Member, rows, |ready| {
            let ids = &ids;
            async move {
                let mut indices = Vec::new();
                let mut organizations = Vec::new();
                for (index, _) in ready {
                    let id = ids.get(index).ok_or_else(|| {
                        AuthError::internal("Member projection lost its stored join index")
                    })?;
                    if let Some(organization) =
                        self.lock()?.organizations.first_ref(|row| row.id == *id)?
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
            }
        })
        .await
    }
}
#[async_trait]
impl MemberStore for EphemeralStore {
    async fn get_member_with_user(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<crate::store::MemberUser>> {
        let organization_id = self.organization_query(
            EntityRole::Member,
            "organizationId",
            Value::from(organization_id),
        )?;
        let user_id =
            self.organization_query(EntityRole::Member, "userId", Value::from(user_id))?;
        self.read_member_user(
            |row| {
                Ok(row
                    .organization_id
                    .field_value()
                    .strict_equals(&organization_id.field_value())
                    && row
                        .user_id
                        .field_value()
                        .strict_equals(&user_id.field_value()))
            },
            false,
        )
        .await
    }
    async fn get_member_with_user_value(
        &self,
        organization_id: &Value,
        user_id: &Value,
    ) -> AuthResult<Option<crate::store::MemberUser>> {
        let organization_id = self.organization_query(
            EntityRole::Member,
            "organizationId",
            organization_id.clone(),
        )?;
        let user_id = self.organization_query(EntityRole::Member, "userId", user_id.clone())?;
        self.read_member_user(
            |row| {
                Ok(row
                    .organization_id
                    .field_value()
                    .strict_equals(&organization_id.field_value())
                    && row
                        .user_id
                        .field_value()
                        .strict_equals(&user_id.field_value()))
            },
            false,
        )
        .await
    }
    async fn get_member_by_id_with_user(
        &self,
        id: &str,
    ) -> AuthResult<Option<crate::store::MemberUser>> {
        let id = self.organization_query(EntityRole::Member, "id", Value::from(id))?;
        self.read_member_user(|row| Ok(row.id == id), true).await
    }

    async fn insert_member(&self, mut record: Member) -> AuthResult<Member> {
        record.id = self
            .generated_id(
                "member",
                if record.id.is_undefined() {
                    None
                } else {
                    Some(record.id.typed()?.clone())
                },
                self.lock()?.members.len(),
            )?
            .map(crate::SchemaValue::Typed)
            .unwrap_or_default();
        let fields = std::mem::take(&mut record.additional_fields);
        let mut record: Member = self
            .store_record(EntityRole::Member, record, None, fields)
            .await?;
        {
            let mut state = self.lock()?;
            self.assign_insert_serial_id(&mut record.id, state.members.len());
            state.members.push(record.clone());
        }
        self.output_member(record).await
    }

    async fn create_member(&self, input: CreateMember) -> AuthResult<Member> {
        let count = self.lock()?.members.len();
        let member = Member {
            additional_fields: Default::default(),
            id: self
                .generated_id("member", None, count)?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            organization_id: input.organization_id,
            user_id: input.user_id,
            role: input.role,
            created_at: (Utc::now()).into(),
        };
        let mut member: Member = self
            .store_record(EntityRole::Member, member, None, input.additional_fields)
            .await?;
        {
            let mut state = self.lock()?;
            self.assign_insert_serial_id(&mut member.id, state.members.len());
            state.members.push(member.clone());
        }
        self.output_member(member).await
    }
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        let organization_id = self.organization_query(
            EntityRole::Member,
            "organizationId",
            Value::from(organization_id),
        )?;
        let user_id =
            self.organization_query(EntityRole::Member, "userId", Value::from(user_id))?;
        let rows = self.lock()?.members.snapshot()?;
        match rows.into_iter().find(|row| {
            row.organization_id
                .field_value()
                .strict_equals(&organization_id.field_value())
                && row
                    .user_id
                    .field_value()
                    .strict_equals(&user_id.field_value())
        }) {
            Some(value) => self.output_member(value).await.map(Some),
            None => Ok(None),
        }
    }
    async fn get_member_value(
        &self,
        organization_id: &Value,
        user_id: &Value,
    ) -> AuthResult<Option<Member>> {
        let organization_id = self.organization_query(
            EntityRole::Member,
            "organizationId",
            organization_id.clone(),
        )?;
        let user_id = self.organization_query(EntityRole::Member, "userId", user_id.clone())?;
        let rows = self.lock()?.members.snapshot()?;
        for row in rows {
            if row
                .organization_id
                .field_value()
                .strict_equals(&organization_id.field_value())
                && row
                    .user_id
                    .field_value()
                    .strict_equals(&user_id.field_value())
            {
                return self.output_member(row).await.map(Some);
            }
        }
        Ok(None)
    }
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        let id = self.organization_query(EntityRole::Member, "id", Value::from(id))?;
        let value = self.lock()?.members.get(&id)?;
        match value {
            Some(value) => self.output_member(value).await.map(Some),
            None => Ok(None),
        }
    }
    async fn update_member_role(&self, id: &str, role: &str) -> AuthResult<Member> {
        let id = self.organization_query(EntityRole::Member, "id", Value::from(id))?;
        let patch = self
            .prepare_record_patch(
                EntityRole::Member,
                [("role".into(), Value::from(role))].into_iter().collect(),
                FieldMap::new(),
            )
            .await?;
        let result = {
            let state = self.lock()?;
            let mut value = state
                .members
                .get_mut(&id)?
                .ok_or_else(|| AuthError::not_found("Member not found"))?;
            *value = patch.apply(value.clone())?;
            value.clone()
        };
        self.output_member(result).await
    }
    async fn delete_member(&self, id: &str) -> AuthResult<()> {
        let id = id.to_owned();
        crate::store::transaction(self, move |tx| {
            Box::pin(async move { tx.delete_member(&id).await })
        })
        .await
    }
    async fn delete_member_for_user(
        &self,
        id: &str,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<()> {
        let (id, organization_id, user_id) = (
            id.to_owned(),
            organization_id.to_owned(),
            user_id.to_owned(),
        );
        crate::store::transaction(self, move |tx| {
            Box::pin(async move {
                tx.delete_member_for_user(&id, &organization_id, &user_id)
                    .await
            })
        })
        .await
    }
    async fn list_organization_members(&self, org: &str) -> AuthResult<Vec<Member>> {
        let org =
            self.organization_query(EntityRole::Member, "organizationId", Value::from(org))?;
        let rows = self
            .lock()?
            .members
            .snapshot()?
            .into_iter()
            .filter(|row| {
                row.organization_id
                    .field_value()
                    .strict_equals(&org.field_value())
            })
            .collect();
        self.output_records(EntityRole::Member, rows).await
    }
    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        use crate::user_fields::UserFieldType;
        let schema = self.field_config(EntityRole::Member)?;
        let organization_id = self.organization_query(
            EntityRole::Member,
            "organizationId",
            Value::from(params.organization_id.clone()),
        )?;
        let mut members: Vec<_> = self
            .lock()?
            .members
            .snapshot()?
            .iter()
            .filter(|member| {
                member
                    .organization_id
                    .field_value()
                    .strict_equals(&organization_id.field_value())
            })
            .cloned()
            .collect();
        let value = |member: &Member, field: &str| -> Option<Value> {
            match field {
                "id" => member.id.as_str().map(|id| Value::String(id.to_owned())),
                "organizationId" => Some(member.organization_id.field_value()),
                "userId" => Some(member.user_id.field_value()),
                "role" => Some(member.role.field_value()),
                "createdAt" => Some(member.created_at.field_value()),
                _ => schema.fields().get(field).map(|config| {
                    member
                        .additional_fields
                        .get(resolve_field_name(config.field_name.as_deref(), field))
                        .cloned()
                        .unwrap_or(Value::Null)
                }),
            }
        };
        if let (Some(field), Some(expected)) = (&params.filter_field, &params.filter_value) {
            let operator = params.filter_operator.as_deref().unwrap_or("eq");
            if matches!(operator, "in" | "not_in") && !expected.is_array() {
                return Err(AuthError::internal("Value must be an array"));
            }
            let expected = if field == "id" {
                match expected {
                    Value::Array(values) => Value::Array(
                        values
                            .iter()
                            .map(|value| self.memory_user_id_query(value))
                            .collect::<AuthResult<Vec<_>>>()?
                            .into(),
                    ),
                    value => self.memory_user_id_query(value)?,
                }
            } else {
                self.memory_field_query(&schema, field, expected.clone())?
            };
            let field_type = schema.fields().get(field).map(|field| &field.field_type);
            let convert = |expected: &Value| -> Value {
                match (field_type, expected) {
                    (Some(UserFieldType::Number), Value::String(value)) => {
                        crate::organization_fields::numeric_filter(value)
                            .map_or_else(|| expected.clone(), Value::Number)
                    }
                    (Some(UserFieldType::Boolean), Value::String(value)) => {
                        Value::Bool(value == "true")
                    }
                    _ => expected.clone(),
                }
            };
            let expected = if let Some(values) = expected.as_array() {
                // The adapter converts number arrays only when every input is a numeric string.
                if matches!(field_type, Some(UserFieldType::Number))
                    && values.iter().all(|value| {
                        value
                            .as_str()
                            .and_then(crate::organization_fields::numeric_filter)
                            .is_some()
                    })
                {
                    Value::Array(values.iter().map(convert).collect::<Vec<_>>().into())
                } else {
                    expected.clone()
                }
            } else {
                convert(&expected)
            };
            let matches_member = |member: &Member| -> AuthResult<bool> {
                let Some(actual) = value(member, field) else {
                    return Ok(true);
                };
                if matches!(operator, "in" | "not_in") {
                    let contains = expected.as_array().is_some_and(|values| {
                        values
                            .iter()
                            .any(|expected| actual.same_value_zero(expected))
                    });
                    return Ok(if operator == "in" {
                        contains
                    } else {
                        !contains
                    });
                }
                if actual.is_null() {
                    return Ok(false);
                }
                let expected = if field == "createdAt"
                    && expected.is_string()
                    && !schema
                        .fields()
                        .get(field)
                        .is_some_and(|field| field.references_id())
                {
                    match expected
                        .as_str()
                        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                    {
                        Some(date) => Value::from(date.with_timezone(&Utc)),
                        None => return Ok(false),
                    }
                } else {
                    expected.clone()
                };
                let ordering = crate::query::field_compare(&actual, &expected)?;
                Ok(match operator {
                    "eq" => actual.strict_equals(&expected),
                    "ne" => !actual.strict_equals(&expected),
                    "contains" | "starts_with" | "ends_with" => {
                        let actual = actual.display_utf16()?;
                        let expected = expected.display_utf16()?;
                        let (actual, expected) = (actual.as_utf16(), expected.as_utf16());
                        match operator {
                            "starts_with" => actual.starts_with(expected),
                            "ends_with" => actual.ends_with(expected),
                            _ => {
                                expected.is_empty()
                                    || actual.windows(expected.len()).any(|part| part == expected)
                            }
                        }
                    }
                    "gt" => ordering == Some(std::cmp::Ordering::Greater),
                    "gte" => matches!(
                        ordering,
                        Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
                    ),
                    "lt" => ordering == Some(std::cmp::Ordering::Less),
                    "lte" => matches!(
                        ordering,
                        Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
                    ),
                    _ => true,
                })
            };
            let mut selected = Vec::with_capacity(members.len());
            for member in members {
                if matches_member(&member)? {
                    selected.push(member);
                }
            }
            members = selected;
        }
        let field = params.sort_by.as_deref().unwrap_or("createdAt");
        let mut sort_error = None;
        members.sort_by(|left, right| {
            if sort_error.is_some() {
                return std::cmp::Ordering::Equal;
            }
            match compare_member_values(
                &value(left, field).unwrap_or(Value::Null),
                &value(right, field).unwrap_or(Value::Null),
            ) {
                Ok(ordering) => ordering,
                Err(error) => {
                    sort_error = Some(error);
                    std::cmp::Ordering::Equal
                }
            }
        });
        if let Some(error) = sort_error {
            return Err(error);
        }
        if params.sort_direction.as_deref() == Some("desc") {
            members.reverse();
        }
        let total = members.len();
        Ok((
            self.output_records(
                EntityRole::Member,
                crate::query::paginate_memory(members, params.limit, params.offset),
            )
            .await?,
            total,
        ))
    }
    async fn count_organization_members(&self, org: &str) -> AuthResult<i64> {
        let org =
            self.organization_query(EntityRole::Member, "organizationId", Value::from(org))?;
        Ok(self
            .lock()?
            .members
            .snapshot()?
            .iter()
            .filter(|member| {
                member
                    .organization_id
                    .field_value()
                    .strict_equals(&org.field_value())
            })
            .count() as i64)
    }
    async fn count_organization_members_value(&self, org: &Value) -> AuthResult<i64> {
        let org = self.organization_query(EntityRole::Member, "organizationId", org.clone())?;
        self.lock()?
            .members
            .snapshot()?
            .iter()
            .try_fold(0, |count, member| {
                Ok(count
                    + i64::from(
                        member
                            .organization_id
                            .field_value()
                            .strict_equals(&org.field_value()),
                    ))
            })
    }
    async fn count_organization_owners(&self, org: &str) -> AuthResult<i64> {
        let org =
            self.organization_query(EntityRole::Member, "organizationId", Value::from(org))?;
        self.lock()?
            .members
            .snapshot()?
            .iter()
            .filter(|member| {
                member
                    .organization_id
                    .field_value()
                    .strict_equals(&org.field_value())
            })
            .try_fold(0, |count, member| {
                Ok(count + i64::from(member.role.typed()?.split(',').any(|role| role == "owner")))
            })
    }
}
#[async_trait]
impl InvitationStore for EphemeralStore {
    async fn create_invitation(&self, mut input: CreateInvitation) -> AuthResult<Invitation> {
        let mut invitation = Invitation {
            additional_fields: Default::default(),
            id: self
                .generated_id("invitation", input.id, self.lock()?.invitations.len())?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            organization_id: (input.organization_id).into(),
            email: (input.email).into(),
            role: input.role.into(),
            status: (input.status.unwrap_or_default()).into(),
            inviter_id: (input.inviter_id).into(),
            team_id: (input.team_id).into(),
            expires_at: (input.expires_at).into(),
            created_at: (input.created_at.unwrap_or_else(|| Utc::now().into())).into(),
        };
        if let Some(value) = input.additional_fields.remove("status") {
            invitation.status = crate::SchemaValue::Dynamic(value);
        }
        if let Some(value) = input.additional_fields.remove("createdAt") {
            invitation.created_at = crate::SchemaValue::Dynamic(value);
        }
        if let Some(value) = input.additional_fields.remove("expiresAt") {
            invitation.expires_at = crate::SchemaValue::Dynamic(value);
        }
        if let Some(value) = input.additional_fields.remove("inviterId") {
            invitation.inviter_id = crate::SchemaValue::Dynamic(value);
        }
        let mut invitation: Invitation = self
            .store_record(
                EntityRole::Invitation,
                invitation,
                None,
                input.additional_fields,
            )
            .await?;
        {
            let mut state = self.lock()?;
            self.assign_insert_serial_id(&mut invitation.id, state.invitations.len());
            state.invitations.push(invitation.clone());
        }
        self.output_invitation(invitation).await
    }
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        let id = self.organization_query(EntityRole::Invitation, "id", Value::from(id))?;
        let value = self.lock()?.invitations.get(&id)?;
        match value {
            Some(value) => self.output_invitation(value).await.map(Some),
            None => Ok(None),
        }
    }
    async fn get_pending_invitation(
        &self,
        org: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        let email = self.organization_query(EntityRole::Invitation, "email", Value::from(email))?;
        let org =
            self.organization_query(EntityRole::Invitation, "organizationId", Value::from(org))?;
        let rows = self.lock()?.invitations.snapshot()?;
        for invitation in rows.into_iter().filter(|row| {
            row.organization_id
                .field_value()
                .strict_equals(&org.field_value())
                && row.is_pending()
        }) {
            if match (invitation.email.as_str(), email.as_str()) {
                (Some(actual), Some(expected)) => actual.eq_ignore_ascii_case(expected),
                _ => invitation
                    .email
                    .field_value()
                    .strict_equals(&email.field_value()),
            } && !invitation.is_expired()?
            {
                return self.output_invitation(invitation).await.map(Some);
            }
        }
        Ok(None)
    }
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        let id = self.organization_query(EntityRole::Invitation, "id", Value::from(id))?;
        let patch = self
            .prepare_record_patch(
                EntityRole::Invitation,
                [("status".into(), status.into_field())]
                    .into_iter()
                    .collect(),
                FieldMap::new(),
            )
            .await?;
        let result = {
            let state = self.lock()?;
            let mut value = state
                .invitations
                .get_mut(&id)?
                .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
            *value = patch.apply(value.clone())?;
            value.clone()
        };
        self.output_invitation(result).await
    }
    async fn update_invitation_expiry(
        &self,
        id: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<Invitation> {
        let id = self.organization_query(EntityRole::Invitation, "id", Value::from(id))?;
        let patch = self
            .prepare_record_patch(
                EntityRole::Invitation,
                [("expiresAt".into(), Value::from(expires_at))]
                    .into_iter()
                    .collect(),
                FieldMap::new(),
            )
            .await?;
        let result = {
            let state = self.lock()?;
            let mut value = state
                .invitations
                .get_mut(&id)?
                .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
            *value = patch.apply(value.clone())?;
            value.clone()
        };
        self.output_invitation(result).await
    }
    async fn list_organization_invitations(&self, org: &str) -> AuthResult<Vec<Invitation>> {
        let org =
            self.organization_query(EntityRole::Invitation, "organizationId", Value::from(org))?;
        let rows = self
            .lock()?
            .invitations
            .snapshot()?
            .into_iter()
            .filter(|row| {
                row.organization_id
                    .field_value()
                    .strict_equals(&org.field_value())
            })
            .collect();
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        self.output_records(EntityRole::Invitation, rows).await
    }
    async fn count_pending_organization_invitations(&self, org: &str) -> AuthResult<i64> {
        let org =
            self.organization_query(EntityRole::Invitation, "organizationId", Value::from(org))?;
        self.lock()?
            .invitations
            .snapshot()?
            .iter()
            .filter(|invitation| {
                invitation
                    .organization_id
                    .field_value()
                    .strict_equals(&org.field_value())
                    && invitation.is_pending()
            })
            .try_fold(0, |count, invitation| {
                Ok(count + i64::from(!invitation.is_expired()?))
            })
    }
    async fn list_user_invitations(
        &self,
        email: &str,
    ) -> AuthResult<Vec<crate::store::InvitationOrganization>> {
        if self.config.advanced.database.joins == Some(true) {
            return self.joined_user_invitations(email).await;
        }
        let email = self.organization_query(
            EntityRole::Invitation,
            "email",
            Value::from(email.to_lowercase()),
        )?;
        let selected = {
            let state = self.lock()?;
            state
                .invitations
                .select_refs(|row| row.email.field_value().strict_equals(&email.field_value()))?
                .into_iter()
                .map(|row| {
                    let id = row.read(|row| self.organization_primary_id(&row.organization_id))?;
                    Ok((row, id))
                })
                .collect::<AuthResult<Vec<_>>>()?
        };
        let (rows, ids): (Vec<_>, Vec<_>) = crate::query::paginate_memory(
            selected,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        )
        .into_iter()
        .unzip();
        self.output_record_refs_batches_then(EntityRole::Invitation, rows, |ready| {
            let ids = &ids;
            async move {
                let mut pending = Vec::new();
                let mut organizations = Vec::new();
                for (index, invitation) in ready {
                    let id = ids.get(index).ok_or_else(|| {
                        AuthError::internal("Invitation projection lost its stored join index")
                    })?;
                    let organization = self.lock()?.organizations.first_ref(|row| row.id == *id)?;
                    let has_organization = organization.is_some();
                    organizations.extend(organization);
                    pending.push((index, invitation, has_organization));
                }
                let mut organizations = self
                    .output_record_refs(EntityRole::Organization, organizations)
                    .await?
                    .into_iter();
                Ok(pending
                    .into_iter()
                    .map(|(index, invitation, has_organization)| {
                        (
                            index,
                            crate::store::InvitationOrganization {
                                invitation,
                                organization: if has_organization {
                                    organizations.next()
                                } else {
                                    None
                                },
                            },
                        )
                    })
                    .collect())
            }
        })
        .await
    }
}

#[cfg(test)]
mod query_tests {
    use super::*;
    use crate::organization_fields::OrganizationFields;
    use crate::user_fields::{UserFieldConfig, UserFieldType};
    use serde_json::json;

    #[tokio::test]
    async fn native_json_policies_transform_raw_text_without_reencoding_reads() -> AuthResult<()> {
        use crate::store::OrganizationRoleStore;
        let store = EphemeralStore::default();
        let replace =
            |from: &'static str, to: &'static str| -> crate::user_fields::UserFieldTransform {
                UserFieldTransform::new(move |value| {
                    Ok(match value {
                        Value::String(value) => Value::from(value.replace(from, to)),
                        value => value,
                    })
                })
            };
        let policy = UserFieldConfig {
            required: Some(false),
            transform: Some(FieldTransforms {
                input: Some(replace("source", "stored")),
                output: Some(replace("stored", "visible")),
            }),
            ..Default::default()
        };
        let mut fields = OrganizationFields::default();
        let _ = fields
            .organization
            .fields_mut()
            .insert("metadata".into(), policy.clone());
        let _ = fields
            .organization_role
            .fields_mut()
            .insert("permission".into(), policy);
        store.configure_organization_fields(fields)?;
        let organization = store
            .create_organization(
                CreateOrganization::new("Native", "native")
                    .with_metadata(Value::from_json(json!({"source":1}))?),
            )
            .await?;
        assert_eq!(
            organization.metadata.json()?,
            Some(json!(r#"{"visible":1}"#))
        );
        assert_eq!(
            store
                .lock()
                .unwrap()
                .organizations
                .get(&organization.id)?
                .unwrap()
                .metadata
                .json()?,
            Some(json!(r#"{"stored":1}"#))
        );
        assert_eq!(
            store
                .get_organization_by_id(organization.id.typed().unwrap())
                .await?
                .unwrap()
                .metadata,
            organization.metadata
        );
        let updated = store
            .update_organization(
                organization.id.typed().unwrap(),
                UpdateOrganization {
                    metadata: Some(Value::Null),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(updated.metadata.json()?, Some(json!("null")));
        let role = store
            .create_organization_role(crate::CreateOrganizationRole {
                organization_id: organization.id.typed().unwrap().clone(),
                role: "native".into(),
                permission: Value::from_json(json!({"ignored":["original"]}))?,
                additional_fields: [("permission".into(), Value::from(r#"{"source":["read"]}"#))]
                    .into_iter()
                    .collect(),
            })
            .await?;
        assert_eq!(
            role.permission.json()?,
            Some(json!(r#"{"visible":["read"]}"#))
        );
        assert_eq!(
            store
                .lock()
                .unwrap()
                .organization_roles
                .get(&role.id)?
                .unwrap()
                .permission
                .json()?,
            Some(json!(r#"{"stored":["read"]}"#))
        );
        assert_eq!(
            store
                .get_organization_role(role.id.typed().unwrap())
                .await?
                .unwrap()
                .permission,
            role.permission
        );
        Ok(())
    }

    #[tokio::test]
    async fn member_queries_use_typed_storage_before_output_transforms() -> AuthResult<()> {
        let store = EphemeralStore::default();
        let mut fields = OrganizationFields::default();
        fields.member.additional_fields = Some(
            [
                (
                    "label".into(),
                    UserFieldConfig {
                        field_name: Some("stored_label".into()),
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new(|value| {
                                Ok(if value.is_undefined() {
                                    value
                                } else {
                                    Value::from(format!(
                                        "{}:in",
                                        value.as_str().unwrap_or_default()
                                    ))
                                })
                            })),
                            output: Some(UserFieldTransform::new(|value| {
                                Ok(if value.is_undefined() {
                                    value
                                } else {
                                    Value::from(format!(
                                        "{}:out",
                                        value.as_str().unwrap_or_default()
                                    ))
                                })
                            })),
                        }),
                        ..Default::default()
                    },
                ),
                (
                    "score".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Number,
                        ..Default::default()
                    },
                ),
                (
                    "enabled".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Boolean,
                        ..Default::default()
                    },
                ),
            ]
            .into_iter()
            .collect(),
        );
        store.configure_organization_fields(fields)?;
        for (user, score, enabled) in [("first", 2, false), ("second", 10, true)] {
            let mut member = CreateMember::new("organization", user, "member");
            member.additional_fields = [
                ("label".into(), Value::from(user)),
                ("score".into(), Value::from(f64::from(score))),
                ("enabled".into(), Value::from(enabled)),
            ]
            .into_iter()
            .collect();
            let _ = store.create_member(member).await?;
        }
        let mut params = ListOrganizationMembersParams {
            organization_id: "organization".into(),
            filter_field: Some("label".into()),
            filter_value: Some("first:in".into()),
            ..Default::default()
        };
        let (members, total) = store.query_organization_members(&params).await?;
        assert_eq!(total, 1);
        assert_eq!(members[0].user_id, "first");
        assert_eq!(
            members[0].additional_fields["label"],
            Value::String("first:in:out".into())
        );
        params.filter_value = Some("first".into());
        assert_eq!(store.query_organization_members(&params).await?.1, 0);
        params.filter_field = Some("score".into());
        params.filter_value = Some(" 0x2 ".into());
        params.filter_operator = Some("gt".into());
        let (members, total) = store.query_organization_members(&params).await?;
        assert_eq!(total, 1);
        assert_eq!(members[0].user_id, "second");
        params.filter_operator = Some("contains".into());
        for filter in ["0xa", "1e1"] {
            params.filter_value = Some(filter.into());
            let (members, total) = store.query_organization_members(&params).await?;
            assert_eq!(total, 1);
            assert_eq!(members[0].user_id, "second");
        }
        params.filter_field = Some("enabled".into());
        params.filter_value = Some("false".into());
        params.filter_operator = Some("eq".into());
        let (members, total) = store.query_organization_members(&params).await?;
        assert_eq!(total, 1);
        assert_eq!(members[0].user_id, "first");
        params.filter_operator = Some("contains".into());
        params.filter_value = Some("not-true".into());
        let (members, total) = store.query_organization_members(&params).await?;
        assert_eq!(total, 1);
        assert_eq!(members[0].user_id, "first");
        params.filter_field = None;
        params.filter_value = None;
        params.sort_by = Some("score".into());
        params.sort_direction = Some("desc".into());
        params.limit = Some(1.0);
        let (members, total) = store.query_organization_members(&params).await?;
        assert_eq!(total, 2);
        assert_eq!(members[0].user_id, "second");
        Ok(())
    }
}
