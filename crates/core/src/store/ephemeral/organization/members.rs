use super::*;

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
        let mut record = self
            .store_record(EntityRole::Member, record, None, fields)
            .await?;
        {
            let mut state = self.lock()?;
            if let Some(id) = self.next_serial_id(state.members.len()) {
                let _ = record.insert("id".into(), id);
            }
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
        let mut member = self
            .store_record(EntityRole::Member, member, None, input.additional_fields)
            .await?;
        {
            let mut state = self.lock()?;
            if let Some(id) = self.next_serial_id(state.members.len()) {
                let _ = member.insert("id".into(), id);
            }
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
        let schema = self.field_config(EntityRole::Member)?;
        let rows = self.lock()?.members.snapshot()?;
        match rows.into_iter().find(|row| {
            organization_value(&row, &schema, "organizationId")
                .strict_equals(&organization_id.field_value())
                && organization_value(&row, &schema, "userId").strict_equals(&user_id.field_value())
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
        let schema = self.field_config(EntityRole::Member)?;
        let rows = self.lock()?.members.snapshot()?;
        for row in rows {
            if organization_value(&row, &schema, "organizationId")
                .strict_equals(&organization_id.field_value())
                && organization_value(&row, &schema, "userId").strict_equals(&user_id.field_value())
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
        self.update_member_role_value(&id.into(), role).await
    }
    async fn update_member_role_value(&self, id: &Value, role: &str) -> AuthResult<Member> {
        let id = self.organization_query(EntityRole::Member, "id", id.clone())?;
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
            *value = patch.apply(value.clone());
            value.clone()
        };
        self.output_member(result).await
    }
    async fn delete_member(&self, id: &str) -> AuthResult<()> {
        self.delete_member_value(&id.into()).await
    }
    async fn delete_member_value(&self, id: &Value) -> AuthResult<()> {
        let id = id.clone();
        crate::store::transaction(self, move |tx| {
            Box::pin(async move { tx.delete_member_value(&id).await })
        })
        .await
    }
    async fn delete_member_for_user(
        &self,
        id: &str,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<()> {
        self.delete_member_for_user_value(&id.into(), &organization_id.into(), &user_id.into())
            .await
    }
    async fn delete_member_for_user_value(
        &self,
        id: &Value,
        organization_id: &Value,
        user_id: &Value,
    ) -> AuthResult<()> {
        let (id, organization_id, user_id) = (id.clone(), organization_id.clone(), user_id.clone());
        crate::store::transaction(self, move |tx| {
            Box::pin(async move {
                tx.delete_member_for_user_value(&id, &organization_id, &user_id)
                    .await
            })
        })
        .await
    }
    async fn list_organization_members(&self, org: &str) -> AuthResult<Vec<Member>> {
        self.list_organization_members_value(&Value::from(org))
            .await
    }
    async fn list_organization_members_value(&self, org: &Value) -> AuthResult<Vec<Member>> {
        let org = self.organization_query(EntityRole::Member, "organizationId", org.clone())?;
        let schema = self.field_config(EntityRole::Member)?;
        let rows = self
            .lock()?
            .members
            .snapshot()?
            .into_iter()
            .filter(|row| {
                organization_value(row, &schema, "organizationId").strict_equals(&org.field_value())
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
            params.organization_id.field_value(),
        )?;
        let mut members: Vec<_> = self
            .lock()?
            .members
            .snapshot()?
            .iter()
            .filter(|member| {
                organization_value(member, &schema, "organizationId")
                    .strict_equals(&organization_id.field_value())
            })
            .cloned()
            .collect();
        let value = |member: &FieldMap, field: &str| -> Option<Value> {
            (field == "id" || schema.fields().contains_key(field))
                .then(|| organization_value(member, &schema, field))
        };
        if let (Some(field), Some(expected)) = (&params.filter_field, &params.filter_value) {
            let operator = params.filter_operator.as_deref().unwrap_or("eq");
            if matches!(operator, "in" | "not_in") && !expected.is_array() {
                return Err(AuthError::internal("Value must be an array"));
            }
            let expected = if field == "id" {
                self.memory_primary_id_query(expected)?
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
            let matches_member = |member: &FieldMap| -> AuthResult<bool> {
                let Some(actual) = value(member, field) else {
                    return Ok(true);
                };
                if matches!(operator, "in" | "not_in") {
                    let values = expected
                        .as_array()
                        .ok_or_else(|| AuthError::internal("Value must be an array"))?;
                    let contains = values
                        .iter()
                        .any(|expected| actual.same_value_zero(expected));
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
                    "gt" | "gte" | "lt" | "lte" => {
                        use std::cmp::Ordering::{Equal, Greater, Less};
                        let ordering = crate::query::field_compare(&actual, &expected)?;
                        matches!(
                            (operator, ordering),
                            ("gt" | "gte", Some(Greater))
                                | ("lt" | "lte", Some(Less))
                                | ("gte" | "lte", Some(Equal))
                        )
                    }
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
        let descending = params.sort_direction.as_deref() == Some("desc");
        crate::memory_sort::sort(&mut members, descending, |member| {
            Ok(value(member, field).unwrap_or(Value::Null))
        })?;
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
        let schema = self.field_config(EntityRole::Member)?;
        let org =
            self.organization_query(EntityRole::Member, "organizationId", Value::from(org))?;
        Ok(self
            .lock()?
            .members
            .snapshot()?
            .iter()
            .filter(|member| {
                organization_value(member, &schema, "organizationId")
                    .strict_equals(&org.field_value())
            })
            .count() as i64)
    }
    async fn count_organization_members_value(&self, org: &Value) -> AuthResult<i64> {
        let schema = self.field_config(EntityRole::Member)?;
        let org = self.organization_query(EntityRole::Member, "organizationId", org.clone())?;
        self.lock()?
            .members
            .snapshot()?
            .iter()
            .try_fold(0, |count, member| {
                Ok(count
                    + i64::from(
                        organization_value(member, &schema, "organizationId")
                            .strict_equals(&org.field_value()),
                    ))
            })
    }
    async fn count_organization_owners(&self, org: &str) -> AuthResult<i64> {
        let schema = self.field_config(EntityRole::Member)?;
        let org =
            self.organization_query(EntityRole::Member, "organizationId", Value::from(org))?;
        self.lock()?
            .members
            .snapshot()?
            .iter()
            .filter(|member| {
                organization_value(member, &schema, "organizationId")
                    .strict_equals(&org.field_value())
            })
            .try_fold(0, |count, member| {
                let role = crate::SchemaValue::<String>::from_field(organization_value(
                    member, &schema, "role",
                ));
                Ok(count + i64::from(role.typed()?.split(',').any(|role| role == "owner")))
            })
    }
}
