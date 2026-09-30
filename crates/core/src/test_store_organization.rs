use super::*;
use better_auth_schema_registry::EntityRole;
use serde_json::{Map, json};

fn compare_member_values(
    left: &serde_json::Value,
    right: &serde_json::Value,
) -> std::cmp::Ordering {
    use serde_json::Value;
    match (left, right) {
        (Value::Null, Value::Null) => std::cmp::Ordering::Equal,
        (Value::Null, _) => std::cmp::Ordering::Less,
        (_, Value::Null) => std::cmp::Ordering::Greater,
        (Value::Number(left), Value::Number(right)) => left
            .as_f64()
            .partial_cmp(&right.as_f64())
            .unwrap_or(std::cmp::Ordering::Equal),
        (Value::Bool(left), Value::Bool(right)) => left.cmp(right),
        (Value::String(left), Value::String(right)) => left.cmp(right),
        _ => left.to_string().cmp(&right.to_string()),
    }
}

#[async_trait]
impl OrganizationStore for MemoryStore {
    fn configure_organization_fields(
        &self,
        fields: crate::organization_fields::OrganizationFields,
    ) -> AuthResult<()> {
        let fields = fields.into_storage()?;
        *self
            .organization_fields
            .write()
            .unwrap_or_else(|error| error.into_inner()) = fields;
        Ok(())
    }
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
            additional_fields: Default::default(),
            id: input.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            name: input.name,
            slug: input.slug,
            logo: input.logo,
            metadata: input.metadata,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let metadata = org.metadata.clone();
        let mut org: Organization =
            self.store_record(EntityRole::Organization, org, None, input.additional_fields)?;
        org.metadata = metadata;
        state.organizations.insert(org.id.clone(), org.clone());
        self.output_organization(org)
    }
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        self.lock()
            .organizations
            .get(id)
            .cloned()
            .map(|value| self.output_organization(value))
            .transpose()
    }
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        self.lock()
            .organizations
            .values()
            .find(|org| org.slug == slug)
            .cloned()
            .map(|value| self.output_organization(value))
            .transpose()
    }
    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        self.lock()
            .organizations
            .values()
            .filter(|org| ids.contains(&org.id))
            .cloned()
            .map(|value| self.output_organization(value))
            .collect()
    }
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let mut state = self.lock();
        let mut org = state
            .organizations
            .get(id)
            .cloned()
            .ok_or_else(|| AuthError::not_found("Organization not found"))?;
        let mut patch = Map::new();
        if let Some(name) = update.name {
            let _ = patch.insert("name".into(), json!(name));
        }
        if let Some(slug) = update.slug {
            let _ = patch.insert("slug".into(), json!(slug));
        }
        if let Some(logo) = update.logo {
            let _ = patch.insert("logo".into(), json!(logo));
        }
        if let Some(created_at) = update.created_at {
            let _ = patch.insert("createdAt".into(), json!(created_at));
        }
        if let Some(new_id) = update.id {
            let _ = patch.insert("id".into(), json!(new_id));
        }
        if let Some(metadata) = update.metadata {
            org.metadata = Some(metadata);
        }
        org.updated_at = Utc::now();
        let metadata = org.metadata.clone();
        let mut result: Organization = self.store_record(
            EntityRole::Organization,
            org,
            Some(patch),
            update.additional_fields,
        )?;
        result.metadata = metadata;
        state.organizations.remove(id);
        state
            .organizations
            .insert(result.id.clone(), result.clone());
        self.output_organization(result)
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
        state
            .members
            .values()
            .filter(|member| member.user_id == user_id)
            .filter_map(|member| state.organizations.get(&member.organization_id).cloned())
            .map(|value| self.output_organization(value))
            .collect()
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
            additional_fields: Default::default(),
            id: uuid::Uuid::new_v4().to_string(),
            organization_id: input.organization_id,
            user_id: input.user_id,
            role: input.role,
            created_at: Utc::now(),
        };
        let member: Member =
            self.store_record(EntityRole::Member, member, None, input.additional_fields)?;
        state.members.insert(member.id.clone(), member.clone());
        self.output_member(member)
    }
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        self.lock()
            .members
            .values()
            .find(|member| member.organization_id == organization_id && member.user_id == user_id)
            .cloned()
            .map(|value| self.output_member(value))
            .transpose()
    }
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        self.lock()
            .members
            .get(id)
            .cloned()
            .map(|value| self.output_member(value))
            .transpose()
    }
    async fn update_member_role(&self, id: &str, role: &str) -> AuthResult<Member> {
        let mut state = self.lock();
        let member = state
            .members
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Member not found"))?;
        *member = self.store_record(
            EntityRole::Member,
            member.clone(),
            Some([("role".into(), json!(role))].into_iter().collect()),
            Map::new(),
        )?;
        self.output_member(member.clone())
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
        self.lock()
            .members
            .values()
            .filter(|member| member.organization_id == org)
            .cloned()
            .map(|value| self.output_member(value))
            .collect()
    }
    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        use crate::user_fields::UserFieldType;
        use serde_json::Value;
        let schema = self.organization_fields().member;
        let mut members: Vec<_> = self
            .lock()
            .members
            .values()
            .filter(|member| member.organization_id == params.organization_id)
            .cloned()
            .collect();
        let value = |member: &Member, field: &str| -> Option<Value> {
            match field {
                "id" => Some(Value::String(member.id.clone())),
                "organizationId" => Some(Value::String(member.organization_id.clone())),
                "userId" => Some(Value::String(member.user_id.clone())),
                "role" => Some(Value::String(member.role.clone())),
                "createdAt" => Some(Value::String(member.created_at.to_rfc3339())),
                _ => schema.additional_fields.get(field).map(|config| {
                    member
                        .additional_fields
                        .get(config.field_name.as_deref().unwrap_or(field))
                        .cloned()
                        .unwrap_or(Value::Null)
                }),
            }
        };
        if let (Some(field), Some(expected)) = (&params.filter_field, &params.filter_value) {
            members.retain(|member| {
                let Some(actual) = value(member, field) else {
                    return true;
                };
                if actual.is_null() {
                    return false;
                }
                let expected = if field == "createdAt" {
                    match chrono::DateTime::parse_from_rfc3339(expected) {
                        Ok(date) => date.with_timezone(&Utc).to_rfc3339(),
                        Err(_) => return false,
                    }
                } else {
                    expected.clone()
                };
                let field_type = schema
                    .additional_fields
                    .get(field)
                    .map(|field| &field.field_type);
                let number = matches!(field_type, Some(UserFieldType::Number))
                    .then(|| crate::organization_fields::numeric_filter(&expected))
                    .flatten();
                let ordering = if let Some(number) = number
                    && let Some(actual) = actual.as_f64()
                {
                    actual
                        .partial_cmp(&number)
                        .unwrap_or(std::cmp::Ordering::Equal)
                } else {
                    let expected = if matches!(field_type, Some(UserFieldType::Boolean)) {
                        Value::Bool(expected == "true")
                    } else {
                        Value::String(expected.clone())
                    };
                    compare_member_values(&actual, &expected)
                };
                match params.filter_operator.as_deref().unwrap_or("eq") {
                    "eq" => ordering.is_eq(),
                    "ne" => !ordering.is_eq(),
                    "contains" => {
                        let expected = if matches!(field_type, Some(UserFieldType::Boolean)) {
                            (expected == "true").to_string()
                        } else {
                            number.map_or(expected, |number| number.to_string())
                        };
                        actual
                            .as_str()
                            .map_or_else(|| actual.to_string(), str::to_owned)
                            .contains(&expected)
                    }
                    "gt" => ordering.is_gt(),
                    "gte" => !ordering.is_lt(),
                    "lt" => ordering.is_lt(),
                    "lte" => !ordering.is_gt(),
                    _ => true,
                }
            });
        }
        let field = params.sort_by.as_deref().unwrap_or("createdAt");
        members.sort_by(|left, right| {
            compare_member_values(
                &value(left, field).unwrap_or(Value::Null),
                &value(right, field).unwrap_or(Value::Null),
            )
        });
        if params.sort_direction.as_deref() == Some("desc") {
            members.reverse();
        }
        let total = members.len();
        Ok((
            members
                .into_iter()
                .skip(params.offset.unwrap_or(0))
                .take(params.limit.unwrap_or(usize::MAX))
                .map(|member| self.output_member(member))
                .collect::<AuthResult<Vec<_>>>()?,
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
            additional_fields: Default::default(),
            id: input.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            organization_id: input.organization_id,
            email: input.email,
            role: input.role,
            status: input.status.unwrap_or_default(),
            inviter_id: input.inviter_id,
            team_id: input.team_id,
            expires_at: input.expires_at,
            created_at: input.created_at.unwrap_or_else(Utc::now),
        };
        let invitation: Invitation = self.store_record(
            EntityRole::Invitation,
            invitation,
            None,
            input.additional_fields,
        )?;
        self.lock()
            .invitations
            .insert(invitation.id.clone(), invitation.clone());
        self.output_invitation(invitation)
    }
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        self.lock()
            .invitations
            .get(id)
            .cloned()
            .map(|value| self.output_invitation(value))
            .transpose()
    }
    async fn get_pending_invitation(
        &self,
        org: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        self.lock()
            .invitations
            .values()
            .find(|invitation| {
                invitation.organization_id == org
                    && invitation.email.eq_ignore_ascii_case(email)
                    && invitation.is_pending()
                    && !invitation.is_expired()
            })
            .cloned()
            .map(|value| self.output_invitation(value))
            .transpose()
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
        *invitation = self.store_record(
            EntityRole::Invitation,
            invitation.clone(),
            Some([("status".into(), json!(status))].into_iter().collect()),
            Map::new(),
        )?;
        self.output_invitation(invitation.clone())
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
        *invitation = self.store_record(
            EntityRole::Invitation,
            invitation.clone(),
            Some(
                [("expiresAt".into(), json!(expires_at))]
                    .into_iter()
                    .collect(),
            ),
            Map::new(),
        )?;
        self.output_invitation(invitation.clone())
    }
    async fn list_organization_invitations(&self, org: &str) -> AuthResult<Vec<Invitation>> {
        self.lock()
            .invitations
            .values()
            .filter(|invitation| invitation.organization_id == org)
            .cloned()
            .map(|value| self.output_invitation(value))
            .collect()
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
        self.lock()
            .invitations
            .values()
            .filter(|invitation| {
                invitation.email.eq_ignore_ascii_case(email)
                    && invitation.is_pending()
                    && !invitation.is_expired()
            })
            .cloned()
            .map(|value| self.output_invitation(value))
            .collect()
    }
}

#[cfg(test)]
mod query_tests {
    use super::*;
    use crate::organization_fields::OrganizationFields;
    use crate::user_fields::{UserFieldConfig, UserFieldType};
    use serde_json::{Value, json};

    #[tokio::test]
    async fn member_queries_use_typed_storage_before_output_transforms() -> AuthResult<()> {
        let store = MemoryStore::default();
        let mut fields = OrganizationFields::default();
        fields.member.additional_fields = [
            (
                "label".into(),
                UserFieldConfig {
                    field_name: Some("stored_label".into()),
                    input_transform: Some(Arc::new(|value| {
                        Ok(value.map(|value| {
                            json!(format!("{}:in", value.as_str().unwrap_or_default()))
                        }))
                    })),
                    output_transform: Some(Arc::new(|value| {
                        Ok(value.map(|value| {
                            json!(format!("{}:out", value.as_str().unwrap_or_default()))
                        }))
                    })),
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
        .collect();
        store.configure_organization_fields(fields)?;
        for (user, score, enabled) in [("first", 2, false), ("second", 10, true)] {
            let mut member = CreateMember::new("organization", user, "member");
            member.additional_fields = [
                ("label".into(), json!(user)),
                ("score".into(), json!(score)),
                ("enabled".into(), json!(enabled)),
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
        params.limit = Some(1);
        let (members, total) = store.query_organization_members(&params).await?;
        assert_eq!(total, 2);
        assert_eq!(members[0].user_id, "second");
        Ok(())
    }
}
