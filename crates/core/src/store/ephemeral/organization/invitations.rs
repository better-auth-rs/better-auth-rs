use super::*;

#[async_trait]
impl InvitationStore for EphemeralStore {
    async fn create_invitation(&self, mut input: CreateInvitation) -> AuthResult<Invitation> {
        let mut invitation = Invitation {
            additional_fields: Default::default(),
            id: self
                .generated_id("invitation", input.id, self.lock()?.invitations.len())?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            organization_id: input.organization_id,
            email: (input.email).into(),
            role: input.role.into(),
            status: (input.status.unwrap_or_default()).into(),
            inviter_id: input.inviter_id,
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
        let mut invitation = self
            .store_record(
                EntityRole::Invitation,
                invitation,
                None,
                input.additional_fields,
            )
            .await?;
        {
            let mut state = self.lock()?;
            if let Some(id) = self.next_serial_id(state.invitations.len()) {
                let _ = invitation.insert("id".into(), id);
            }
            state.invitations.push(invitation.clone());
        }
        self.output_invitation(invitation).await
    }
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        self.get_invitation_by_id_value(&id.into()).await
    }
    async fn get_invitation_by_id_value(&self, id: &Value) -> AuthResult<Option<Invitation>> {
        let id = self.organization_query(EntityRole::Invitation, "id", id.clone())?;
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
        self.get_pending_invitation_value(&org.into(), email).await
    }
    async fn get_pending_invitation_value(
        &self,
        org: &Value,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        Ok(self
            .pending_invitation_rows(org, Some(email))
            .await?
            .into_iter()
            .next())
    }
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        self.update_invitation_status_value(&id.into(), status)
            .await
    }
    async fn update_invitation_status_value(
        &self,
        id: &Value,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        let id = self.organization_query(EntityRole::Invitation, "id", id.clone())?;
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
            *value = patch.apply(value.clone());
            value.clone()
        };
        self.output_invitation(result).await
    }
    async fn update_invitation_expiry(
        &self,
        id: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<Invitation> {
        self.update_invitation_expiry_value(&id.into(), expires_at)
            .await
    }
    async fn update_invitation_expiry_value(
        &self,
        id: &Value,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<Invitation> {
        let id = self.organization_query(EntityRole::Invitation, "id", id.clone())?;
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
            *value = patch.apply(value.clone());
            value.clone()
        };
        self.output_invitation(result).await
    }
    async fn list_organization_invitations(&self, org: &str) -> AuthResult<Vec<Invitation>> {
        self.list_organization_invitations_value(&Value::from(org))
            .await
    }
    async fn list_organization_invitations_value(
        &self,
        org: &Value,
    ) -> AuthResult<Vec<Invitation>> {
        let org = self.organization_query(EntityRole::Invitation, "organizationId", org.clone())?;
        let schema = self.field_config(EntityRole::Invitation)?;
        let rows = self
            .lock()?
            .invitations
            .snapshot()?
            .into_iter()
            .filter(|row| {
                organization_value(row, &schema, "organizationId").strict_equals(&org.field_value())
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
        self.count_pending_organization_invitations_value(&org.into())
            .await
    }
    async fn count_pending_organization_invitations_value(&self, org: &Value) -> AuthResult<i64> {
        Ok(self.pending_invitation_rows(org, None).await?.len() as i64)
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
        let schema = self.field_config(EntityRole::Invitation)?;
        let selected = {
            let state = self.lock()?;
            state.invitations.select_refs(|row| {
                organization_value(row, &schema, "email").strict_equals(&email.field_value())
            })?
        };
        let rows = crate::query::paginate_memory(
            selected,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        self.output_record_refs_batches_then(
            EntityRole::Invitation,
            rows,
            |ready: Vec<(usize, Invitation)>| async move {
                let mut pending = Vec::new();
                let mut organizations = Vec::new();
                for (index, invitation) in ready {
                    let owner = invitation.organization_id.field_value();
                    let organization = if owner.is_null() || owner.is_undefined() {
                        None
                    } else {
                        let id = self.organization_primary_id(&invitation.organization_id)?;
                        self.lock()?
                            .organizations
                            .first_ref(|row| organization_id(row) == id)?
                    };
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
            },
        )
        .await
    }
}

impl EphemeralStore {
    pub(in crate::store::ephemeral) fn pending_invitation_selectors(
        &self,
        organization_id: &Value,
        email: Option<&str>,
    ) -> AuthResult<Vec<(String, Value)>> {
        let mut selectors = Vec::new();
        if let Some(email) = email {
            selectors.push(("email", Value::from(email.to_lowercase())));
        }
        selectors.extend([
            ("organizationId", organization_id.clone()),
            ("status", "pending".into()),
        ]);
        let schema = self.field_config(EntityRole::Invitation)?;
        selectors
            .into_iter()
            .map(|(name, value)| {
                let value = self
                    .organization_query(EntityRole::Invitation, name, value)?
                    .field_value();
                Ok((schema.record_storage_key(name).to_owned(), value))
            })
            .collect()
    }

    pub(in crate::store::ephemeral) fn matches_pending_invitation(
        row: &FieldMap,
        selectors: &[(String, Value)],
    ) -> bool {
        selectors.iter().all(|(name, value)| {
            crate::query::field_matches_equality(row.get(name).unwrap_or(&Value::Undefined), value)
        })
    }

    async fn pending_invitation_rows(
        &self,
        organization_id: &Value,
        email: Option<&str>,
    ) -> AuthResult<Vec<Invitation>> {
        let selectors = self.pending_invitation_selectors(organization_id, email)?;
        let rows = self
            .lock()?
            .invitations
            .select_refs(|row| Self::matches_pending_invitation(row, &selectors))?;
        self.project_pending_invitation_rows(rows).await
    }

    pub(in crate::store::ephemeral) async fn project_pending_invitation_rows(
        &self,
        rows: Vec<super::super::rows::RowRef<FieldMap>>,
    ) -> AuthResult<Vec<Invitation>> {
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        let rows = self
            .output_record_refs::<Invitation>(EntityRole::Invitation, rows)
            .await?;
        rows.into_iter()
            .try_fold(Vec::new(), |mut live, invitation| {
                if invitation
                    .expires_at
                    .clone()
                    .converted_date()?
                    .is_after(Utc::now())?
                {
                    live.push(invitation);
                }
                Ok(live)
            })
    }
}
