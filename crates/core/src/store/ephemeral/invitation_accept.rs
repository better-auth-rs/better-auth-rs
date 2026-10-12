use super::rows::RowRef;
use super::table::TableRef;
use super::*;
use crate::SchemaValue;
use crate::store::database_hooks::SessionUpdate;
use crate::store::{SessionWriteEffects, TeamMemberLimits};
use better_auth_schema_registry::EntityRole;

struct InvitationClaim {
    row: super::rows::RowRef<FieldMap>,
    fields: FieldMap,
    schema: crate::user_fields::UserConfig,
    selector_column: String,
}

fn validate_membership_allocations(
    live: &TableRef<FieldMap>,
    allocated: &[RowRef<FieldMap>],
) -> AuthResult<()> {
    for pending in allocated {
        let id = pending.field("id")?.unwrap_or_default();
        if !live
            .select_refs(|row| Ok(row.field("id")?.unwrap_or_default().same_value_zero(&id)))?
            .is_empty()
        {
            return Err(AuthError::conflict(
                "Member allocation changed while field transforms were pending",
            ));
        }
    }
    Ok(())
}

impl InvitationClaim {
    fn unchanged(&self, column: &str) -> AuthResult<bool> {
        Ok(super::rows::same_field_value(
            self.row.field(column)?.as_ref(),
            self.fields.get(column),
        ))
    }

    fn validate(
        &self,
        invitations: &TableRef<FieldMap>,
        changed_message: &'static str,
    ) -> AuthResult<()> {
        if !invitations.contains_ref(&self.row)? {
            return Err(AuthError::bad_request("Invitation not found"));
        }
        if !self.unchanged(&self.selector_column)? {
            return Err(AuthError::conflict(changed_message));
        }
        if !self.unchanged(self.schema.record_storage_key("status"))? {
            return Err(AuthError::bad_request("Invitation not found"));
        }
        for name in ["teamId", "organizationId", "role"] {
            if !self.unchanged(self.schema.record_storage_key(name))? {
                return Err(AuthError::conflict(changed_message));
            }
        }
        Ok(())
    }
}

impl EphemeralStore {
    pub(super) async fn accept_invitation(
        &self,
        invitation_id: &Value,
        user_id: &Value,
        session_token: Option<&crate::FieldValue>,
        teams_enabled: bool,
        maximum: TeamMemberLimits<'_>,
        effects: SessionWriteEffects<StatelessSchema>,
    ) -> AuthResult<(Member, Invitation, Option<SessionView>)> {
        let bound_id =
            self.organization_query_field(EntityRole::Invitation, "id", invitation_id.clone())?;
        let pending_status =
            self.organization_query_field(EntityRole::Invitation, "status", "pending".into())?;
        let patch = self
            .prepare_increment_one_patch(
                EntityRole::Invitation,
                [("status".into(), InvitationStatus::Accepted.into_field())]
                    .into_iter()
                    .collect(),
                FieldMap::new(),
            )
            .await?;
        let schema = self.field_config(EntityRole::Invitation)?;
        let claim = self.operation(|_| {
            let row = self
                .select_organization_rows(
                    EntityRole::Invitation,
                    &[bound_id.clone(), pending_status],
                )?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    AuthError::from_code(
                        "BAD_REQUEST",
                        "INVITATION_NOT_FOUND",
                        "Invitation not found",
                    )
                })?;
            row.apply_patch(patch.apply(FieldMap::new()))?;
            let fields = row.shallow_fields()?;
            Ok(InvitationClaim {
                row,
                fields,
                schema,
                selector_column: bound_id.0,
            })
        })?;
        // Claim output follows the committed claim and precedes the compensation boundary.
        let accepted = self.output_invitation(claim.fields.clone()).await?;
        match self
            .accept_invitation_members(
                (&claim, &accepted),
                user_id,
                session_token,
                teams_enabled,
                maximum,
                effects,
            )
            .await
        {
            Ok((member, session)) => Ok((member, accepted, session)),
            Err(error) => {
                self.restore_pending_invitation(&claim, invitation_id)
                    .await?;
                Err(error)
            }
        }
    }

    async fn restore_pending_invitation(
        &self,
        claim: &InvitationClaim,
        invitation_id: &Value,
    ) -> AuthResult<()> {
        let _id =
            self.organization_query_field(EntityRole::Invitation, "id", invitation_id.clone())?;
        let status =
            self.organization_query_field(EntityRole::Invitation, "status", "accepted".into())?;
        let patch = self
            .prepare_increment_one_patch(
                EntityRole::Invitation,
                [("status".into(), InvitationStatus::Pending.into_field())].into(),
                FieldMap::new(),
            )
            .await?;
        // Compensation retains the claimed row; a changed alias must not select a replacement row.
        let restored = self.operation(|op| {
            if op
                .capture_table(EntityRole::Invitation)?
                .contains_ref(&claim.row)?
                && super::organization_rows::matches(&claim.row, &[status])?
                && claim.unchanged(claim.schema.record_storage_key("status"))?
            {
                claim.row.apply_patch(patch.apply(FieldMap::new()))?;
                Ok(Some(claim.row.shallow_fields()?))
            } else {
                Ok(None)
            }
        })?;
        if let Some(row) = restored {
            let _ = self.output_invitation(row).await?;
        }
        Ok(())
    }

    async fn accept_invitation_members(
        &self,
        (claim, invitation): (&InvitationClaim, &Invitation),
        user_id: &Value,
        session_token: Option<&crate::FieldValue>,
        teams_enabled: bool,
        maximum: TeamMemberLimits<'_>,
        mut effects: SessionWriteEffects<StatelessSchema>,
    ) -> AuthResult<(Member, Option<SessionView>)> {
        let session_selector = session_token
            .filter(|_| effects.write_database())
            .map(|token| self.memory_session_token_query(token.clone()))
            .transpose()?;
        let member_user =
            self.organization_query_field(EntityRole::Member, "userId", user_id.clone())?;
        let member_org = self.organization_query_field(
            EntityRole::Member,
            "organizationId",
            invitation.organization_id.field_value(),
        )?;
        let team_id = invitation.team_id.field_value();
        let team_ids: Vec<_> = if teams_enabled && team_id.is_truthy() {
            team_id
                .as_str()
                .ok_or_else(|| AuthError::type_error("acceptedI.teamId.split is not a function"))?
                .split(',')
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
        };
        let team_fields = if team_ids.is_empty() {
            None
        } else {
            Some(self.organization_query_field(
                EntityRole::Team,
                "organizationId",
                invitation.organization_id.field_value(),
            )?)
        };
        let (mut transaction_base, staged, pending_hooks) = self.begin_adapter_transaction()?;
        let mut team_memberships = team_fields
            .map(|organization| {
                self.snapshot_table(&transaction_base, EntityRole::TeamMember)
                    .cloned()
                    .map(|base| (organization, base))
            })
            .transpose()?;
        let mut allocated_memberships = Vec::new();
        let mut team_checks = Vec::new();
        let mut reservations: Vec<(
            String,
            super::team_capacity::PreparedTeamSeats,
            Option<usize>,
        )> = Vec::new();
        if let Some((team_org, membership_base)) = &mut team_memberships {
            for team_id in &team_ids {
                let selector = Value::from(team_id.as_str());
                let bound_team_id =
                    self.organization_query_field(EntityRole::Team, "id", selector.clone())?;
                team_checks.push((team_id.clone(), bound_team_id.clone()));
                let pending: Vec<_> = reservations
                    .iter()
                    .map(|(_, prepared, _)| prepared.pending_write())
                    .collect();
                let _ = self
                    .read_team_details(
                        &selector,
                        Some(&invitation.organization_id.field_value()),
                        false,
                        &pending,
                    )
                    .await?
                    .ok_or_else(|| {
                        AuthError::from_code("BAD_REQUEST", "TEAM_NOT_FOUND", "Team not found")
                    })?
                    .into_public_parts(
                        maximum.team_output_fields().unwrap_or(&Default::default()),
                    )?;
                let limit = maximum
                    .maximum(team_id, &invitation.organization_id.field_value())
                    .await?;
                let key =
                    crate::organization_fields::team_membership_key_values(&selector, user_id)?;
                // Rebase only pending writes; observed live rows must not become transaction inserts.
                self.operation(|op| {
                    let observed = op.capture_table(EntityRole::TeamMember)?.shallow_copy()?;
                    if !reservations.is_empty()
                        && matches!(
                            self.config.advanced.database.generate_id(),
                            crate::id::IdGeneration::Serial
                        )
                        && observed.len()? != membership_base.len()?
                    {
                        return Err(AuthError::conflict(
                            "Member allocation changed while field transforms were pending",
                        ));
                    }
                    if matches!(
                        self.config.advanced.database.generate_id(),
                        crate::id::IdGeneration::Serial
                    ) {
                        validate_membership_allocations(&observed, &allocated_memberships)?;
                    }
                    let working =
                        staged.operation(|op| op.capture_table(EntityRole::TeamMember))?;
                    let memberships = observed.reconcile(membership_base, &working)?;
                    *membership_base = observed;
                    staged.operation(|op| op.replace_table(EntityRole::TeamMember, memberships))
                })?;
                if staged
                    .find_team_member_by_key_or_pair(&selector, user_id, &key)
                    .await?
                    .is_some()
                {
                    continue;
                }
                let selectors = self.team_member_selectors(&selector, None)?;
                let (team, actual) = self.operation(|_| {
                    let team = self
                        .select_organization_rows(
                            EntityRole::Team,
                            &[bound_team_id.clone(), team_org.clone()],
                        )?
                        .into_iter()
                        .next()
                        .ok_or_else(|| AuthError::bad_request("Team not found"))?;
                    let actual = self
                        .select_organization_rows(EntityRole::TeamMember, &selectors)?
                        .len();
                    Ok((team, actual))
                })?;
                let mut prepared = self
                    .prepare_team_reservation(team, bound_team_id, actual, limit)
                    .await?;
                if !prepared.reserved {
                    return Err(AuthError::from_code(
                        "FORBIDDEN",
                        "TEAM_MEMBER_LIMIT_REACHED",
                        "Team member limit reached",
                    ));
                }
                let before_create = staged
                    .operation(|op| op.capture_table(EntityRole::TeamMember)?.shallow_copy())?;
                let (_, created) = match staged
                    .create_team_member_with_key(&selector, user_id, &key)
                    .await
                {
                    Ok(result) => result,
                    Err(error) => {
                        if limit.is_some() {
                            self.release_prepared_team_seat(&mut prepared).await?;
                        }
                        return Err(error);
                    }
                };
                allocated_memberships.extend(staged.operation(|op| {
                    op.capture_table(EntityRole::TeamMember)?
                        .select_refs(|row| Ok(!before_create.contains_ref(row)?))
                })?);
                if limit.is_some() && !created {
                    self.release_prepared_team_seat(&mut prepared).await?;
                } else if limit.is_none() && created {
                    self.increment_prepared_team_seat(&mut prepared).await?;
                }
                reservations.push((team_id.clone(), prepared, limit));
            }
        }
        let member_selectors = [member_org, member_user];
        let member_count = self.operation(|op| {
            let state = op.capture_state()?;
            claim.validate(
                self.snapshot_table(&state, EntityRole::Invitation)?,
                "Invitation changed while capacity was being resolved",
            )?;
            if !self
                .snapshot_table(&state, EntityRole::Member)?
                .select_refs(|row| super::organization_rows::matches(row, &member_selectors))?
                .is_empty()
            {
                return Err(AuthError::bad_request("User is already a member"));
            }
            if let Some((column, token)) = &session_selector {
                let _ = self
                    .snapshot_table(&state, EntityRole::Session)?
                    .select_refs(|row| {
                        Ok(crate::query::field_matches_equality(
                            &row.field(column)?.unwrap_or_default(),
                            token,
                        ))
                    })?
                    .into_iter()
                    .next()
                    .ok_or(AuthError::SessionNotFound)?;
            }
            self.snapshot_table(&state, EntityRole::Member)?.len()
        })?;
        self.operation(|_| {
            let mut copies = crate::StructuredCloneContext::new();
            for (_, prepared, _) in &reservations {
                let (source, patch) = prepared.pending_write();
                let fields = source.shallow_fields()?;
                let mut fields = copies.clone_map(&fields)?;
                fields.extend(patch);
                let id = fields.get("id").cloned().unwrap_or_default();
                staged.operation(|op| {
                    let table = op.capture_table(EntityRole::Team)?;
                    let source = table
                        .select_refs(|row| {
                            Ok(row.field("id")?.unwrap_or_default().same_value_zero(&id))
                        })?
                        .into_iter()
                        .next();
                    match source {
                        Some(source) => source.replace(fields),
                        None => table.push(fields).map(|_| ()),
                    }
                })?;
            }
            Ok(())
        })?;
        let prepared_session = if let Some((column, token)) = &session_selector {
            Some(self.operation(|op| {
                let source = op
                    .capture_table(EntityRole::Session)?
                    .select_refs(|row| {
                        Ok(crate::query::field_matches_equality(
                            &row.field(column)?.unwrap_or_default(),
                            token,
                        ))
                    })?
                    .into_iter()
                    .next()
                    .ok_or(AuthError::SessionNotFound)?;
                let original = source.shallow_fields()?;
                Ok((source, original))
            })?)
        } else {
            None
        };
        let transaction = EphemeralTransaction {
            store: staged.clone(),
        };
        let cookie_session = if let (Some(token), [team_id]) = (session_token, team_ids.as_slice())
        {
            Some(
                transaction
                    .update_session_with_writer_by_token_value(
                        token,
                        SessionUpdate {
                            additional_fields: [("activeTeamId".into(), team_id.as_str().into())]
                                .into(),
                            ..Default::default()
                        },
                        effects
                            .secondary
                            .as_ref()
                            .map(|writer| writer.bind(token.clone())),
                    )
                    .await?
                    .ok_or_else(|| {
                        AuthError::type_error("Cannot read properties of null (reading 'token')")
                    })?,
            )
        } else {
            None
        };
        if let (Some(session), Some(effect)) = (&cookie_session, effects.after_output.take()) {
            effect(session.clone(), transaction.clone_handle()).await?;
        }
        let member = Member {
            field_order: Default::default(),
            additional_fields: Default::default(),
            id: Default::default(),
            organization_id: invitation.organization_id.clone(),
            user_id: SchemaValue::from_field(user_id.clone()),
            role: invitation.role.clone(),
            created_at: Utc::now().into(),
        };
        let member = staged
            .create_record(EntityRole::Member, member, FieldMap::new())
            .await?;
        let member = staged.insert_organization_row(EntityRole::Member, member)?;
        let output = staged
            .output_record_refs(EntityRole::Member, vec![member])
            .await?
            .remove(0);
        if let Some(token) = session_token {
            let _ = transaction
                .update_session_with_writer_by_token_value(
                    token,
                    SessionUpdate {
                        additional_fields: [(
                            "activeOrganizationId".into(),
                            invitation.organization_id.field_value(),
                        )]
                        .into(),
                        ..Default::default()
                    },
                    effects
                        .secondary
                        .as_ref()
                        .map(|writer| writer.bind(token.clone())),
                )
                .await?;
        }
        let committed = staged.prepare_transaction_commit()?;
        self.operation(|op| {
            let validate_common = |state: &State| -> AuthResult<()> {
                claim.validate(
                    self.snapshot_table(state, EntityRole::Invitation)?,
                    "Invitation changed while field transforms were pending",
                )?;
                if !self
                    .snapshot_table(state, EntityRole::Member)?
                    .select_refs(|row| super::organization_rows::matches(row, &member_selectors))?
                    .is_empty()
                {
                    return Err(AuthError::bad_request("User is already a member"));
                }
                if let Some((source, original)) = &prepared_session {
                    if !self
                        .snapshot_table(state, EntityRole::Session)?
                        .contains_ref(source)?
                    {
                        return Err(AuthError::SessionNotFound);
                    }
                    let row = source.shallow_fields()?;
                    if !row.keys().eq(original.keys())
                        || !row.iter().all(|(name, value)| {
                            original
                                .get(name)
                                .is_some_and(|original| value.same_value_zero(original))
                        })
                    {
                        return Err(AuthError::conflict(
                            "Session changed while field transforms were pending",
                        ));
                    }
                }
                Ok(())
            };
            let validate_allocations = |state: &State| -> AuthResult<()> {
                if matches!(
                    self.config.advanced.database.generate_id(),
                    crate::id::IdGeneration::Serial
                ) {
                    if self.snapshot_table(state, EntityRole::Member)?.len()? != member_count {
                        return Err(AuthError::conflict(
                            "Member allocation changed while field transforms were pending",
                        ));
                    }
                    if let Some((_, membership_base)) = &team_memberships {
                        let memberships = self.snapshot_table(state, EntityRole::TeamMember)?;
                        if memberships.len()? != membership_base.len()? {
                            return Err(AuthError::conflict(
                                "Member allocation changed while field transforms were pending",
                            ));
                        }
                        validate_membership_allocations(memberships, &allocated_memberships)?;
                    }
                }
                Ok(())
            };
            validate_common(&op.capture_state()?)?;
            let mut existing_guards = Vec::new();
            let mut reservation_guards = Vec::new();
            if let Some((team_org, _)) = &team_memberships {
                for (id, team_id) in &team_checks {
                    let team = op
                        .capture_table(EntityRole::Team)?
                        .select_refs(|row| {
                            super::organization_rows::matches(
                                row,
                                &[team_id.clone(), team_org.clone()],
                            )
                        })?
                        .into_iter()
                        .next()
                        .ok_or_else(|| AuthError::bad_request("Team not found"))?;
                    let selector = Value::from(id.as_str());
                    let key =
                        crate::organization_fields::team_membership_key_values(&selector, user_id)?;
                    let lookup = if !reservations
                        .iter()
                        .any(|(_, prepared, _)| prepared.same_team(&team))
                    {
                        let (existing, lookup) =
                            self.prepare_team_member_lookup(op, &selector, user_id, &key)?;
                        if existing.is_none() {
                            return Err(AuthError::conflict(
                                "Team membership changed while field transforms were pending",
                            ));
                        }
                        Some(lookup)
                    } else {
                        None
                    };
                    existing_guards.push(lookup);
                }
                for (id, prepared, maximum) in &reservations {
                    let team = prepared.current(&op.capture_table(EntityRole::Team)?)?;
                    if !team
                        .get(&team_org.0)
                        .unwrap_or(&Value::Undefined)
                        .strict_equals(&team_org.1)
                    {
                        return Err(AuthError::bad_request("Team not found"));
                    }
                    let selector = Value::from(id.as_str());
                    let selectors = self.team_member_selectors(&selector, None)?;
                    let actual = op
                        .capture_table(EntityRole::TeamMember)?
                        .select_refs(|row| Self::matches_team_member(row, &selectors))?
                        .len();
                    let key =
                        crate::organization_fields::team_membership_key_values(&selector, user_id)?;
                    let (existing, lookup) =
                        self.prepare_team_member_lookup(op, &selector, user_id, &key)?;
                    if existing.is_some() {
                        return Err(AuthError::conflict(
                            "Team membership changed while field transforms were pending",
                        ));
                    }
                    if maximum.is_some_and(|limit| actual >= limit) {
                        return Err(AuthError::forbidden("Team member limit reached"));
                    }
                    let _ = prepared.apply(&op.capture_table(EntityRole::Team)?, actual)?;
                    reservation_guards.push((selectors, lookup));
                }
            }
            validate_allocations(&op.capture_state()?)?;
            if let Some((_, membership_base)) = &team_memberships {
                let _ = transaction_base.tables.insert(
                    self.memory_model_name(EntityRole::TeamMember)?.to_owned(),
                    membership_base.clone(),
                );
            }
            let plan = committed.plan(op, &transaction_base)?;
            // Bound selectors and identity checks below do not invoke conversion or application callbacks.
            let current = op.capture_state()?;
            validate_common(&current)?;
            if let Some((team_org, _)) = &team_memberships {
                for ((_, team_id), lookup) in team_checks.iter().zip(existing_guards) {
                    let team = self
                        .snapshot_table(&current, EntityRole::Team)?
                        .select_refs(|row| {
                            super::organization_rows::matches(
                                row,
                                &[team_id.clone(), team_org.clone()],
                            )
                        })?
                        .into_iter()
                        .next()
                        .ok_or_else(|| AuthError::bad_request("Team not found"))?;
                    if let Some(lookup) = lookup {
                        if lookup
                            .find(self.snapshot_table(&current, EntityRole::TeamMember)?)?
                            .is_none()
                        {
                            return Err(AuthError::conflict(
                                "Team membership changed while field transforms were pending",
                            ));
                        }
                    } else if !reservations
                        .iter()
                        .any(|(_, prepared, _)| prepared.same_team(&team))
                    {
                        return Err(AuthError::conflict(
                            "Team changed while field transforms were pending",
                        ));
                    }
                }
                for ((_, prepared, maximum), (selectors, lookup)) in
                    reservations.iter().zip(reservation_guards)
                {
                    let team =
                        prepared.current(self.snapshot_table(&current, EntityRole::Team)?)?;
                    if !team
                        .get(&team_org.0)
                        .unwrap_or(&Value::Undefined)
                        .strict_equals(&team_org.1)
                    {
                        return Err(AuthError::bad_request("Team not found"));
                    }
                    let actual = self
                        .snapshot_table(&current, EntityRole::TeamMember)?
                        .select_refs(|row| Self::matches_team_member(row, &selectors))?
                        .len();
                    if lookup
                        .find(self.snapshot_table(&current, EntityRole::TeamMember)?)?
                        .is_some()
                    {
                        return Err(AuthError::conflict(
                            "Team membership changed while field transforms were pending",
                        ));
                    }
                    if maximum.is_some_and(|limit| actual >= limit) {
                        return Err(AuthError::forbidden("Team member limit reached"));
                    }
                    let _ =
                        prepared.apply(self.snapshot_table(&current, EntityRole::Team)?, actual)?;
                }
            }
            validate_allocations(&current)?;
            plan.publish(op)
        })?;
        self.drain_transaction_hooks(&pending_hooks).await?;
        Ok((output, cookie_session))
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]
mod tests {
    use super::*;
    use crate::{
        id::IdGeneration,
        organization_fields::OrganizationFields,
        user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Barrier;

    #[tokio::test]
    async fn concurrent_serial_acceptance_preserves_projected_output_without_callback_replay()
    -> AuthResult<()> {
        let mut config = (*test_config()).clone();
        config.advanced.database.generate_id = Some(IdGeneration::Serial);
        let store = EphemeralStore::new(Arc::new(config));
        store.operation(|op| {
            op.replace_physical_table("team".into(), None)?;
            op.replace_physical_table("teamMember".into(), None)
        })?;
        let first = store
            .create_invitation(CreateInvitation::new(
                "1",
                "first@example.com",
                "member",
                "3",
                (Utc::now() + chrono::Duration::days(1)).into(),
            ))
            .await?;
        let second = store
            .create_invitation(CreateInvitation::new(
                "1",
                "second@example.com",
                "member",
                "3",
                (Utc::now() + chrono::Duration::days(1)).into(),
            ))
            .await?;
        let calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(2));
        let mut fields = OrganizationFields::default();
        let _ = fields.member.fields_mut().insert(
            "role".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new_async({
                        let calls = calls.clone();
                        move |value| {
                            let calls = calls.clone();
                            let barrier = barrier.clone();
                            async move {
                                let _ = calls.fetch_add(1, Ordering::SeqCst);
                                assert_eq!(value, Value::from("member"));
                                barrier.wait().await;
                                Ok(Value::from("visible-member"))
                            }
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        store.configure_organization_fields(fields)?;
        let (a, b) = tokio::join!(
            store.accept_invitation_with_teams(
                first.id.typed()?,
                "1",
                None,
                false,
                TeamMemberLimits::Fixed(None)
            ),
            store.accept_invitation_with_teams(
                second.id.typed()?,
                "2",
                None,
                false,
                TeamMemberLimits::Fixed(None)
            ),
        );
        let (winner, rejected) = if a.is_ok() { (a, b) } else { (b, a) };
        let (member, _, _) = winner?;
        assert_eq!(member.id, "1");
        assert_eq!(member.role, "visible-member");
        assert!(matches!(rejected, Err(AuthError::Conflict(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let state = store.operation(|op| op.capture_state())?;
        assert_eq!(state.fixture_table("member").len()?, 1);
        assert_eq!(
            state.fixture_table("member").snapshot()?[0]["id"],
            Value::Number(1.0)
        );
        assert_eq!(
            state.fixture_table("member").snapshot()?[0]["role"],
            Value::from("member")
        );
        let invitations = state.fixture_table("invitation").snapshot()?;
        assert_eq!(
            invitations
                .iter()
                .filter(|row| row.get("status") == Some(&Value::from("pending")))
                .count(),
            1
        );
        assert_eq!(
            invitations
                .iter()
                .filter(|row| row.get("status") == Some(&Value::from("accepted")))
                .count(),
            1
        );
        assert!(!state.tables.contains_key("team"));
        assert!(!state.tables.contains_key("teamMember"));
        assert_eq!(state.fixture_table("session").len()?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn session_cookie_projection_failure_or_replacement_keeps_acceptance_atomic()
    -> AuthResult<()> {
        use crate::store::TeamStore;
        for mode in ["team-failure", "organization-failure", "replace"] {
            let replace = mode == "replace";
            let writer = EphemeralStore::new(test_config());
            let team = writer
                .create_team(crate::CreateTeam {
                    name: "Session projection team".into(),
                    organization_id: "organization".into(),
                    ..Default::default()
                })
                .await?;
            let mut invitation = CreateInvitation::new(
                "organization",
                "recipient@example.com",
                "member",
                "inviter",
                (Utc::now() + chrono::Duration::days(1)).into(),
            );
            invitation.team_id = Some(team.id.typed()?.clone());
            let invitation = writer.create_invitation(invitation).await?;
            let session = writer
                .create_session(CreateSession {
                    inherited_fields: FieldMap::new(),
                    additional_fields: [("token".into(), "invitation-session".into())].into(),
                    user_id: "recipient".into(),
                    expires_at: (Utc::now() + chrono::Duration::days(1)).into(),
                    ip_address: None,
                    user_agent: None,
                    impersonated_by: None,
                    active_organization_id: None,
                })
                .await?;
            let original = writer
                .operation(|op| op.capture_state())?
                .fixture_table("session")
                .snapshot()?;
            let original_team = writer
                .operation(|op| op.capture_state())?
                .fixture_table("team")
                .snapshot()?;
            let calls = Arc::new(AtomicUsize::new(0));
            let mut reader = writer.clone();
            let _ = reader.session_config.fields_mut().insert(
                "activeTeamId".into(),
                UserFieldConfig {
                    field_name: Some("currentTeam".into()),
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new({
                            let writer = writer.clone();
                            let calls = calls.clone();
                            let team_id = team.id.field_value();
                            move |value| {
                                let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
                                assert_eq!(value, team_id);
                                if mode == "team-failure"
                                    || (mode == "organization-failure" && call == 2)
                                {
                                    return Err(AuthError::internal(
                                        "Session cookie projection failed",
                                    ));
                                }
                                if !replace {
                                    return Ok(value);
                                }
                                writer.operation(|op| {
                                    let table = op.capture_table(EntityRole::Session)?;
                                    let source = table
                                        .select_refs(|row| {
                                            Ok(row.field("token")?
                                                == Some(Value::from("invitation-session")))
                                        })?
                                        .into_iter()
                                        .next()
                                        .ok_or(AuthError::SessionNotFound)?;
                                    let mut replacement = source.shallow_fields()?;
                                    let _ = replacement
                                        .insert("ipAddress".into(), "concurrent-writer".into());
                                    let replacement_table =
                                        table.without_refs(std::slice::from_ref(&source))?;
                                    let _ = replacement_table.push(replacement)?;
                                    op.replace_table(EntityRole::Session, replacement_table)
                                })?;
                                Ok(value)
                            }
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            let result = reader
                .accept_invitation_with_teams(
                    invitation.id.typed()?,
                    "recipient",
                    Some(session.token.typed()?),
                    true,
                    TeamMemberLimits::Fixed(Some(1)),
                )
                .await;
            if replace {
                assert!(matches!(result, Err(AuthError::SessionNotFound)));
            } else {
                assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message == "Session cookie projection failed")
                );
            }
            assert_eq!(
                calls.load(Ordering::SeqCst),
                if mode == "team-failure" { 1 } else { 2 }
            );
            let state = writer.operation(|op| op.capture_state())?;
            assert_eq!(state.fixture_table("member").len()?, 0);
            assert_eq!(state.fixture_table("teamMember").len()?, 0);
            assert_eq!(state.fixture_table("team").snapshot()?, original_team);
            let mut expected = original;
            if replace {
                let _ = expected[0].insert("ipAddress".into(), "concurrent-writer".into());
            }
            assert_eq!(state.fixture_table("session").snapshot()?, expected);
            assert_eq!(
                state.fixture_table("invitation").snapshot()?[0]["status"],
                Value::from("pending")
            );
        }
        Ok(())
    }
}
