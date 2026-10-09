use super::rows::RecordSource;
use super::sessions::session_token_matches;
use super::*;
use crate::SchemaValue;
use crate::store::TeamMemberLimits;
use better_auth_schema_registry::EntityRole;

struct InvitationClaim {
    row: super::rows::RowRef<FieldMap>,
    fields: FieldMap,
    schema: crate::user_fields::UserConfig,
}

impl InvitationClaim {
    fn validate(&self, state: &State, changed_message: &'static str) -> AuthResult<()> {
        if !state.invitations.contains_ref(&self.row) {
            return Err(AuthError::bad_request("Invitation not found"));
        }
        self.row.read(|fields| {
            if !organization_value(fields, &self.schema, "status").strict_equals(&"accepted".into())
            {
                return Err(AuthError::bad_request("Invitation not found"));
            }
            if ["teamId", "organizationId", "role"].iter().any(|name| {
                organization_value(fields, &self.schema, name)
                    != organization_value(&self.fields, &self.schema, name)
            }) {
                return Err(AuthError::conflict(changed_message));
            }
            Ok(())
        })
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
    ) -> AuthResult<(Member, Invitation, Option<SessionView>)> {
        let bound_id =
            self.organization_query(EntityRole::Invitation, "id", invitation_id.clone())?;
        let patch = self
            .prepare_record_patch(
                EntityRole::Invitation,
                [("status".into(), InvitationStatus::Accepted.into_field())]
                    .into_iter()
                    .collect(),
                FieldMap::new(),
            )
            .await?;
        let schema = self.field_config(EntityRole::Invitation)?;
        let claim = {
            let state = self.lock()?;
            let row = state
                .invitations
                .first_ref(|row| {
                    organization_id(row) == bound_id
                        && organization_value(row, &schema, "status")
                            .strict_equals(&"pending".into())
                })?
                .ok_or_else(|| AuthError::bad_request("Invitation not found"))?;
            let fields = row.write(|fields| {
                *fields = patch.apply(fields.clone());
                Ok(fields.clone())
            })?;
            InvitationClaim {
                row,
                fields,
                schema,
            }
        };
        // Claim output follows the committed claim and precedes the compensation boundary.
        let accepted = self.output_invitation(claim.fields.clone()).await?;
        match self
            .accept_invitation_members(
                &claim,
                &accepted,
                user_id,
                session_token,
                teams_enabled,
                maximum,
            )
            .await
        {
            Ok((member, session)) => Ok((member, accepted, session)),
            Err(error) => {
                self.restore_pending_invitation(&claim).await?;
                Err(error)
            }
        }
    }

    async fn restore_pending_invitation(&self, claim: &InvitationClaim) -> AuthResult<()> {
        {
            let state = self.lock()?;
            if !state.invitations.contains_ref(&claim.row)
                || !claim.row.read(|row| {
                    Ok(organization_value(row, &claim.schema, "status")
                        .strict_equals(&"accepted".into()))
                })?
            {
                return Ok(());
            }
        }
        let patch = self
            .prepare_record_patch(
                EntityRole::Invitation,
                [("status".into(), InvitationStatus::Pending.into_field())].into(),
                FieldMap::new(),
            )
            .await?;
        let restored = {
            let state = self.lock()?;
            if state.invitations.contains_ref(&claim.row) {
                claim.row.write(|row| {
                    if organization_value(row, &claim.schema, "status")
                        .strict_equals(&"accepted".into())
                    {
                        *row = patch.apply(row.clone());
                        Ok(Some(row.clone()))
                    } else {
                        Ok(None)
                    }
                })?
            } else {
                None
            }
        };
        if let Some(row) = restored {
            let _ = self.output_invitation(row).await?;
        }
        Ok(())
    }

    async fn accept_invitation_members(
        &self,
        claim: &InvitationClaim,
        invitation: &Invitation,
        user_id: &Value,
        session_token: Option<&crate::FieldValue>,
        teams_enabled: bool,
        maximum: TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Option<SessionView>)> {
        let member_schema = self.field_config(EntityRole::Member)?;
        let team_schema = self.field_config(EntityRole::Team)?;
        let session_token = session_token
            .map(|token| self.memory_session_token_query(token.clone()))
            .transpose()?;
        let member_user = self.organization_query(EntityRole::Member, "userId", user_id.clone())?;
        let member_org = self.organization_reference_query(
            EntityRole::Member,
            "organizationId",
            &invitation.organization_id,
        )?;
        let team_org = self.organization_reference_query(
            EntityRole::Team,
            "organizationId",
            &invitation.organization_id,
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
        let mut limits = HashMap::new();
        for team_id in &team_ids {
            let _team = self
                .lock()?
                .teams
                .get(&self.organization_query(
                    EntityRole::Team,
                    "id",
                    Value::from(team_id.as_str()),
                )?)?
                .filter(|team| {
                    organization_value(team, &team_schema, "organizationId")
                        .strict_equals(&team_org.field_value())
                })
                .ok_or_else(|| AuthError::bad_request("Team not found"))?;
            let limit = maximum
                .maximum(team_id, &invitation.organization_id.field_value())
                .await?;
            let selector = Value::from(team_id.as_str());
            let selectors = self.team_member_selectors(&selector, None)?;
            let key = crate::organization_fields::team_membership_key_values(&selector, user_id)?;
            let existing = self
                .find_team_member_by_key_or_pair(&selector, user_id, &key)
                .await?;
            let members = self.lock()?.team_members.snapshot()?;
            if existing.is_none()
                && limit.is_some_and(|limit| {
                    members
                        .iter()
                        .filter(|row| Self::matches_team_member(row, &selectors))
                        .count()
                        >= limit
                })
            {
                return Err(AuthError::forbidden("Team member limit reached"));
            }
            let _ = limits.insert(team_id.clone(), limit);
        }
        let member_count = {
            let state = self.lock()?;
            claim.validate(
                &state,
                "Invitation changed while capacity was being resolved",
            )?;
            if state.members.snapshot()?.iter().any(|row| {
                organization_value(row, &member_schema, "organizationId")
                    .strict_equals(&member_org.field_value())
                    && organization_value(row, &member_schema, "userId")
                        .strict_equals(&member_user.field_value())
            }) {
                return Err(AuthError::bad_request("User is already a member"));
            }
            if let Some((column, token)) = &session_token {
                let _ = state
                    .sessions
                    .find(|row| session_token_matches(row, column, token))?
                    .ok_or(AuthError::SessionNotFound)?;
            }
            state.members.len()
        };
        let mut reservations = Vec::new();
        for team_id in &team_ids {
            if reservations.iter().any(|(id, _)| id == team_id) {
                continue;
            }
            let bound_team_id =
                self.organization_query(EntityRole::Team, "id", Value::from(team_id.as_str()))?;
            let (team, members) = {
                let state = self.lock()?;
                (
                    state
                        .teams
                        .first_ref(|row| {
                            organization_id(row) == bound_team_id
                                && organization_value(row, &team_schema, "organizationId")
                                    .strict_equals(&team_org.field_value())
                        })?
                        .ok_or_else(|| AuthError::bad_request("Team not found"))?,
                    state.team_members.snapshot()?,
                )
            };
            let selector = Value::from(team_id.as_str());
            let selectors = self.team_member_selectors(&selector, None)?;
            let key = crate::organization_fields::team_membership_key_values(&selector, user_id)?;
            if self
                .find_team_member_by_key_or_pair(&selector, user_id, &key)
                .await?
                .is_some()
            {
                continue;
            }
            let actual = members
                .iter()
                .filter(|row| Self::matches_team_member(row, &selectors))
                .count();
            let maximum = *limits
                .get(team_id)
                .ok_or_else(|| AuthError::internal("Invitation team capacity was not resolved"))?;
            let prepared = self.prepare_team_reservation(team, actual, maximum).await?;
            if !prepared.reserved {
                return Err(AuthError::forbidden("Team member limit reached"));
            }
            reservations.push((team_id.clone(), prepared));
        }
        let (membership_base, staged_memberships, _membership_queue) = self.begin_transaction()?;
        for (team_id, prepared) in &mut reservations {
            let selector = Value::from(team_id.as_str());
            let key = crate::organization_fields::team_membership_key_values(&selector, user_id)?;
            let maximum = *limits
                .get(team_id)
                .ok_or_else(|| AuthError::internal("Invitation team capacity was not resolved"))?;
            let (_, created) = match staged_memberships
                .create_team_member_with_key(&selector, user_id, &key)
                .await
            {
                Ok(result) => result,
                Err(error) => {
                    if maximum.is_some() {
                        self.release_prepared_team_seat(prepared).await?;
                    }
                    return Err(error);
                }
            };
            if maximum.is_some() && !created {
                self.release_prepared_team_seat(prepared).await?;
            } else if maximum.is_none() && created {
                self.increment_prepared_team_seat(prepared).await?;
            }
        }
        let team_patch = if session_token.is_some() {
            if let [team_id] = team_ids.as_slice() {
                Some(
                    self.bind_session_update_fields(
                        [("activeTeamId".into(), team_id.as_str().into())].into(),
                    )
                    .await?,
                )
            } else {
                None
            }
        } else {
            None
        };
        let mut prepared_session = if let Some((column, token)) = &session_token {
            let source = self
                .lock()?
                .sessions
                .first_ref(|row| session_token_matches(row, column, token))?
                .ok_or(AuthError::SessionNotFound)?;
            let original = source.read(|row| Ok(row.clone()))?;
            let mut fields = original.clone();
            let cookie = if let Some(patch) = &team_patch {
                fields.extend(patch.clone());
                Some(
                    self.output_session(RecordSource::Snapshot(Box::new(fields.clone())))
                        .await?,
                )
            } else {
                None
            };
            Some((source, original, fields, cookie))
        } else {
            None
        };
        let member = Member {
            field_order: Default::default(),
            additional_fields: Default::default(),
            id: Default::default(),
            organization_id: invitation.organization_id.clone(),
            user_id: SchemaValue::from_field(user_id.clone()),
            role: invitation.role.clone(),
            created_at: Utc::now().into(),
        };
        let mut member = self
            .create_record(EntityRole::Member, member, FieldMap::new())
            .await?;
        if let Some(id) = self.next_serial_id(member_count) {
            let _ = member.insert("id".into(), id);
        }
        let output = self.output_member(member.clone()).await?;
        if let Some((_, _, fields, _)) = &mut prepared_session {
            let patch = self
                .bind_session_update_fields(
                    [(
                        "activeOrganizationId".into(),
                        invitation.organization_id.field_value(),
                    )]
                    .into(),
                )
                .await?;
            fields.extend(patch);
            let _ = self
                .output_session(RecordSource::Snapshot(Box::new(fields.clone())))
                .await?;
        }
        let mut state = self.lock()?;
        claim.validate(
            &state,
            "Invitation changed while field transforms were pending",
        )?;
        if state.members.snapshot()?.iter().any(|row| {
            organization_value(row, &member_schema, "organizationId")
                .strict_equals(&member_org.field_value())
                && organization_value(row, &member_schema, "userId")
                    .strict_equals(&member_user.field_value())
        }) {
            return Err(AuthError::bad_request("User is already a member"));
        }
        if let Some((source, original, _, _)) = &prepared_session {
            if !state.sessions.contains_ref(source) {
                return Err(AuthError::SessionNotFound);
            }
            let unchanged = source.read(|row| {
                Ok(row.keys().eq(original.keys())
                    && row.iter().all(|(name, value)| {
                        original
                            .get(name)
                            .is_some_and(|original| value.same_value_zero(original))
                    }))
            })?;
            if !unchanged {
                return Err(AuthError::conflict(
                    "Session changed while field transforms were pending",
                ));
            }
        }
        let current_members = state.team_members.snapshot()?;
        for id in &team_ids {
            let _team = state
                .teams
                .get(&self.organization_query(EntityRole::Team, "id", Value::from(id.as_str()))?)?
                .filter(|team| {
                    organization_value(team, &team_schema, "organizationId")
                        .strict_equals(&team_org.field_value())
                })
                .ok_or_else(|| AuthError::bad_request("Team not found"))?;
            let selector = Value::from(id.as_str());
            let key = crate::organization_fields::team_membership_key_values(&selector, user_id)?;
            if !reservations.iter().any(|(reserved, _)| reserved == id)
                && self
                    .team_member_by_key_or_pair(&state, &selector, user_id, &key)?
                    .is_none()
            {
                return Err(AuthError::conflict(
                    "Team membership changed while field transforms were pending",
                ));
            }
        }
        let mut teams = Vec::new();
        for (id, prepared) in reservations {
            let team = prepared.current(&state.teams)?;
            if !organization_value(&team, &team_schema, "organizationId")
                .strict_equals(&team_org.field_value())
            {
                return Err(AuthError::bad_request("Team not found"));
            }
            let selector = Value::from(id.as_str());
            let selectors = self.team_member_selectors(&selector, None)?;
            let actual = current_members
                .iter()
                .filter(|row| Self::matches_team_member(row, &selectors))
                .count();
            let key = crate::organization_fields::team_membership_key_values(&selector, user_id)?;
            if self
                .team_member_by_key_or_pair(&state, &selector, user_id, &key)?
                .is_some()
            {
                return Err(AuthError::conflict(
                    "Team membership changed while field transforms were pending",
                ));
            }
            let maximum = *limits
                .get(&id)
                .ok_or_else(|| AuthError::internal("Invitation team capacity was not resolved"))?;
            if maximum.is_some_and(|limit| actual >= limit) {
                return Err(AuthError::forbidden("Team member limit reached"));
            }
            teams.push(prepared.apply(&state.teams, actual)?);
        }
        // Validate the complete staged result before publishing any member, seat, or session delta.
        if matches!(
            self.config.advanced.database.generate_id(),
            crate::id::IdGeneration::Serial
        ) && (state.members.len() != member_count
            || state.team_members.len() != membership_base.team_members.len())
        {
            return Err(AuthError::conflict(
                "Member allocation changed while field transforms were pending",
            ));
        }
        state.team_members.merge(
            &membership_base.team_members,
            staged_memberships.lock()?.team_members.clone(),
        )?;
        for (source, fields) in teams {
            source.write(|row| {
                *row = fields;
                Ok(())
            })?;
        }
        state.members.push(member);
        let cookie_session = if let Some((source, _, fields, cookie)) = prepared_session {
            source.write(|row| {
                *row = fields;
                Ok(())
            })?;
            cookie
        } else {
            None
        };
        Ok((output, cookie_session))
    }
}

#[cfg(test)]
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
        let state = store.lock()?;
        assert_eq!(state.members.len(), 1);
        assert_eq!(state.members.snapshot()?[0]["id"], Value::Number(1.0));
        assert_eq!(state.members.snapshot()?[0]["role"], Value::from("member"));
        let invitations = state.invitations.snapshot()?;
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
        assert_eq!(state.team_members.len(), 0);
        assert_eq!(state.sessions.len(), 0);
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
            let original = writer.lock()?.sessions.snapshot()?;
            let original_team = writer.lock()?.teams.snapshot()?;
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
                                let mut state = writer.lock()?;
                                let source = state
                                    .sessions
                                    .first_ref(|row| {
                                        row.get("token") == Some(&Value::from("invitation-session"))
                                    })?
                                    .ok_or(AuthError::SessionNotFound)?;
                                let mut replacement = state
                                    .sessions
                                    .remove_ref(&source)?
                                    .ok_or(AuthError::SessionNotFound)?;
                                let _ = replacement
                                    .insert("ipAddress".into(), "concurrent-writer".into());
                                state.sessions.push(replacement);
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
            let state = writer.lock()?;
            assert_eq!(state.members.len(), 0);
            assert_eq!(state.team_members.len(), 0);
            assert_eq!(state.teams.snapshot()?, original_team);
            let mut expected = original;
            if replace {
                let _ = expected[0].insert("ipAddress".into(), "concurrent-writer".into());
            }
            assert_eq!(state.sessions.snapshot()?, expected);
            assert_eq!(
                state.invitations.snapshot()?[0]["status"],
                Value::from("pending")
            );
        }
        Ok(())
    }
}
