use super::sessions::session_token_matches;
use super::*;
use crate::store::TeamMemberLimits;
use crate::{SchemaValue, TeamMember};
use better_auth_schema_registry::EntityRole;

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
        let invitation = {
            let state = self.lock()?;
            let mut row = state
                .invitations
                .get_mut(&bound_id)?
                .filter(|row| row.is_pending())
                .ok_or_else(|| AuthError::bad_request("Invitation not found"))?;
            *row = patch.apply(row.clone())?;
            row.clone()
        };
        // Claim output follows the committed claim and precedes the compensation boundary.
        let accepted = self.output_invitation(invitation.clone()).await?;
        match self
            .accept_invitation_members(
                &invitation,
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
                self.restore_pending_invitation(invitation_id).await?;
                Err(error)
            }
        }
    }

    async fn restore_pending_invitation(&self, id: &Value) -> AuthResult<()> {
        let id = self.organization_query(EntityRole::Invitation, "id", id.clone())?;
        if !self
            .lock()?
            .invitations
            .get(&id)?
            .is_some_and(|row| row.status == InvitationStatus::Accepted)
        {
            return Ok(());
        }
        let patch = self
            .prepare_record_patch(
                EntityRole::Invitation,
                [("status".into(), InvitationStatus::Pending.into_field())]
                    .into_iter()
                    .collect(),
                FieldMap::new(),
            )
            .await?;
        let restored = {
            let state = self.lock()?;
            if let Some(mut row) = state
                .invitations
                .get_mut(&id)?
                .filter(|row| row.status == InvitationStatus::Accepted)
            {
                *row = patch.apply(row.clone())?;
                Some(row.clone())
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
        claim: &Invitation,
        invitation: &Invitation,
        user_id: &Value,
        session_token: Option<&crate::FieldValue>,
        teams_enabled: bool,
        maximum: TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Option<SessionView>)> {
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
        let team_user = self.memory_reference_id_input(user_id.clone())?;
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
            let team = self
                .lock()?
                .teams
                .get(&self.organization_query(
                    EntityRole::Team,
                    "id",
                    Value::from(team_id.as_str()),
                )?)?
                .filter(|team| team.organization_id == team_org)
                .ok_or_else(|| AuthError::bad_request("Team not found"))?;
            let limit = maximum
                .maximum(team_id, &invitation.organization_id.field_value())
                .await?;
            let members = self.lock()?.team_members.snapshot()?;
            if !members.iter().any(|row| {
                row.team_id
                    .field_value()
                    .strict_equals(&team.id.field_value())
                    && row
                        .user_id
                        .field_value()
                        .strict_equals(&team_user.field_value())
            }) && limit.is_some_and(|limit| {
                members.iter().filter(|row| row.team_id == team.id).count() >= limit
            }) {
                return Err(AuthError::forbidden("Team member limit reached"));
            }
            let _ = limits.insert(team_id.clone(), limit);
        }
        let (member_count, team_member_count) = {
            let state = self.lock()?;
            let current = state
                .invitations
                .get(&claim.id)?
                .filter(|row| row.status == InvitationStatus::Accepted)
                .ok_or_else(|| AuthError::bad_request("Invitation not found"))?;
            if current.team_id != claim.team_id
                || current.organization_id != claim.organization_id
                || current.role != claim.role
            {
                return Err(AuthError::conflict(
                    "Invitation changed while capacity was being resolved",
                ));
            }
            if state.members.snapshot()?.iter().any(|row| {
                row.organization_id
                    .field_value()
                    .strict_equals(&member_org.field_value())
                    && row
                        .user_id
                        .field_value()
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
            (state.members.len(), state.team_members.len())
        };
        let mut reservations = Vec::new();
        let mut memberships = Vec::new();
        for team_id in &team_ids {
            if reservations.iter().any(|(id, _)| id == team_id) {
                continue;
            }
            let (team, members) = {
                let state = self.lock()?;
                (
                    state
                        .teams
                        .get(&self.organization_query(
                            EntityRole::Team,
                            "id",
                            Value::from(team_id.as_str()),
                        )?)?
                        .filter(|team| team.organization_id == team_org)
                        .ok_or_else(|| AuthError::bad_request("Team not found"))?,
                    state.team_members.snapshot()?,
                )
            };
            if members.iter().any(|row| {
                row.team_id
                    .field_value()
                    .strict_equals(&team.id.field_value())
                    && row
                        .user_id
                        .field_value()
                        .strict_equals(&team_user.field_value())
            }) {
                continue;
            }
            let actual = members.iter().filter(|row| row.team_id == team.id).count();
            let maximum = *limits
                .get(team_id)
                .ok_or_else(|| AuthError::internal("Invitation team capacity was not resolved"))?;
            let prepared = self.prepare_team_reservation(team, actual, maximum).await?;
            if !prepared.reserved {
                return Err(AuthError::forbidden("Team member limit reached"));
            }
            reservations.push((team_id.clone(), prepared));
        }
        let member = Member {
            additional_fields: Default::default(),
            id: self
                .generated_id("member", None, member_count)?
                .map(SchemaValue::Typed)
                .unwrap_or_default(),
            organization_id: invitation.organization_id.clone(),
            user_id: SchemaValue::from_field(user_id.clone()),
            role: invitation.role.clone(),
            created_at: Utc::now().into(),
        };
        let mut member: Member = self
            .store_record(EntityRole::Member, member, None, FieldMap::new())
            .await?;
        if let Some(id) = self.next_serial_id(member_count) {
            member.id = SchemaValue::from_field(id);
        }
        let output = self.output_member(member.clone()).await?;
        for (team_id, _) in &reservations {
            memberships.push(TeamMember {
                id: self
                    .generated_id("teamMember", None, team_member_count + memberships.len())?
                    .map(SchemaValue::Typed)
                    .unwrap_or_default(),
                team_id: self.organization_query(
                    EntityRole::Team,
                    "id",
                    Value::from(team_id.as_str()),
                )?,
                user_id: team_user.clone(),
                created_at: Utc::now().into(),
            });
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
        let organization_patch = if session_token.is_some() {
            Some(
                self.bind_session_update_fields(
                    [(
                        "activeOrganizationId".into(),
                        invitation.organization_id.field_value(),
                    )]
                    .into(),
                )
                .await?,
            )
        } else {
            None
        };
        let mut state = self.lock()?;
        let current = state
            .invitations
            .get(&claim.id)?
            .filter(|row| row.status == InvitationStatus::Accepted)
            .ok_or_else(|| AuthError::bad_request("Invitation not found"))?;
        if current.team_id != claim.team_id
            || current.organization_id != claim.organization_id
            || current.role != claim.role
        {
            return Err(AuthError::conflict(
                "Invitation changed while field transforms were pending",
            ));
        }
        if state.members.snapshot()?.iter().any(|row| {
            row.organization_id
                .field_value()
                .strict_equals(&member_org.field_value())
                && row
                    .user_id
                    .field_value()
                    .strict_equals(&member_user.field_value())
        }) {
            return Err(AuthError::bad_request("User is already a member"));
        }
        let session = session_token
            .as_ref()
            .map(|(column, token)| {
                state
                    .sessions
                    .find(|row| session_token_matches(row, column, token))?
                    .ok_or(AuthError::SessionNotFound)
            })
            .transpose()?;
        let current_members = state.team_members.snapshot()?;
        for id in &team_ids {
            let team = state
                .teams
                .get(&self.organization_query(EntityRole::Team, "id", Value::from(id.as_str()))?)?
                .filter(|team| team.organization_id == team_org)
                .ok_or_else(|| AuthError::bad_request("Team not found"))?;
            if !reservations.iter().any(|(reserved, _)| reserved == id)
                && !current_members.iter().any(|row| {
                    row.team_id
                        .field_value()
                        .strict_equals(&team.id.field_value())
                        && row
                            .user_id
                            .field_value()
                            .strict_equals(&team_user.field_value())
                })
            {
                return Err(AuthError::conflict(
                    "Team membership changed while field transforms were pending",
                ));
            }
        }
        let mut teams = Vec::new();
        for (id, prepared) in reservations {
            let team = state
                .teams
                .get(&self.organization_query(EntityRole::Team, "id", Value::from(id.as_str()))?)?
                .filter(|team| team.organization_id == team_org)
                .ok_or_else(|| AuthError::bad_request("Team not found"))?;
            let actual = current_members
                .iter()
                .filter(|row| row.team_id == team.id)
                .count();
            if current_members.iter().any(|row| {
                row.team_id
                    .field_value()
                    .strict_equals(&team.id.field_value())
                    && row
                        .user_id
                        .field_value()
                        .strict_equals(&team_user.field_value())
            }) {
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
            teams.push((team.id.clone(), prepared.apply(team, actual)?));
        }
        // Validate the complete staged result before publishing any member, seat, or session delta.
        let (session, cookie_session) = if let Some(mut session) = session {
            let cookie_session = if let Some(fields) = &team_patch {
                self.apply_session_storage_fields(&mut session, fields);
                let mut cookie = session.clone();
                cookie.id = Self::project_id(&cookie.id)?;
                if !self.session_config.fields().contains_key("userId") {
                    cookie.user_id = Self::project_id(&cookie.user_id)?;
                }
                Some(cookie)
            } else {
                None
            };
            if let Some(fields) = &organization_patch {
                self.apply_session_storage_fields(&mut session, fields);
            }
            (Some(session), cookie_session)
        } else {
            (None, None)
        };
        if matches!(
            self.config.advanced.database.generate_id(),
            crate::id::IdGeneration::Serial
        ) && state.members.len() != member_count
        {
            return Err(AuthError::conflict(
                "Member allocation changed while field transforms were pending",
            ));
        }
        for mut membership in memberships {
            if let Some(id) = self.next_serial_id(state.team_members.len()) {
                membership.id = SchemaValue::from_field(id);
            }
            state.team_members.push(membership);
        }
        for (id, team) in teams {
            let _ = state.teams.replace(&id, team)?;
        }
        state.members.push(member);
        if let Some(session) = session {
            let mut stored = state
                .sessions
                .find_mut(|row| {
                    row.token
                        .field_value()
                        .strict_equals(&session.token.field_value())
                })?
                .ok_or(AuthError::SessionNotFound)?;
            *stored = session;
        }
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
        assert_eq!(
            state.members.snapshot()?[0].id.field_value(),
            Value::Number(1.0)
        );
        assert_eq!(state.members.snapshot()?[0].role, "member");
        let invitations = state.invitations.snapshot()?;
        assert_eq!(invitations.iter().filter(|row| row.is_pending()).count(), 1);
        assert_eq!(
            invitations
                .iter()
                .filter(|row| row.status == InvitationStatus::Accepted)
                .count(),
            1
        );
        assert_eq!(state.team_members.len(), 0);
        assert_eq!(state.sessions.len(), 0);
        Ok(())
    }
}
