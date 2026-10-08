use super::*;

pub(super) async fn observe(joins: bool) -> AuthResult<Value> {
    let store = EphemeralStore::new(Arc::new(config(joins)));
    store.configure_organization_fields(OrganizationFields {
        member: UserConfig {
            additional_fields: Some(
                [
                    (
                        "reference".into(),
                        UserFieldConfig {
                            references: Some(UserFieldReference {
                                model: "organizationRole".into(),
                                field: "id".into(),
                                ..Default::default()
                            }),
                            ..reference(None)
                        },
                    ),
                    (
                        "userId".into(),
                        UserFieldConfig {
                            field_name: Some("stored_user_id".into()),
                            references: Some(UserFieldReference {
                                model: "user".into(),
                                field: "id".into(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        },
        ..Default::default()
    })?;
    let user_id = user(&store).await?;
    let organization = store
        .create_organization(CreateOrganization::new("Organization", "ordinary"))
        .await?;
    let organization_id = organization.id.typed()?.clone();
    let padded_organization = format!("00{organization_id}");
    let padded_user = format!("00{user_id}");
    let role = store
        .create_organization_role(CreateOrganizationRole {
            organization_id: padded_organization.clone().into(),
            role: "viewer".into(),
            permission: FieldValue::from(FieldMap::new()),
            additional_fields: Default::default(),
        })
        .await?;
    let padded_role = format!("00{}", role.id.typed()?);
    let created_member = store
        .create_member(CreateMember::new(
            &padded_organization,
            &padded_user,
            "owner",
        ))
        .await?;
    let team = store
        .create_team(CreateTeam {
            name: "Team".into(),
            organization_id: padded_organization.clone().into(),
            ..Default::default()
        })
        .await?;
    let padded_team = format!("00{}", team.id.typed()?);
    let _ = store
        .add_team_member(&team.id, &user_id, None)
        .await?
        .ok_or_else(|| AuthError::internal("ordinary team membership is inserted"))?;
    let mut invitation = CreateInvitation::new(
        &padded_organization,
        EMAIL,
        "member",
        &padded_user,
        "2100-01-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .map_err(|error| AuthError::internal(format!("invalid invitation expiry: {error}")))?
            .into(),
    );
    invitation.team_id = Some(team.id.typed()?.clone());
    let invitation = store.create_invitation(invitation).await?;
    let (filtered, total) = store
        .query_organization_members(&ListOrganizationMembersParams {
            organization_id: padded_organization.clone().into(),
            filter_field: Some("reference".into()),
            filter_value: Some(FieldValue::from(padded_role)),
            filter_operator: Some("eq".into()),
            ..Default::default()
        })
        .await?;
    let mut filtered_members = Vec::new();
    for row in filtered {
        let user = store
            .get_user_by_id(row.user_id.typed()?)
            .await?
            .ok_or_else(|| AuthError::internal("ordinary member has its user"))?;
        filtered_members.push(joined_member(&MemberUser {
            member: row,
            user: better_auth_core::MemberUserView::from_user(&user),
        }));
    }
    let full = store
        .get_organization_details(OrganizationDetailsQuery {
            organization: OrganizationKey::Id(&padded_organization),
            members_limit: None,
            users_limit: 100.0,
            include_teams: true,
        })
        .await?
        .ok_or_else(|| AuthError::internal("ordinary organization exists"))?;
    let point_team_member = store
        .get_team_member(&padded_team, &padded_user)
        .await?
        .ok_or_else(|| AuthError::internal("ordinary team member pair exists"))?;
    let lookup = json!({
        "numericMember":member(&store.get_member_value(&FieldValue::from(organization_id.parse::<u64>().map_err(|error| AuthError::internal(format!("invalid serial organization ID: {error}")))?), &FieldValue::from(user_id.parse::<u64>().map_err(|error| AuthError::internal(format!("invalid serial user ID: {error}")))?)).await?.ok_or_else(|| AuthError::internal("ordinary numeric member pair exists"))?),
        "member":joined_member(&store.get_member_with_user(&padded_organization, &padded_user).await?.ok_or_else(|| AuthError::internal("ordinary member pair exists"))?),
        "memberById":joined_member(&store.get_member_by_id_with_user(created_member.id.typed()?).await?.ok_or_else(|| AuthError::internal("ordinary member ID exists"))?),
        "filtered":{"total":total,"members":filtered_members},
        "organizations":store.list_user_organizations(&padded_user).await?.iter().map(|row| &row.id).collect::<Vec<_>>(),
        "teams":store.list_user_teams(&padded_user).await?.iter().map(|row| &row.id).collect::<Vec<_>>(),
        "teamMembers":team_members(store.list_team_members(&padded_team).await?),
        "teamMember":{"teamId":point_team_member.team_id,"userId":point_team_member.user_id},
        "counts":{
            "members":store.count_organization_members(&padded_organization).await?,
            "owners":store.count_organization_owners(&padded_organization).await?,
            "pendingInvitations":store.count_pending_organization_invitations(&padded_organization).await?,
            "teams":store.count_organization_teams(&padded_organization).await?,
            "teamMembers":store.count_team_members(&padded_team).await?,
            "roles":store.count_organization_roles(&padded_organization).await?,
        },
        "role":store.find_organization_role(&padded_organization, OrganizationRoleKey::Name("viewer")).await?.ok_or_else(|| AuthError::internal("ordinary role exists"))?.organization_id,
        "invitations":store.list_user_invitations(EMAIL).await?.iter().map(|row| -> AuthResult<Value> { Ok(json!({
            "organizationId":row.invitation.organization_id,"inviterId":row.invitation.inviter_id,
            "organizationName":present(row.organization.as_ref().ok_or_else(|| AuthError::internal("ordinary invitation organization exists"))?.name.json()?),"teamId":present(row.invitation.team_id.json()?),
        })) }).collect::<AuthResult<Vec<_>>>()?,
        "pending":store.get_pending_invitation(&padded_organization, EMAIL).await?.iter().map(|row| &row.id).collect::<Vec<_>>(),
        "full":{
            "id":full.organization.id,"members":full.members.iter().map(joined_member).collect::<Vec<_>>(),
            "teams":full.teams.ok_or_else(|| AuthError::internal("team page requested"))?.iter().map(|row| json!({"id":row.id,"organizationId":row.organization_id})).collect::<Vec<_>>(),
            "invitations":full.invitations.iter().map(|row| json!({"organizationId":row.organization_id,"inviterId":row.inviter_id})).collect::<Vec<_>>(),
        },
    });
    store.delete_member(created_member.id.typed()?).await?;
    let removed = json!({
        "members":store.count_organization_members(&padded_organization).await?,
        "teamMembers":store.count_team_members(&padded_team).await?,
    });
    let session = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            user_id: user_id.clone().into(),
            expires_at: "2100-01-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .map_err(|error| AuthError::internal(format!("invalid session expiry: {error}")))?
                .into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            additional_fields: Default::default(),
        })
        .await?;
    let (accepted_member, accepted_invitation, snapshot) = store
        .accept_invitation_with_teams(
            invitation.id.typed()?,
            &user_id,
            Some(session.token.typed()?),
            true,
            Some(10).into(),
        )
        .await?;
    let _ = snapshot
        .ok_or_else(|| AuthError::internal("ordinary acceptance returns its cookie snapshot"))?;
    let session_after = store
        .get_session(session.token.typed()?)
        .await?
        .ok_or_else(|| AuthError::internal("ordinary accepted session remains available"))?;
    let acceptance = json!({
        "member":member(&accepted_member),"status":accepted_invitation.status,"teamId":present(accepted_invitation.team_id.json()?),
        "teamMembers":team_members(store.list_team_members(&padded_team).await?),
        "activeOrganizationId":present(session_after.active_organization_id.json()?),
        "activeTeamId":present(session_after.active_team_id.json()?),
    });
    store.remove_team_member(&padded_team, &padded_user).await?;
    let removed_team_member = store.count_team_members(&padded_team).await?;
    store.delete_team(team.id.typed()?).await?;
    store.delete_organization_role(role.id.typed()?).await?;
    store.delete_organization(&organization_id).await?;
    let cleanup = json!({
        "removedTeamMember":removed_team_member,
        "members":store.count_organization_members(&padded_organization).await?,
        "invitations":store.list_organization_invitations(&padded_organization).await?.len(),
        "teams":store.list_organization_teams(&padded_organization).await?.len(),
        "roles":store.count_organization_roles(&padded_organization).await?,
        "organizationPresent":store.get_organization_by_id(&organization_id).await?.is_some(),
        "userPresent":store.get_user_by_id(&user_id).await?.is_some(),
    });
    Ok(
        json!({"joins":joins,"lookup":lookup,"removed":removed,"acceptance":acceptance,"cleanup":cleanup}),
    )
}
