use super::*;
use crate::store::{OrganizationRoleStore, TeamStore};
use crate::{CreateOrganizationRole, CreateTeam};

struct Records {
    organization_a: Organization,
    organization_b: Organization,
    member_aa: Member,
    member_ba: Member,
    member_ab: Member,
}

async fn create_organization(
    fixture: &Fixture,
    operations: &mut Vec<JsonValue>,
    suffix: &str,
) -> AuthResult<Organization> {
    let label = format!("organization-{suffix}");
    let mut input_record = CreateOrganization::new(
        format!("Display Organization {}", suffix.to_uppercase()),
        format!("display-organization-{suffix}"),
    );
    input_record.additional_fields = input(&label, false);
    let row = fixture.store.create_organization(input_record).await?;
    fixture.point(
        operations,
        &format!("create-{label}"),
        "organization",
        &row.id,
        &row.additional_fields,
    )?;
    Ok(row)
}

async fn create_member(
    fixture: &Fixture,
    operations: &mut Vec<JsonValue>,
    label: &str,
    organization: &Organization,
    user: &UserView,
) -> AuthResult<Member> {
    let mut input_record = CreateMember::new(organization.id.typed()?, user.id.typed()?, "member");
    input_record.additional_fields = input(label, false);
    let row = fixture.store.create_member(input_record).await?;
    fixture.point(
        operations,
        &format!("create-{label}"),
        "member",
        &row.id,
        &row.additional_fields,
    )?;
    Ok(row)
}

async fn snapshots(
    fixture: &Fixture,
    user_a: &UserView,
    user_b: &UserView,
) -> AuthResult<(JsonValue, Records)> {
    let mut operations = Vec::new();
    let organization_a = create_organization(fixture, &mut operations, "a").await?;
    let organization_b = create_organization(fixture, &mut operations, "b").await?;
    let member_aa = create_member(
        fixture,
        &mut operations,
        "member-a-a",
        &organization_a,
        user_a,
    )
    .await?;
    let member_ba = create_member(
        fixture,
        &mut operations,
        "member-b-a",
        &organization_a,
        user_b,
    )
    .await?;
    let member_ab = create_member(
        fixture,
        &mut operations,
        "member-a-b",
        &organization_b,
        user_a,
    )
    .await?;
    let instant: DateTime<Utc> = "2030-01-01T00:00:00Z".parse().map_err(|error| {
        AuthError::internal(format!("Parse the display fixture timestamp: {error}"))
    })?;
    let team = fixture
        .store
        .create_team(CreateTeam {
            additional_fields: input("team", false),
            name: "Display Team".into(),
            organization_id: organization_a.id.clone(),
            created_at: Some(instant.into()),
            ..Default::default()
        })
        .await?;
    fixture.point(
        &mut operations,
        "create-team",
        "team",
        &team.id,
        &team.additional_fields,
    )?;
    let mut invitation_input = CreateInvitation::new(
        organization_a.id.typed()?,
        "invitee@memory-core-json.test",
        "member",
        user_a.id.typed()?,
        "2100-01-01T00:00:00Z"
            .parse::<DateTime<Utc>>()
            .map_err(|error| {
                AuthError::internal(format!("Parse the display fixture timestamp: {error}"))
            })?
            .into(),
    );
    invitation_input.created_at = Some(instant.into());
    invitation_input.status = Some(InvitationStatus::Pending);
    invitation_input.additional_fields = input("invitation", false);
    let invitation = fixture.store.create_invitation(invitation_input).await?;
    fixture.point(
        &mut operations,
        "create-invitation",
        "invitation",
        &invitation.id,
        &invitation.additional_fields,
    )?;
    let role = fixture
        .store
        .create_organization_role(CreateOrganizationRole {
            additional_fields: input("role", false),
            organization_id: organization_a.id.typed()?.clone(),
            role: "viewer".into(),
            permission: FieldMap::default().into(),
        })
        .await?;
    fixture.point(
        &mut operations,
        "create-role",
        "organizationRole",
        &role.id,
        &role.additional_fields,
    )?;

    let organization = fixture
        .store
        .get_organization_by_id(organization_a.id.typed()?)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the display organization"))?;
    fixture.point(
        &mut operations,
        "read-organization",
        "organization",
        &organization_a.id,
        &organization.additional_fields,
    )?;
    let member = fixture
        .store
        .get_member_by_id(member_aa.id.typed()?)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the display member"))?;
    fixture.point(
        &mut operations,
        "read-member",
        "member",
        &member_aa.id,
        &member.additional_fields,
    )?;
    let team_read = fixture
        .store
        .get_team(team.id.typed()?)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the display team"))?;
    fixture.point(
        &mut operations,
        "read-team",
        "team",
        &team.id,
        &team_read.additional_fields,
    )?;
    let invitation_read = fixture
        .store
        .get_invitation_by_id(invitation.id.typed()?)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the display invitation"))?;
    fixture.point(
        &mut operations,
        "read-invitation",
        "invitation",
        &invitation.id,
        &invitation_read.additional_fields,
    )?;
    let role_read = fixture
        .store
        .get_organization_role(role.id.typed()?)
        .await?
        .ok_or_else(|| AuthError::internal("Expected the display role"))?;
    fixture.point(
        &mut operations,
        "read-role",
        "organizationRole",
        &role.id,
        &role_read.additional_fields,
    )?;
    Ok((
        json!({"name": "organization-snapshot", "operations": operations}),
        Records {
            organization_a,
            organization_b,
            member_aa,
            member_ba,
            member_ab,
        },
    ))
}

pub(super) async fn groups(
    fixture: &Fixture,
    user_a: &UserView,
    user_b: &UserView,
) -> AuthResult<(JsonValue, JsonValue)> {
    let (snapshots, records) = snapshots(fixture, user_a, user_b).await?;
    let mut operations = Vec::new();
    let organizations = fixture
        .store
        .list_user_organizations(user_a.id.typed()?)
        .await?;
    let result = organizations
        .iter()
        .map(|row| display(&row.additional_fields))
        .collect::<AuthResult<Vec<_>>>()?;
    fixture.observe(
        &mut operations,
        "list-for-user-a",
        json!(result),
        &[
            ("member", &records.member_aa.id),
            ("member", &records.member_ab.id),
            ("organization", &records.organization_a.id),
            ("organization", &records.organization_b.id),
        ],
    )?;
    let (members, total) = fixture
        .store
        .query_organization_members(&ListOrganizationMembersParams {
            organization_id: records.organization_a.id.typed()?.clone(),
            limit: Some(10.0),
            offset: Some(0.0),
            filter_field: Some("settings".into()),
            filter_value: Some(FieldMap::from_iter([("label".into(), "member-a-a".into())]).into()),
            filter_operator: Some("eq".into()),
            ..Default::default()
        })
        .await?;
    let user_ids = members
        .iter()
        .map(|member| member.user_id.typed().cloned())
        .collect::<AuthResult<Vec<_>>>()?;
    // The public Organization adapter reads users after its member query and count complete.
    let _users = fixture
        .store
        .list_users_by_ids(&user_ids, members.len() as f64)
        .await?;
    let rows = members
        .iter()
        .map(|row| display(&row.additional_fields))
        .collect::<AuthResult<Vec<_>>>()?;
    fixture.observe(
        &mut operations,
        "filter-members",
        json!({"rows": rows, "total": total}),
        &[
            ("member", &records.member_aa.id),
            ("member", &records.member_ba.id),
        ],
    )?;
    Ok((
        snapshots,
        json!({"name": "organization-joined-query", "operations": operations}),
    ))
}
