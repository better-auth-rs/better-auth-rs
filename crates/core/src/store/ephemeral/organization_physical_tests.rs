use super::*;
use crate::organization_fields::OrganizationFields;
use crate::store::{OrganizationRoleStore, TeamStore};
use crate::user_fields::{UserConfig, UserFieldConfig, UserFieldType};
use crate::{CreateOrganizationRole, CreateTeam, UpdateOrganizationRole, UpdateTeam};
use better_auth_schema_registry::EntityRole;

const MODELS: [(EntityRole, &str, &str); 5] = [
    (EntityRole::Organization, "name", "slug"),
    (EntityRole::Member, "role", "userId"),
    (EntityRole::Invitation, "status", "role"),
    (EntityRole::Team, "name", "organizationId"),
    (EntityRole::OrganizationRole, "role", "organizationId"),
];

fn model_fields(fields: &mut OrganizationFields, role: EntityRole) -> &mut UserConfig {
    match role {
        EntityRole::Organization => &mut fields.organization,
        EntityRole::Member => &mut fields.member,
        EntityRole::Invitation => &mut fields.invitation,
        EntityRole::Team => &mut fields.team,
        EntityRole::OrganizationRole => &mut fields.organization_role,
        _ => unreachable!("The fixture contains only Organization models"),
    }
}

fn mapped(column: &str) -> UserFieldConfig {
    UserFieldConfig {
        field_name: Some(column.into()),
        ..Default::default()
    }
}

fn stored(store: &EphemeralStore, role: EntityRole) -> AuthResult<FieldMap> {
    let state = store.lock()?;
    let rows = match role {
        EntityRole::Organization => &state.organizations,
        EntityRole::Member => &state.members,
        EntityRole::Invitation => &state.invitations,
        EntityRole::Team => &state.teams,
        EntityRole::OrganizationRole => &state.organization_roles,
        _ => unreachable!("The fixture contains only Organization models"),
    };
    rows.snapshot()?
        .pop()
        .ok_or_else(|| AuthError::internal("Physical fixture row is missing"))
}

async fn create(
    store: &EphemeralStore,
    role: EntityRole,
    extras: FieldMap,
) -> AuthResult<FieldMap> {
    match role {
        EntityRole::Organization => {
            let mut input = CreateOrganization::new("name-before", "slug-before");
            input.additional_fields = extras;
            store.create_organization(input).await?.field_values()
        }
        EntityRole::Member => {
            let mut input = CreateMember::new("organization", "recipient-before", "member");
            input.additional_fields = extras;
            store.create_member(input).await?.field_values()
        }
        EntityRole::Invitation => {
            let mut input = CreateInvitation::new(
                "organization",
                "recipient@example.com",
                "member",
                "inviter",
                (Utc::now() + chrono::Duration::days(1)).into(),
            );
            input.additional_fields = extras;
            store.create_invitation(input).await?.field_values()
        }
        EntityRole::Team => store
            .create_team(CreateTeam {
                name: "name-before".into(),
                organization_id: "organization".into(),
                additional_fields: extras,
                ..Default::default()
            })
            .await?
            .field_values(),
        EntityRole::OrganizationRole => store
            .create_organization_role(CreateOrganizationRole {
                organization_id: "organization".into(),
                role: "reader".into(),
                permission: FieldMap::new().into(),
                additional_fields: extras,
            })
            .await?
            .field_values(),
        _ => unreachable!("The fixture contains only Organization models"),
    }
}

async fn read(store: &EphemeralStore, role: EntityRole, id: &str) -> AuthResult<FieldMap> {
    let fields = match role {
        EntityRole::Organization => store
            .get_organization_by_id(id)
            .await?
            .map(|row| row.field_values()),
        EntityRole::Member => store
            .get_member_by_id(id)
            .await?
            .map(|row| row.field_values()),
        EntityRole::Invitation => store
            .get_invitation_by_id(id)
            .await?
            .map(|row| row.field_values()),
        EntityRole::Team => store.get_team(id).await?.map(|row| row.field_values()),
        EntityRole::OrganizationRole => store
            .get_organization_role(id)
            .await?
            .map(|row| row.field_values()),
        _ => unreachable!("The fixture contains only Organization models"),
    };
    fields.ok_or_else(|| AuthError::internal("Projected fixture row is missing"))?
}

async fn update(store: &EphemeralStore, role: EntityRole, id: &str) -> AuthResult<FieldMap> {
    match role {
        EntityRole::Organization => store
            .update_organization(
                id,
                UpdateOrganization {
                    name: Some("accepted".into()),
                    ..Default::default()
                },
            )
            .await?
            .field_values(),
        EntityRole::Member => store
            .update_member_role(id, "accepted")
            .await?
            .field_values(),
        EntityRole::Invitation => store
            .update_invitation_status(id, InvitationStatus::Accepted)
            .await?
            .field_values(),
        EntityRole::Team => store
            .update_team(
                id,
                UpdateTeam {
                    name: Some("accepted".into()),
                    ..Default::default()
                },
            )
            .await?
            .field_values(),
        EntityRole::OrganizationRole => store
            .update_organization_role(
                id,
                UpdateOrganizationRole {
                    role: Some("accepted".into()),
                    ..Default::default()
                },
            )
            .await?
            .field_values(),
        _ => unreachable!("The fixture contains only Organization models"),
    }
}

#[tokio::test]
async fn existing_rows_follow_reconfigured_columns_without_rewriting_storage() -> AuthResult<()> {
    for (role, primary, alternate) in MODELS {
        let store = EphemeralStore::new(test_config());
        let created = create(&store, role, FieldMap::new()).await?;
        let id = created["id"].decode::<String>()?;
        let before = stored(&store, role)?;
        let original = before[primary].clone();
        let alternate_value = before[alternate].clone();
        let mut fields = OrganizationFields::default();
        let schema = model_fields(&mut fields, role);
        let _ = schema
            .fields_mut()
            .insert(primary.into(), mapped(alternate));
        let _ = schema
            .fields_mut()
            .insert("original".into(), mapped(primary));
        store.configure_organization_fields(fields)?;

        let selected = read(&store, role, &id).await?;
        assert_eq!(selected[primary], alternate_value);
        assert_eq!(selected["original"], original);
        assert_eq!(stored(&store, role)?, before);
        let changed = update(&store, role, &id).await?;
        assert_eq!(changed[primary], Value::from("accepted"));
        assert_eq!(changed["original"], original);
        let physical = stored(&store, role)?;
        assert_eq!(physical[primary], original);
        assert_eq!(physical[alternate], Value::from("accepted"));
        assert!(!physical.contains_key("original"));

        store.configure_organization_fields(OrganizationFields::default())?;
        let restored = read(&store, role, &id).await?;
        assert_eq!(restored[primary], original);
        assert_eq!(restored[alternate], Value::from("accepted"));
        assert_eq!(stored(&store, role)?, physical);
    }
    Ok(())
}

#[tokio::test]
async fn native_and_additional_aliases_share_one_physical_column() -> AuthResult<()> {
    for (role, primary, _) in MODELS {
        let store = EphemeralStore::new(test_config());
        let mut fields = OrganizationFields::default();
        let schema = model_fields(&mut fields, role);
        let _ = schema.fields_mut().insert(primary.into(), mapped("shared"));
        let _ = schema
            .fields_mut()
            .insert("shadow".into(), mapped("shared"));
        store.configure_organization_fields(fields)?;
        let created = create(
            &store,
            role,
            [("shadow".into(), "last-writer".into())].into(),
        )
        .await?;
        let id = created["id"].decode::<String>()?;
        assert_eq!(created[primary], Value::from("last-writer"));
        assert_eq!(created["shadow"], Value::from("last-writer"));
        let before = stored(&store, role)?;
        assert_eq!(before["shared"], Value::from("last-writer"));
        assert!(!before.contains_key(primary));
        assert!(!before.contains_key("shadow"));

        let changed = update(&store, role, &id).await?;
        assert_eq!(changed[primary], Value::from("accepted"));
        assert_eq!(changed["shadow"], Value::from("accepted"));
        let physical = stored(&store, role)?;
        store.configure_organization_fields(OrganizationFields::default())?;
        assert!(read(&store, role, &id).await?[primary].is_undefined());
        assert_eq!(stored(&store, role)?, physical);
    }
    Ok(())
}

#[tokio::test]
async fn mapped_owner_claim_and_capacity_use_physical_columns_atomically() -> AuthResult<()> {
    let store = EphemeralStore::new(test_config());
    let mut fields = OrganizationFields::default();
    for (schema, column) in [
        (&mut fields.member, "memberOwner"),
        (&mut fields.invitation, "invitationOwner"),
        (&mut fields.team, "teamOwner"),
    ] {
        let _ = schema
            .fields_mut()
            .insert("organizationId".into(), mapped(column));
    }
    let _ = fields
        .member
        .fields_mut()
        .insert("userId".into(), mapped("memberUser"));
    let _ = fields
        .invitation
        .fields_mut()
        .insert("status".into(), mapped("claimStatus"));
    let _ = fields.team.fields_mut().insert(
        "memberCount".into(),
        UserFieldConfig {
            field_type: UserFieldType::Number,
            ..mapped("seats")
        },
    );
    store.configure_organization_fields(fields)?;
    let team = store
        .create_team(CreateTeam {
            name: "Mapped team".into(),
            organization_id: "organization".into(),
            ..Default::default()
        })
        .await?;
    let mut invite = CreateInvitation::new(
        "organization",
        "member@example.com",
        "member",
        "inviter",
        (Utc::now() + chrono::Duration::days(1)).into(),
    );
    invite.team_id = Some(team.id.typed()?.clone());
    let invite = store.create_invitation(invite).await?;
    let (member, accepted, _) = store
        .accept_invitation_with_teams(
            invite.id.typed()?,
            "recipient",
            None,
            true,
            crate::store::TeamMemberLimits::Fixed(Some(1)),
        )
        .await?;
    assert_eq!(member.organization_id, "organization");
    assert_eq!(accepted.status, InvitationStatus::Accepted);
    assert_eq!(store.count_organization_members("organization").await?, 1);
    assert!(
        store
            .get_member("organization", "recipient")
            .await?
            .is_some()
    );
    assert_eq!(
        store.list_organization_teams("organization").await?.len(),
        1
    );
    assert!(
        store
            .add_team_member(&team.id, "other", Some(1))
            .await?
            .is_none()
    );
    assert_eq!(
        stored(&store, EntityRole::Team)?["seats"],
        Value::Number(1.0)
    );
    assert_eq!(
        stored(&store, EntityRole::Invitation)?["claimStatus"],
        Value::from("accepted")
    );
    assert_eq!(
        stored(&store, EntityRole::Member)?["memberUser"],
        Value::from("recipient")
    );
    store
        .remove_team_member(team.id.typed()?, "recipient")
        .await?;
    assert_eq!(
        stored(&store, EntityRole::Team)?["seats"],
        Value::Number(0.0)
    );
    assert_eq!(store.count_team_members(team.id.typed()?).await?, 0);
    Ok(())
}

#[tokio::test]
async fn mapped_updates_preserve_physical_rows_across_transaction_commit_and_rollback()
-> AuthResult<()> {
    let store = EphemeralStore::new(test_config());
    let mut fields = OrganizationFields::default();
    let _ = fields
        .organization
        .fields_mut()
        .insert("name".into(), mapped("storedName"));
    store.configure_organization_fields(fields)?;
    let organization = store
        .create_organization(CreateOrganization::new("before", "transaction"))
        .await?;
    let before = stored(&store, EntityRole::Organization)?;
    let (_base, discarded, _pending) = store.begin_adapter_transaction()?;
    let _ = update(
        &discarded,
        EntityRole::Organization,
        organization.id.typed()?,
    )
    .await?;
    assert_eq!(stored(&store, EntityRole::Organization)?, before);
    drop(discarded);
    assert_eq!(stored(&store, EntityRole::Organization)?, before);

    let (base, committed, pending) = store.begin_adapter_transaction()?;
    let _ = update(
        &committed,
        EntityRole::Organization,
        organization.id.typed()?,
    )
    .await?;
    store.commit_transaction(base, committed, pending).await?;
    let physical = stored(&store, EntityRole::Organization)?;
    assert_eq!(physical["storedName"], Value::from("accepted"));
    assert_eq!(physical["slug"], before["slug"]);
    assert!(!physical.contains_key("name"));
    Ok(())
}
