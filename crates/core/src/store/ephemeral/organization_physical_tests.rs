#![expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::unreachable,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors. Unexpected fixture variants and deliberate callback panics must fail or exercise the recorded unwind path."
)]

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
    store
        .storage_rows(role)?
        .pop()
        .ok_or_else(|| AuthError::internal("Physical fixture row is missing"))
}

fn fresh_id_alias_store(role: EntityRole, rows: Vec<FieldMap>) -> AuthResult<EphemeralStore> {
    let store = EphemeralStore::new(test_config());
    let mut fields = OrganizationFields::default();
    let _ = model_fields(&mut fields, role)
        .fields_mut()
        .insert("id".into(), mapped("lookup"));
    store.configure_organization_fields(fields)?;
    store.operation(|op| {
        let table = op.create_table(role)?;
        for row in rows {
            let _ = table.push(row)?;
        }
        Ok(())
    })?;
    Ok(store)
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
            .ok_or_else(|| AuthError::internal("Physical fixture invitation is missing"))?
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

#[tokio::test]
async fn fresh_organization_id_aliases_select_and_update_the_bound_physical_row() -> AuthResult<()>
{
    for (role, primary, _) in MODELS {
        let baseline = EphemeralStore::new(test_config());
        let expected = create(&baseline, role, FieldMap::new()).await?;
        let canonical = expected["id"].decode::<String>()?;
        let mut selected = stored(&baseline, role)?;
        let _ = selected.insert("lookup".into(), "requested-alias".into());
        let mut decoy = selected.clone();
        let _ = decoy.insert("id".into(), "requested-alias".into());
        let _ = decoy.insert("lookup".into(), "unrelated-alias".into());
        let _ = decoy.insert(primary.into(), "decoy".into());
        let before = vec![selected.clone(), decoy.clone()];
        let store = fresh_id_alias_store(role, before.clone())?;
        assert_eq!(read(&store, role, "requested-alias").await?, expected);
        assert_eq!(read(&store, role, &canonical).await?, expected);
        assert_eq!(store.storage_rows(role)?, before);

        let store = fresh_id_alias_store(role, before)?;
        let changed = update(&store, role, "requested-alias").await?;
        assert_eq!(changed["id"], expected["id"]);
        assert_eq!(changed[primary], Value::from("accepted"));
        assert_eq!(read(&store, role, &canonical).await?, changed);
        let after = store.storage_rows(role)?;
        assert_eq!(after.len(), 2);
        assert_eq!(after[1], decoy);
        assert_eq!(after[0]["id"], selected["id"]);
        assert_eq!(after[0]["lookup"], selected["lookup"]);
        assert_eq!(after[0][primary], Value::from("accepted"));
    }
    Ok(())
}

#[tokio::test]
async fn organization_id_list_binds_one_alias_for_the_complete_in_operand() -> AuthResult<()> {
    let baseline = EphemeralStore::new(test_config());
    let _ = create(&baseline, EntityRole::Organization, FieldMap::new()).await?;
    let mut first = stored(&baseline, EntityRole::Organization)?;
    let _ = first.insert("id".into(), "first-id".into());
    let _ = first.insert("lookup".into(), "first-alias".into());
    let mut second = first.clone();
    let _ = second.insert("id".into(), "second-id".into());
    let _ = second.insert("lookup".into(), "second-alias".into());
    let store = fresh_id_alias_store(
        EntityRole::Organization,
        vec![first.clone(), second.clone()],
    )?;
    let selected = store
        .list_organizations_by_ids(&["first-alias".into(), "second-alias".into()])
        .await?;
    assert_eq!(
        selected
            .iter()
            .map(|row| row.id.field_value())
            .collect::<Vec<_>>(),
        vec!["first-id".into(), "second-id".into()]
    );
    assert_eq!(
        store.storage_rows(EntityRole::Organization)?,
        vec![first, second]
    );
    Ok(())
}

#[tokio::test]
async fn member_unique_join_retains_the_first_user_id_alias_in_both_join_modes() -> AuthResult<()> {
    for native in [false, true] {
        let mut config = (*test_config()).clone();
        config.advanced.database.joins = Some(native);
        let _ = config
            .user
            .fields_mut()
            .insert("id".into(), mapped("lookup"));
        let store = EphemeralStore::new(Arc::new(config));
        let mut fields = OrganizationFields::default();
        let mut reference = fields.schema_for(EntityRole::Member)?.fields()["userId"].clone();
        reference.unique = Some(true);
        let _ = fields
            .member
            .fields_mut()
            .insert("userId".into(), reference);
        store.configure_organization_fields(fields)?;
        let now = Value::from(Utc::now());
        let user: FieldMap = [
            ("id".into(), "canonical-user".into()),
            ("lookup".into(), "user-alias".into()),
            ("name".into(), "Alias owner".into()),
            ("email".into(), "alias@example.com".into()),
            ("emailVerified".into(), false.into()),
            ("image".into(), Value::Null),
            ("createdAt".into(), now.clone()),
            ("updatedAt".into(), now.clone()),
        ]
        .into();
        let member: FieldMap = [
            ("id".into(), "member".into()),
            ("organizationId".into(), "organization".into()),
            ("userId".into(), "user-alias".into()),
            ("role".into(), "member".into()),
            ("createdAt".into(), now),
        ]
        .into();
        store.operation(|op| {
            let _ = op.create_table(EntityRole::User)?.push(user.clone())?;
            let _ = op.create_table(EntityRole::Member)?.push(member.clone())?;
            Ok(())
        })?;
        let joined = store
            .get_member_with_user("organization", "user-alias")
            .await?
            .unwrap();
        assert_eq!(joined.member.field_values()?, member);
        assert_eq!(joined.user.id, "canonical-user");
        assert_eq!(joined.user.name.field_value(), Value::from("Alias owner"));
        assert_eq!(store.storage_rows(EntityRole::User)?, vec![user]);
        assert_eq!(store.storage_rows(EntityRole::Member)?, vec![member]);
    }
    Ok(())
}

#[tokio::test]
async fn team_alias_change_during_reservation_cannot_commit_a_seat_or_membership() -> AuthResult<()>
{
    use crate::user_fields::{FieldTransforms, UserFieldTransform};
    let baseline = EphemeralStore::new(test_config());
    let _ = create(&baseline, EntityRole::Team, FieldMap::new()).await?;
    let mut team = stored(&baseline, EntityRole::Team)?;
    let _ = team.insert("lookup".into(), "team-alias".into());
    let store = fresh_id_alias_store(EntityRole::Team, vec![team.clone()])?;
    let mut fields = store.organization_fields()?;
    let writer = store.clone();
    let _ = fields.team.fields_mut().insert(
        "memberCount".into(),
        UserFieldConfig {
            field_type: UserFieldType::Number,
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    writer.operation(|op| {
                        let row = op
                            .capture_table(EntityRole::Team)?
                            .select_refs(|_| Ok(true))?
                            .remove(0);
                        row.apply_patch([("lookup".into(), "changed-alias".into())].into())
                    })?;
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    let result = store
        .add_team_member_value(&"team-alias".into(), &"member".into(), Some(1))
        .await;
    assert!(matches!(result, Err(AuthError::Conflict(_))));
    let _ = team.insert("lookup".into(), "changed-alias".into());
    assert_eq!(store.storage_rows(EntityRole::Team)?, vec![team]);
    assert!(store.storage_rows(EntityRole::TeamMember)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn invitation_alias_change_after_claim_restores_status_without_committing_members()
-> AuthResult<()> {
    use crate::user_fields::{FieldTransforms, UserFieldTransform};
    let baseline = EphemeralStore::new(test_config());
    let _ = create(&baseline, EntityRole::Invitation, FieldMap::new()).await?;
    let mut invitation = stored(&baseline, EntityRole::Invitation)?;
    let _ = invitation.insert("lookup".into(), "invitation-alias".into());
    let store = fresh_id_alias_store(EntityRole::Invitation, vec![invitation.clone()])?;
    let mut fields = store.organization_fields()?;
    let writer = store.clone();
    let _ = fields.invitation.fields_mut().insert(
        "status".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    writer.operation(|op| {
                        let row = op
                            .capture_table(EntityRole::Invitation)?
                            .select_refs(|_| Ok(true))?
                            .remove(0);
                        row.apply_patch([("lookup".into(), "changed-alias".into())].into())
                    })?;
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    let result = store
        .accept_invitation_with_teams_values(
            &"invitation-alias".into(),
            &"recipient".into(),
            None,
            false,
            crate::store::TeamMemberLimits::Fixed(None),
        )
        .await;
    assert!(matches!(result, Err(AuthError::Conflict(_))));
    let _ = invitation.insert("lookup".into(), "changed-alias".into());
    assert_eq!(
        store.storage_rows(EntityRole::Invitation)?,
        vec![invitation]
    );
    assert!(store.storage_rows(EntityRole::Member)?.is_empty());
    assert!(store.storage_rows(EntityRole::TeamMember)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn invitation_claim_accepts_its_own_selector_update() -> AuthResult<()> {
    for column in ["id", "lookup"] {
        let baseline = EphemeralStore::new(test_config());
        let _ = create(&baseline, EntityRole::Invitation, FieldMap::new()).await?;
        let mut invitation = stored(&baseline, EntityRole::Invitation)?;
        let _ = invitation.insert(column.into(), "invitation-alias".into());
        let store = fresh_id_alias_store(EntityRole::Invitation, vec![invitation.clone()])?;
        let mut fields = store.organization_fields()?;
        let _ = fields
            .invitation
            .fields_mut()
            .insert("id".into(), mapped(column));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_calls = calls.clone();
        let _ = fields.invitation.fields_mut().insert(
            "claimLookup".into(),
            UserFieldConfig {
                on_update: Some(crate::user_fields::UserFieldFactory::new(move || {
                    observed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok("claimed-alias".into())
                })),
                ..mapped(column)
            },
        );
        store.configure_organization_fields(fields)?;
        let (member, accepted, session) = store
            .accept_invitation_with_teams_values(
                &"invitation-alias".into(),
                &"recipient".into(),
                None,
                false,
                crate::store::TeamMemberLimits::Fixed(None),
            )
            .await?;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(accepted.status, InvitationStatus::Accepted);
        assert_eq!(
            accepted.additional_fields["claimLookup"],
            Value::from("claimed-alias")
        );
        let _ = invitation.insert(column.into(), "claimed-alias".into());
        let _ = invitation.insert("status".into(), "accepted".into());
        assert_eq!(accepted.id.field_value(), invitation["id"]);
        assert_eq!(
            store.storage_rows(EntityRole::Invitation)?,
            vec![invitation]
        );
        assert_eq!(member.organization_id, "organization");
        assert_eq!(member.user_id, "recipient");
        assert_eq!(member.role, "member");
        assert_eq!(
            store.storage_rows(EntityRole::Member)?,
            vec![member.field_values()?]
        );
        assert!(store.storage_rows(EntityRole::TeamMember)?.is_empty());
        assert!(session.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn invitation_claim_accepts_its_own_nan_selector() -> AuthResult<()> {
    for column in ["id", "lookup"] {
        let baseline = EphemeralStore::new(test_config());
        let _ = create(&baseline, EntityRole::Invitation, FieldMap::new()).await?;
        let mut invitation = stored(&baseline, EntityRole::Invitation)?;
        let _ = invitation.insert(column.into(), "invitation-alias".into());
        let store = fresh_id_alias_store(EntityRole::Invitation, vec![invitation.clone()])?;
        let mut fields = store.organization_fields()?;
        let _ = fields
            .invitation
            .fields_mut()
            .insert("id".into(), mapped(column));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_calls = calls.clone();
        let _ = fields.invitation.fields_mut().insert(
            "claimLookup".into(),
            UserFieldConfig {
                on_update: Some(crate::user_fields::UserFieldFactory::new(move || {
                    observed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(f64::NAN.into())
                })),
                ..mapped(column)
            },
        );
        store.configure_organization_fields(fields)?;
        let (member, accepted, session) = store
            .accept_invitation_with_teams_values(
                &"invitation-alias".into(),
                &"recipient".into(),
                None,
                false,
                crate::store::TeamMemberLimits::Fixed(None),
            )
            .await?;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(accepted.status, InvitationStatus::Accepted);
        if column == "id" {
            assert_eq!(accepted.id, "NaN");
            assert_eq!(
                accepted.additional_fields["claimLookup"],
                Value::from("NaN")
            );
        } else {
            assert_eq!(accepted.id.field_value(), invitation["id"]);
            assert!(
                accepted.additional_fields["claimLookup"]
                    .as_f64()
                    .is_some_and(f64::is_nan)
            );
        }
        let mut rows = store.storage_rows(EntityRole::Invitation)?;
        assert_eq!(rows.len(), 1);
        let mut row = rows.remove(0);
        assert!(matches!(row.remove(column), Some(Value::Number(value)) if value.is_nan()));
        let _ = invitation.remove(column);
        let _ = invitation.insert("status".into(), "accepted".into());
        assert_eq!(row, invitation);
        assert_eq!(member.organization_id, "organization");
        assert_eq!(member.user_id, "recipient");
        assert_eq!(member.role, "member");
        assert_eq!(
            store.storage_rows(EntityRole::Member)?,
            vec![member.field_values()?]
        );
        assert!(store.storage_rows(EntityRole::TeamMember)?.is_empty());
        assert!(session.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn invitation_claim_rejects_null_selector_deletion_or_undefined() -> AuthResult<()> {
    use crate::user_fields::{FieldTransforms, UserFieldTransform};
    for erase in [false, true] {
        let baseline = EphemeralStore::new(test_config());
        let _ = create(&baseline, EntityRole::Invitation, FieldMap::new()).await?;
        let mut invitation = stored(&baseline, EntityRole::Invitation)?;
        let _ = invitation.insert("lookup".into(), "invitation-alias".into());
        let store = fresh_id_alias_store(EntityRole::Invitation, vec![invitation.clone()])?;
        let mut fields = store.organization_fields()?;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_calls = calls.clone();
        let _ = fields.invitation.fields_mut().insert(
            "claimLookup".into(),
            UserFieldConfig {
                on_update: Some(crate::user_fields::UserFieldFactory::new(move || {
                    Ok(
                        if observed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                            Value::Null
                        } else {
                            Value::Undefined
                        },
                    )
                })),
                ..mapped("lookup")
            },
        );
        let writer = store.clone();
        let _ = fields.invitation.fields_mut().insert(
            "status".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        if value.strict_equals(&"accepted".into()) {
                            writer.operation(|op| {
                                let row = op
                                    .capture_table(EntityRole::Invitation)?
                                    .row_at(0)?
                                    .ok_or_else(|| {
                                        AuthError::internal("Claimed invitation is missing")
                                    })?;
                                if erase {
                                    let _ = row.delete_field("lookup")?;
                                } else {
                                    row.set_field("lookup".into(), Value::Undefined)?;
                                }
                                Ok(())
                            })?;
                        }
                        Ok(value)
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        store.configure_organization_fields(fields)?;
        let result = store
            .accept_invitation_with_teams_values(
                &"invitation-alias".into(),
                &"recipient".into(),
                None,
                false,
                crate::store::TeamMemberLimits::Fixed(None),
            )
            .await;
        assert!(matches!(result, Err(AuthError::Conflict(_))));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        if erase {
            let _ = invitation.remove("lookup");
        } else {
            let _ = invitation.insert("lookup".into(), Value::Undefined);
        }
        assert_eq!(
            store.storage_rows(EntityRole::Invitation)?,
            vec![invitation]
        );
        assert!(store.storage_rows(EntityRole::Member)?.is_empty());
        assert!(store.storage_rows(EntityRole::TeamMember)?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn invitation_claim_rejects_equal_content_ownership_replacements() -> AuthResult<()> {
    use crate::user_fields::{FieldTransforms, UserFieldTransform};
    for column in ["teamId", "organizationId", "role"] {
        let marker = || Value::from(FieldMap::from([("owner".into(), "same-content".into())]));
        let baseline = EphemeralStore::new(test_config());
        let _ = create(&baseline, EntityRole::Invitation, FieldMap::new()).await?;
        let mut invitation = stored(&baseline, EntityRole::Invitation)?;
        let _ = invitation.insert("lookup".into(), "invitation-alias".into());
        let _ = invitation.insert(column.into(), marker());
        let store = fresh_id_alias_store(EntityRole::Invitation, vec![invitation.clone()])?;
        let mut fields = store.organization_fields()?;
        let replacement = marker();
        let changed = replacement.clone();
        let writer = store.clone();
        let _ = fields.invitation.fields_mut().insert(
            "status".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        if value.strict_equals(&"accepted".into()) {
                            writer.operation(|op| {
                                let row = op
                                    .capture_table(EntityRole::Invitation)?
                                    .row_at(0)?
                                    .ok_or_else(|| {
                                        AuthError::internal("Claimed invitation is missing")
                                    })?;
                                row.apply_patch([(column.into(), changed.clone())].into())
                            })?;
                        }
                        Ok(value)
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        store.configure_organization_fields(fields)?;
        let result = store
            .accept_invitation_with_teams_values(
                &"invitation-alias".into(),
                &"recipient".into(),
                None,
                false,
                crate::store::TeamMemberLimits::Fixed(None),
            )
            .await;
        assert!(matches!(result, Err(AuthError::Conflict(_))));
        let _ = invitation.insert(column.into(), replacement.clone());
        let rows = store.storage_rows(EntityRole::Invitation)?;
        assert_eq!(rows, vec![invitation]);
        assert!(rows[0][column].strict_equals(&replacement));
        assert!(store.storage_rows(EntityRole::Member)?.is_empty());
        assert!(store.storage_rows(EntityRole::TeamMember)?.is_empty());
    }
    Ok(())
}
