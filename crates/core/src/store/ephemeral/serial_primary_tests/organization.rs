use super::*;
use crate::organization_fields::OrganizationFields;
use crate::store::{OrganizationRoleStore, TeamMemberLimits, TeamStore};
use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType};
use crate::{CreateOrganizationRole, CreateTeam, SchemaValue, UpdateOrganizationRole};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) fn invitation() -> CreateInvitation {
    CreateInvitation::new(
        "001",
        "recipient@example.com",
        "member",
        "001",
        (Utc::now() + chrono::Duration::days(1)).into(),
    )
}

#[tokio::test]
async fn serial_organization_lifecycle_binds_numbers_and_projects_public_ids() -> AuthResult<()> {
    let store = serial_store();
    let organization = store
        .create_organization(CreateOrganization::new("Organization", "organization"))
        .await?;
    let member = store
        .create_member(CreateMember::new("001", "001", "member"))
        .await?;
    let team = store
        .create_team(CreateTeam {
            name: "First".into(),
            organization_id: "001".into(),
            ..Default::default()
        })
        .await?;
    let second_team = store
        .create_team(CreateTeam {
            name: "Second".into(),
            organization_id: "001".into(),
            ..Default::default()
        })
        .await?;
    let team_member = required(store.add_team_member(&"001".into(), "001", Some(1)).await?)?;
    let mut input = invitation();
    input.team_id = Some("1,2".into());
    let invited = store.create_invitation(input).await?;
    let role = store
        .create_organization_role(CreateOrganizationRole {
            additional_fields: FieldMap::new(),
            organization_id: "001".into(),
            role: "editor".into(),
            permission: Value::Object(FieldMap::new().into()),
        })
        .await?;
    for id in [
        organization.id,
        member.id,
        team.id,
        team_member.id,
        invited.id,
        role.id,
    ] {
        assert_eq!(id.field_value(), Value::from("1"));
    }
    assert_eq!(second_team.id.field_value(), Value::from("2"));
    {
        let state = store.lock()?;
        let ids = [
            organization_id(required(state.organizations.snapshot()?.first())?).field_value(),
            organization_id(required(state.members.snapshot()?.first())?).field_value(),
            organization_id(required(state.invitations.snapshot()?.first())?).field_value(),
            organization_id(required(state.teams.snapshot()?.first())?).field_value(),
            required(state.team_members.snapshot()?.first())?
                .id
                .field_value(),
            organization_id(required(state.organization_roles.snapshot()?.first())?).field_value(),
        ];
        assert_eq!(ids.to_vec(), vec![Value::Number(1.0); 6]);
        assert_eq!(
            required(state.team_members.snapshot()?.first())?
                .team_id
                .field_value(),
            Value::Number(1.0)
        );
        assert_eq!(
            required(state.team_members.snapshot()?.first())?
                .user_id
                .field_value(),
            Value::Number(1.0)
        );
    }
    assert_eq!(
        required(store.get_organization_by_id("001").await?)?.id,
        "1"
    );
    assert_eq!(required(store.get_member_by_id("001").await?)?.id, "1");
    assert_eq!(required(store.get_invitation_by_id("001").await?)?.id, "1");
    assert_eq!(required(store.get_team("001").await?)?.id, "1");
    assert_eq!(required(store.get_organization_role("001").await?)?.id, "1");
    let repeated = required(store.add_team_member(&"001".into(), "001", Some(1)).await?)?;
    assert_eq!(repeated.id.field_value(), Value::from("1"));
    assert_eq!(repeated.team_id.field_value(), Value::from("1"));
    assert_eq!(repeated.user_id.field_value(), Value::from("1"));
    assert_eq!(store.count_team_members("001").await?, 1);
    store.delete_member("001").await?;
    assert!(store.list_team_members("001").await?.is_empty());
    let _ = required(store.add_team_member(&"001".into(), "002", None).await?)?;
    store.delete_team("001").await?;
    assert!(store.get_team("001").await?.is_none());
    assert!(store.list_team_members("001").await?.is_empty());
    assert_eq!(
        required(store.get_invitation_by_id("001").await?)?
            .team_id
            .typed()?
            .as_deref(),
        Some("2")
    );
    store.delete_organization("001").await?;
    let state = store.lock()?;
    assert_eq!(state.organizations.len(), 0);
    assert_eq!(state.members.len(), 0);
    assert_eq!(state.invitations.len(), 0);
    assert_eq!(state.teams.len(), 0);
    assert_eq!(state.team_members.len(), 0);
    assert_eq!(state.organization_roles.len(), 0);
    Ok(())
}

#[tokio::test]
async fn serial_member_queries_sort_numbers_and_bind_array_filters_once() -> AuthResult<()> {
    let store = serial_store();
    for user_id in 1..=10 {
        let _ = store
            .create_member(CreateMember::new("001", user_id.to_string(), "member"))
            .await?;
    }
    let params = ListOrganizationMembersParams {
        organization_id: "001".into(),
        sort_by: Some("id".into()),
        sort_direction: Some("asc".into()),
        ..Default::default()
    };
    let (rows, count) = store.query_organization_members(&params).await?;
    assert_eq!(count, 10);
    assert_eq!(
        rows.iter()
            .map(|row| row.id.field_value())
            .collect::<Vec<_>>(),
        (1..=10)
            .map(|id| Value::from(id.to_string()))
            .collect::<Vec<_>>()
    );
    let (rows, count) = store
        .query_organization_members(&ListOrganizationMembersParams {
            filter_field: Some("id".into()),
            filter_operator: Some("in".into()),
            filter_value: Some(Value::Array(
                vec![Value::from("002"), Value::from("0xa")].into(),
            )),
            ..params
        })
        .await?;
    assert_eq!(count, 2);
    assert_eq!(
        rows.iter()
            .map(|row| row.id.field_value())
            .collect::<Vec<_>>(),
        [Value::from("2"), Value::from("10")]
    );
    Ok(())
}

#[tokio::test]
async fn serial_organization_id_updates_keep_numeric_storage() -> AuthResult<()> {
    let store = serial_store();
    let _ = store
        .create_organization(CreateOrganization::new("Organization", "organization"))
        .await?;
    let updated = store
        .update_organization(
            "001",
            UpdateOrganization {
                id: Some("002".into()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.id.field_value(), Value::from("2"));
    assert!(store.get_organization_by_id("001").await?.is_none());
    assert_eq!(
        required(store.get_organization_by_id("002").await?)?.id,
        "2"
    );
    for invalid in ["", "not-a-number"] {
        let unchanged = store
            .update_organization(
                "002",
                UpdateOrganization {
                    id: Some(invalid.into()),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(unchanged.id.field_value(), Value::from("2"));
    }
    let _ = store
        .create_organization_role(CreateOrganizationRole {
            additional_fields: FieldMap::new(),
            organization_id: "002".into(),
            role: "editor".into(),
            permission: Value::Object(FieldMap::new().into()),
        })
        .await?;
    let updated = store
        .update_organization_role(
            "001",
            UpdateOrganizationRole {
                additional_fields: [("id".into(), Value::from("003"))].into(),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.id.field_value(), Value::from("3"));
    assert!(store.get_organization_role("001").await?.is_none());
    assert_eq!(required(store.get_organization_role("003").await?)?.id, "3");
    for invalid in [
        Value::Undefined,
        Value::Null,
        Value::Bool(false),
        Value::Number(0.0),
        Value::Number(f64::NAN),
        Value::from(""),
        Value::from("not-a-number"),
    ] {
        let unchanged = store
            .update_organization_role(
                "003",
                UpdateOrganizationRole {
                    additional_fields: [("id".into(), invalid)].into(),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(unchanged.id.field_value(), Value::from("3"));
    }
    let state = store.lock()?;
    assert_eq!(
        organization_id(required(state.organizations.snapshot()?.first())?).field_value(),
        Value::Number(2.0)
    );
    assert_eq!(
        organization_id(required(state.organization_roles.snapshot()?.first())?).field_value(),
        Value::Number(3.0)
    );
    Ok(())
}

#[tokio::test]
async fn serial_organization_joins_distinguish_native_owners_from_projected_owners()
-> AuthResult<()> {
    for native in [false, true] {
        let mut config = (*test_config()).clone();
        config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
        config.advanced.database.joins = Some(native);
        let store = EphemeralStore::new(Arc::new(config));
        let _ = store
            .create_organization(CreateOrganization::new("Organization", "organization"))
            .await?;
        let _ = store
            .create_member(CreateMember::new("1", "1", "member"))
            .await?;
        let _ = store.create_invitation(invitation()).await?;
        {
            let state = store.lock()?;
            let id = SchemaValue::from_field(Value::Number(1.0));
            let owner = Value::Array(vec![Value::Number(1.0)].into());
            let _ = required(state.members.get_mut(&id)?)?
                .insert("organizationId".into(), owner.clone());
            let _ =
                required(state.invitations.get_mut(&id)?)?.insert("organizationId".into(), owner);
        }
        let organizations = store.list_user_organizations("001").await?;
        assert_eq!(organizations.len(), usize::from(!native));
        let invitations = store.list_user_invitations("recipient@example.com").await?;
        assert_eq!(invitations.len(), 1);
        let joined = required(invitations.first())?;
        assert_eq!(
            joined.invitation.organization_id.field_value(),
            Value::from("1")
        );
        assert_eq!(joined.organization.is_some(), !native);
        if !native {
            assert_eq!(
                required(organizations.first())?.id.field_value(),
                Value::from("1")
            );
            assert_eq!(
                required(joined.organization.as_ref())?.id.field_value(),
                Value::from("1")
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn live_organization_id_projection_observes_prior_output_callbacks() -> AuthResult<()> {
    let store = Arc::new(serial_store());
    let _ = store
        .create_organization(CreateOrganization::new("Organization", "organization"))
        .await?;
    let _ = store
        .create_member(CreateMember::new("1", "1", "member"))
        .await?;
    let target = Arc::downgrade(&store);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let mut fields = OrganizationFields::default();
    let _ = fields.organization.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    assert_eq!(counted.fetch_add(1, Ordering::SeqCst), 0);
                    let store = required(target.upgrade())?;
                    let state = store.lock()?;
                    let _ = required(
                        state
                            .organizations
                            .get_mut(&SchemaValue::from_field(Value::Number(1.0)))?,
                    )?
                    .insert("id".into(), Value::Number(2.0));
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    let rows = store.list_user_organizations("001").await?;
    assert_eq!(required(rows.first())?.id.field_value(), Value::from("2"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        organization_id(required(store.lock()?.organizations.snapshot()?.first())?).field_value(),
        Value::Number(2.0)
    );
    Ok(())
}

#[tokio::test]
async fn serial_invitation_cookie_projects_ids_without_changing_session_update_order()
-> AuthResult<()> {
    for override_user_id in [false, true] {
        let mut store = serial_store();
        let mut additional_fields = FieldMap::new();
        if override_user_id {
            store.session_config.additional_fields = Some(
                [(
                    "userId".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Number,
                        ..Default::default()
                    },
                )]
                .into(),
            );
            let _ = additional_fields.insert("userId".into(), Value::Number(7.0));
        }
        let session = store
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                additional_fields,
                user_id: "001".into(),
                expires_at: (Utc::now() + chrono::Duration::days(1)).into(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: Some("42".into()),
            })
            .await?;
        let _ = store
            .create_team(CreateTeam {
                name: "Team".into(),
                organization_id: "001".into(),
                ..Default::default()
            })
            .await?;
        let mut input = invitation();
        input.team_id = Some("1".into());
        let _ = store.create_invitation(input).await?;
        let (member, accepted, cookie) = store
            .accept_invitation_with_teams(
                "001",
                "001",
                Some(session.token.typed().unwrap()),
                true,
                TeamMemberLimits::Fixed(Some(1)),
            )
            .await?;
        assert_eq!(member.id.field_value(), Value::from("1"));
        assert_eq!(accepted.id.field_value(), Value::from("1"));
        let cookie = required(cookie)?;
        assert_eq!(cookie.id.field_value(), Value::from("1"));
        assert_eq!(
            cookie.user_id.field_value(),
            if override_user_id {
                Value::Number(7.0)
            } else {
                Value::from("1")
            }
        );
        assert_eq!(
            cookie.active_organization_id.typed().unwrap().as_deref(),
            Some("42")
        );
        assert_eq!(cookie.active_team_id.typed().unwrap().as_deref(), Some("1"));
        let state = store.lock()?;
        let raw = required(state.sessions.find(|row| row.token == session.token)?)?;
        assert_eq!(raw.id.field_value(), Value::Number(1.0));
        assert_eq!(
            raw.user_id.field_value(),
            Value::Number(if override_user_id { 7.0 } else { 1.0 })
        );
        assert_eq!(
            raw.active_organization_id.typed().unwrap().as_deref(),
            Some("1")
        );
        assert_eq!(raw.active_team_id.typed().unwrap().as_deref(), Some("1"));
        assert_eq!(
            organization_id(required(state.members.snapshot()?.first())?).field_value(),
            Value::Number(1.0)
        );
        let memberships = state.team_members.snapshot()?;
        let membership = required(memberships.first())?;
        assert_eq!(membership.id.field_value(), Value::Number(1.0));
        assert_eq!(membership.team_id.field_value(), Value::Number(1.0));
        assert_eq!(membership.user_id.field_value(), Value::Number(1.0));
    }
    Ok(())
}
