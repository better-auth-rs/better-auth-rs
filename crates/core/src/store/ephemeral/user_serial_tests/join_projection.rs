use super::*;

#[tokio::test]
async fn serial_array_owners_join_only_after_fallback_projection() -> AuthResult<()> {
    for joins in [false, true] {
        let store = serial_store(joins);
        let _ = store.create_user(user("owner")).await?;
        let raw_owner = Value::from(vec![Value::Number(1.0)]);
        let session = store
            .create_session(CreateSession {
                user_id: crate::SchemaValue::from_field(raw_owner.clone()),
                expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
                additional_fields: Default::default(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        assert_eq!(session.user_id, "1");
        assert_eq!(stored_ids(&store)?, [Value::Number(1.0)]);
        assert_eq!(
            required(store.lock()?.sessions.snapshot()?.first())?
                .user_id
                .field_value(),
            raw_owner
        );
        let single = store.get_session_snapshot(&session.token).await?;
        let bulk = store
            .get_session_snapshots(std::slice::from_ref(&session.token), true)
            .await?;
        if joins {
            assert!(single.is_none());
            assert!(bulk.is_empty());
        } else {
            let (projected, child) = required(single)?;
            assert_eq!(projected.user_id, "1");
            assert!(child.is_none());
            assert_eq!(bulk.len(), 1);
            let (projected, child) = required(bulk.first())?;
            assert_eq!(projected.user_id, "1");
            assert_eq!(required(child.as_ref())?.user.id, "1");
        }

        let account = store
            .create_account(CreateAccount {
                user_id: crate::SchemaValue::from_field(raw_owner.clone()),
                provider_id: "fixture".into(),
                account_id: "array-owner".into(),
                ..Default::default()
            })
            .await?;
        assert_eq!(account.user_id, "1");
        assert_eq!(
            required(store.lock()?.accounts.snapshot()?.first())?.get("userId"),
            Some(&raw_owner)
        );
        let owner = required(store.get_account_owner("fixture", "array-owner").await?)?;
        assert_eq!(owner.account.user_id, "1");
        if joins {
            assert!(owner.user.is_none());
        } else {
            assert_eq!(required(owner.user)?.id, "1");
        }
    }
    Ok(())
}

#[tokio::test]
async fn member_joins_and_full_details_resolve_users_at_their_projection_stage() -> AuthResult<()> {
    use crate::organization_fields::OrganizationFields;
    use crate::user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
    };

    for joins in [false, true] {
        let store = serial_store(joins);
        for name in ["stored-owner", "projected-owner"] {
            let _ = store.create_user(user(name)).await?;
        }
        store.configure_organization_fields(OrganizationFields {
            member: UserConfig {
                additional_fields: Some(
                    [(
                        "userId".into(),
                        UserFieldConfig {
                            references: Some(UserFieldReference {
                                model: "user".into(),
                                field: "id".into(),
                            }),
                            transform: Some(FieldTransforms {
                                output: Some(UserFieldTransform::new(|value| {
                                    assert_eq!(value, Value::Number(1.0));
                                    Ok(Value::from("2"))
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
            ..Default::default()
        })?;
        let organization = store
            .create_organization(CreateOrganization::new("Projection", "projection"))
            .await?;
        let member = store
            .create_member(CreateMember::new(
                organization.id.typed()?.clone(),
                "1",
                "member",
            ))
            .await?;
        assert_eq!(member.user_id, "2");
        assert_eq!(
            required(store.lock()?.members.snapshot()?.first())?
                .user_id
                .field_value(),
            Value::Number(1.0)
        );
        let joined = required(
            store
                .get_member_with_user(organization.id.typed()?, "1")
                .await?,
        )?;
        assert_eq!(joined.member.user_id, "2");
        assert_eq!(joined.user.id, if joins { "1" } else { "2" });
        let details = required(
            store
                .get_organization_details(OrganizationDetailsQuery {
                    organization: OrganizationKey::Id(organization.id.typed()?),
                    members_limit: None,
                    users_limit: 10.0,
                    include_teams: false,
                })
                .await?,
        )?;
        assert_eq!(details.members.len(), 1);
        let member = required(details.members.first())?;
        assert_eq!(member.member.user_id, "2");
        assert_eq!(member.user.id, "2");
    }
    Ok(())
}
