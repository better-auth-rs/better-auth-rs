use super::*;
use crate::user_fields::UserFieldTransform;

#[tokio::test]
async fn organization_role_batch_matches_native_scope_and_does_not_project_writes() {
    use crate::user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldType};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let outputs = Arc::new(AtomicUsize::new(0));
    let counter = outputs.clone();
    let store = EphemeralStore::new(test_config());
    store
        .configure_organization_fields(crate::organization_fields::OrganizationFields {
            organization_role: UserConfig {
                additional_fields: Some(
                    [
                        (
                            "organizationId".into(),
                            UserFieldConfig {
                                field_type: UserFieldType::Number,
                                ..Default::default()
                            },
                        ),
                        (
                            "permission".into(),
                            UserFieldConfig {
                                transform: Some(FieldTransforms {
                                    input: None,
                                    output: Some(UserFieldTransform::new(move |value| {
                                        counter.fetch_add(1, Ordering::SeqCst);
                                        Ok(value)
                                    })),
                                }),
                                ..Default::default()
                            },
                        ),
                    ]
                    .into(),
                ),
            },
            ..Default::default()
        })
        .unwrap();
    let _ = store
        .create_organization_role(CreateOrganizationRole {
            organization_id: crate::SchemaValue::from_field(Value::Number(7.0)),
            role: "editor".into(),
            permission: FieldMap::new().into(),
            additional_fields: FieldMap::new(),
        })
        .await
        .unwrap();
    {
        let mut state = store.lock().unwrap();
        let mut duplicate = state.organization_roles.snapshot().unwrap().pop().unwrap();
        let _ = duplicate.insert("id".into(), "second".into());
        state.organization_roles.push(duplicate.clone());
        let _ = duplicate.insert("id".into(), "other-tenant".into());
        let _ = duplicate.insert("organizationId".into(), Value::Number(8.0));
        state.organization_roles.push(duplicate);
    }
    outputs.store(0, Ordering::SeqCst);
    let selectors: FieldMap = [
        ("organizationId".into(), Value::Number(7.0)),
        ("role".into(), "editor".into()),
    ]
    .into();
    assert_eq!(
        store
            .update_organization_roles(
                &selectors,
                UpdateOrganizationRole {
                    role: Some("writer".into()),
                    ..Default::default()
                }
            )
            .await
            .unwrap(),
        2
    );
    assert_eq!(outputs.load(Ordering::SeqCst), 0);
    let rows = store.lock().unwrap().organization_roles.snapshot().unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| (row["organizationId"].clone(), row["role"].clone()))
            .collect::<Vec<_>>(),
        vec![
            (Value::Number(7.0), "writer".into()),
            (Value::Number(7.0), "writer".into()),
            (Value::Number(8.0), "editor".into()),
        ]
    );
    assert!(
        store
            .find_organization_role_by_fields(&selectors)
            .await
            .unwrap()
            .is_none()
    );
    let selectors: FieldMap = [
        ("organizationId".into(), Value::Number(7.0)),
        ("role".into(), "writer".into()),
    ]
    .into();
    store
        .delete_organization_role_by_fields(&selectors)
        .await
        .unwrap();
    assert_eq!(
        store
            .count_organization_roles_value(&Value::Number(7.0))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .count_organization_roles_value(&Value::Number(8.0))
            .await
            .unwrap(),
        1
    );
    assert_eq!(outputs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn memory_organization_deletion_cleans_teams_and_roles() {
    let store = EphemeralStore::new(test_config());
    let org = store
        .create_organization(CreateOrganization::new("one", "one"))
        .await
        .unwrap();
    let team = store
        .create_team(CreateTeam {
            name: "one".into(),
            organization_id: org.id.clone(),
            updated_at: None,
            ..Default::default()
        })
        .await
        .unwrap();
    let first = store
        .add_team_member(&team.id, "user-one", Some(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .add_team_member(&team.id, "user-one", Some(1))
            .await
            .unwrap()
            .unwrap()
            .id,
        first.id
    );
    assert!(
        store
            .add_team_member(&team.id, "user-two", Some(1))
            .await
            .unwrap()
            .is_none()
    );
    let role = store
        .create_organization_role(CreateOrganizationRole {
            additional_fields: Default::default(),
            organization_id: org.id.clone(),
            role: "editor".into(),
            permission: Value::from_json(serde_json::json!({"team":["create"]})).unwrap(),
        })
        .await
        .unwrap();
    store
        .delete_organization(org.id.typed().unwrap())
        .await
        .unwrap();
    assert!(
        store
            .get_team(team.id.typed().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .list_team_members(team.id.typed().unwrap())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .get_organization_role(role.id.typed().unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn memory_team_deletion_rolls_back_invitation_output_errors() {
    use crate::{
        organization_fields::OrganizationFields,
        user_fields::{UserConfig, UserFieldConfig},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    for (failure_stage, asynchronous) in [
        ("expired", false),
        ("unassigned", false),
        ("updated", false),
        ("expired", true),
        ("unassigned", true),
        ("updated", true),
    ] {
        let store = EphemeralStore::new(test_config());
        let config = OrganizationFields {
            invitation: UserConfig {
                additional_fields: Some(
                    [(
                        "marker".into(),
                        UserFieldConfig {
                            required: Some(false),
                            default_value: Some(Value::from("created")),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
            ..Default::default()
        };
        store.configure_organization_fields(config.clone()).unwrap();
        let org = store
            .create_organization(CreateOrganization::new("organization", "organization"))
            .await
            .unwrap();
        let team = store
            .create_team(CreateTeam {
                name: "team".into(),
                organization_id: org.id.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        let _ = store
            .add_team_member(&team.id, "owner", None)
            .await
            .unwrap();
        let expires = Utc::now() + chrono::Duration::days(1);
        let mut live = Vec::new();
        for _ in 0..2 {
            let mut input = CreateInvitation::new(
                org.id.typed().unwrap(),
                "recipient@example.com",
                "member",
                "owner",
                expires.into(),
            );
            input.team_id = Some(team.id.typed().unwrap().clone());
            live.push(store.create_invitation(input).await.unwrap().id);
        }
        if failure_stage != "updated" {
            let mut input = CreateInvitation::new(
                org.id.typed().unwrap(),
                "other@example.com",
                "member",
                "owner",
                expires.into(),
            );
            if failure_stage == "expired" {
                input.team_id = Some(team.id.typed().unwrap().clone());
                input.expires_at = (Utc::now() - chrono::Duration::days(1)).into();
            }
            let _ = input
                .additional_fields
                .insert("marker".into(), Value::from("read-fail"));
            let _ = store.create_invitation(input).await.unwrap();
        }
        let updates = Arc::new(AtomicUsize::new(0));
        let count = updates.clone();
        let mut failing = config.clone();
        let marker = failing.invitation.fields_mut().get_mut("marker").unwrap();
        marker.on_update = Some(Arc::new(move || {
            Ok(Value::from(format!(
                "updated-{}",
                count.fetch_add(1, Ordering::SeqCst) + 1
            )))
        }));
        let output = |value| {
            if value == Value::from("read-fail") || value == Value::from("updated-2") {
                Err(AuthError::bad_request("invitation output failed"))
            } else {
                Ok(value)
            }
        };
        marker.transform.get_or_insert_default().output = Some(if asynchronous {
            UserFieldTransform::new_async(move |value| async move { output(value) })
        } else {
            UserFieldTransform::new(output)
        });
        store.configure_organization_fields(failing).unwrap();
        let error = store
            .delete_team(team.id.typed().unwrap())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("invitation output failed"));
        assert_eq!(
            updates.load(Ordering::SeqCst),
            if failure_stage == "updated" { 2 } else { 0 }
        );
        store.configure_organization_fields(config).unwrap();
        assert!(
            store
                .get_team(team.id.typed().unwrap())
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            store
                .list_team_members(team.id.typed().unwrap())
                .await
                .unwrap()
                .len(),
            1
        );
        for id in live {
            let row = store
                .get_invitation_by_id(id.typed().unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.team_id.typed().unwrap().as_deref(), team.id.as_str());
            assert_eq!(
                row.additional_fields.get("marker"),
                Some(&Value::from("created"))
            );
        }
    }
}
