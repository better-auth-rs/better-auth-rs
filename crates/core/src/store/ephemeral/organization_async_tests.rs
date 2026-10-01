use super::*;
use crate::{
    CreateTeam, UpdateTeam,
    organization_fields::OrganizationFields,
    store::TeamStore,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};
use serde_json::json;
use tokio::sync::{Barrier, Notify};

#[tokio::test]
async fn async_team_update_applies_patch_to_latest_row_without_holding_state_lock() -> AuthResult<()>
{
    let store = EphemeralStore::new(test_config());
    let team = store
        .create_team(CreateTeam {
            name: "before".into(),
            organization_id: "organization".into(),
            ..Default::default()
        })
        .await?;
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let mut fields = OrganizationFields::default();
    let _ = fields.team.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new_async({
                    let started = started.clone();
                    let release = release.clone();
                    move |value| {
                        let started = started.clone();
                        let release = release.clone();
                        async move {
                            started.notify_one();
                            release.notified().await;
                            Ok(value)
                        }
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    let pending = tokio::spawn({
        let store = store.clone();
        let id = team.id.typed()?.clone();
        async move {
            store
                .update_team(
                    &id,
                    UpdateTeam {
                        name: Some("after".into()),
                        ..Default::default()
                    },
                )
                .await
        }
    });
    started.notified().await;
    let during = store.get_team(team.id.typed()?).await?.unwrap();
    assert_eq!(during.name, "before");
    let created_at = "2020-01-02T03:04:05Z".parse::<DateTime<Utc>>().unwrap();
    let changed = store
        .update_team(
            team.id.typed()?,
            UpdateTeam {
                created_at: Some(created_at),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(*changed.created_at.typed()?, created_at);
    release.notify_one();
    let updated = pending.await.unwrap()?;
    assert_eq!(updated.name, "after");
    assert_eq!(*updated.created_at.typed()?, created_at);
    assert_eq!(store.get_team(team.id.typed()?).await?.unwrap(), updated);
    Ok(())
}

#[tokio::test]
async fn async_competing_reservations_keep_the_last_seat_atomic() -> AuthResult<()> {
    for maximum in [1, 2] {
        let store = EphemeralStore::new(test_config());
        let team = store
            .create_team(CreateTeam {
                name: "Team".into(),
                organization_id: "organization".into(),
                ..Default::default()
            })
            .await?;
        let barrier = Arc::new(Barrier::new(2));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut fields = OrganizationFields::default();
        let _ = fields.team.fields_mut().insert(
            "memberCount".into(),
            UserFieldConfig {
                field_type: UserFieldType::Number,
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new_async({
                        let calls = calls.clone();
                        move |value| {
                            let barrier = barrier.clone();
                            let calls = calls.clone();
                            async move {
                                let _ = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                barrier.wait().await;
                                Ok(value)
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
            store.add_team_member(&team.id, "first", Some(maximum)),
            store.add_team_member(&team.id, "second", Some(maximum)),
        );
        let (winner, other) = if matches!(a, Ok(Some(_))) {
            (a, b)
        } else {
            (b, a)
        };
        assert!(winner?.is_some());
        if maximum == 1 {
            assert!(other?.is_none());
        } else {
            assert!(matches!(other, Err(AuthError::Conflict(_))));
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(store.count_team_members(team.id.typed()?).await?, 1);
        assert_eq!(
            store
                .lock()?
                .teams
                .get(&team.id)?
                .unwrap()
                .additional_fields["memberCount"],
            json!(1.0)
        );
    }
    Ok(())
}

#[tokio::test]
async fn canceled_reservation_has_no_seat_or_member_write() -> AuthResult<()> {
    let store = EphemeralStore::new(test_config());
    let team = store
        .create_team(CreateTeam {
            name: "Team".into(),
            organization_id: "organization".into(),
            ..Default::default()
        })
        .await?;
    let started = Arc::new(Notify::new());
    let mut fields = OrganizationFields::default();
    let _ = fields.team.fields_mut().insert(
        "memberCount".into(),
        UserFieldConfig {
            field_type: UserFieldType::Number,
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new_async({
                    let started = started.clone();
                    move |_| {
                        let started = started.clone();
                        async move {
                            started.notify_one();
                            std::future::pending().await
                        }
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    let task = tokio::spawn({
        let store = store.clone();
        let id = team.id.clone();
        async move { store.add_team_member(&id, "member", Some(1)).await }
    });
    started.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(store.count_team_members(team.id.typed()?).await?, 0);
    assert_eq!(
        store
            .lock()?
            .teams
            .get(&team.id)?
            .unwrap()
            .additional_fields["memberCount"],
        0
    );
    Ok(())
}

#[tokio::test]
async fn reservation_callback_can_update_an_unrelated_team_field() -> AuthResult<()> {
    let store = EphemeralStore::new(test_config());
    let team = store
        .create_team(CreateTeam {
            name: "Team".into(),
            organization_id: "organization".into(),
            ..Default::default()
        })
        .await?;
    let date = "2020-01-02T03:04:05Z".parse::<DateTime<Utc>>().unwrap();
    let mut fields = OrganizationFields::default();
    let _ = fields.team.fields_mut().insert(
        "memberCount".into(),
        UserFieldConfig {
            field_type: UserFieldType::Number,
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new_async({
                    let store = store.clone();
                    let id = team.id.typed()?.clone();
                    move |value| {
                        let store = store.clone();
                        let id = id.clone();
                        async move {
                            let _ = store
                                .update_team(
                                    &id,
                                    UpdateTeam {
                                        created_at: Some(date),
                                        ..Default::default()
                                    },
                                )
                                .await?;
                            Ok(value)
                        }
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    assert!(
        store
            .add_team_member(&team.id, "member", Some(1))
            .await?
            .is_some()
    );
    let row = store.lock()?.teams.get(&team.id)?.unwrap();
    assert_eq!(*row.created_at.typed()?, date);
    assert_eq!(row.additional_fields["memberCount"], json!(1.0));
    store.configure_organization_fields(Default::default())?;
    Ok(())
}

#[tokio::test]
async fn full_team_keeps_the_prepared_counter_repair() -> AuthResult<()> {
    let store = EphemeralStore::new(test_config());
    let team = store
        .create_team(CreateTeam {
            name: "Team".into(),
            organization_id: "organization".into(),
            ..Default::default()
        })
        .await?;
    let _ = store.add_team_member(&team.id, "first", Some(1)).await?;
    let mut fields = OrganizationFields::default();
    let _ = fields.team.fields_mut().insert(
        "memberCount".into(),
        UserFieldConfig {
            field_type: UserFieldType::Number,
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new_async(
                    |value| async move { Ok(value) },
                )),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    let _ = store
        .update_team(
            team.id.typed()?,
            UpdateTeam {
                additional_fields: [("memberCount".into(), json!(0))].into_iter().collect(),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(
        store
            .lock()?
            .teams
            .get(&team.id)?
            .unwrap()
            .additional_fields["memberCount"],
        0
    );
    assert!(
        store
            .add_team_member(&team.id, "second", Some(1))
            .await?
            .is_none()
    );
    assert_eq!(store.count_team_members(team.id.typed()?).await?, 1);
    assert_eq!(
        store
            .lock()?
            .teams
            .get(&team.id)?
            .unwrap()
            .additional_fields["memberCount"],
        json!(1)
    );
    Ok(())
}

#[tokio::test]
async fn invitation_member_output_failure_compensates_without_member_seat_or_session_write()
-> AuthResult<()> {
    let store = EphemeralStore::new(test_config());
    let team = store
        .create_team(CreateTeam {
            name: "Team".into(),
            organization_id: "organization".into(),
            ..Default::default()
        })
        .await?;
    let mut input = CreateInvitation::new(
        "organization",
        "member@example.com",
        "member",
        "owner",
        Utc::now() + chrono::Duration::days(1),
    );
    input.team_id = Some(team.id.typed()?.clone());
    let invitation = store.create_invitation(input).await?;
    let session = store
        .create_session(CreateSession {
            user_id: "member".into(),
            expires_at: Utc::now() + chrono::Duration::days(1),
            additional_fields: Default::default(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut fields = OrganizationFields::default();
    let _ = fields.invitation.fields_mut().insert(
        "status".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new_async({
                    let events = events.clone();
                    move |value| {
                        let events = events.clone();
                        async move {
                            events.lock().unwrap().push(value.clone());
                            Ok(value)
                        }
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let _ = fields.member.fields_mut().insert(
        "role".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new_async(|_| async {
                    Err(AuthError::bad_request("member output rejected"))
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    let error = store
        .accept_invitation_with_teams(
            invitation.id.typed()?,
            "member",
            Some(&session.token),
            true,
            crate::store::TeamMemberLimits::Fixed(Some(1)),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        AuthError::bad_request("member output rejected").to_string()
    );
    assert_eq!(
        *events.lock().unwrap(),
        vec![Some(json!("accepted")), Some(json!("pending"))]
    );
    let state = store.lock()?;
    assert!(state.invitations.get(&invitation.id)?.unwrap().is_pending());
    assert_eq!(state.members.len(), 0);
    assert_eq!(state.team_members.len(), 0);
    assert_eq!(
        state.teams.get(&team.id)?.unwrap().additional_fields["memberCount"],
        0
    );
    assert_eq!(
        state
            .sessions
            .find(|row| row.token == session.token)?
            .unwrap(),
        session
    );
    Ok(())
}

#[tokio::test]
async fn async_serial_creates_allocate_ids_at_insert_after_callbacks() -> AuthResult<()> {
    let mut config = (*test_config()).clone();
    config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
    let store = EphemeralStore::new(Arc::new(config));
    let barrier = Arc::new(Barrier::new(2));
    let mut fields = OrganizationFields::default();
    let _ = fields.team.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new_async(move |value| {
                    let barrier = barrier.clone();
                    async move {
                        barrier.wait().await;
                        Ok(value)
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    let (first, second) = tokio::join!(
        store.create_team(CreateTeam {
            name: "first".into(),
            organization_id: "organization".into(),
            ..Default::default()
        }),
        store.create_team(CreateTeam {
            name: "second".into(),
            organization_id: "organization".into(),
            ..Default::default()
        }),
    );
    let mut ids = [first?.id.typed()?.clone(), second?.id.typed()?.clone()];
    ids.sort();
    assert_eq!(ids, ["1", "2"]);
    assert_eq!(store.count_organization_teams("organization").await?, 2);
    Ok(())
}

#[tokio::test]
async fn async_team_input_failure_has_no_write_and_output_failure_keeps_write() -> AuthResult<()> {
    let store = EphemeralStore::new(test_config());
    let team = store
        .create_team(CreateTeam {
            name: "before".into(),
            organization_id: "organization".into(),
            ..Default::default()
        })
        .await?;
    let mut fields = OrganizationFields::default();
    let _ = fields.team.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new_async(|value| async move {
                    if value == Some(json!("input-error")) {
                        return Err(AuthError::bad_request("input rejected"));
                    }
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new_async(|value| async move {
                    if value == Some(json!("output-error")) {
                        return Err(AuthError::bad_request("output rejected"));
                    }
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    let error = store
        .update_team(
            team.id.typed()?,
            UpdateTeam {
                name: Some("input-error".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        AuthError::bad_request("input rejected").to_string()
    );
    assert_eq!(store.lock()?.teams.get(&team.id)?.unwrap().name, "before");
    let error = store
        .update_team(
            team.id.typed()?,
            UpdateTeam {
                name: Some("output-error".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        AuthError::bad_request("output rejected").to_string()
    );
    assert_eq!(
        store.lock()?.teams.get(&team.id)?.unwrap().name,
        "output-error"
    );
    Ok(())
}
