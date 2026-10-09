use super::*;

fn team_fields(events: &Events, removing: Arc<AtomicBool>, reject: bool) -> UserConfig {
    let name_events = events.clone();
    let count_events = events.clone();
    let date_events = events.clone();
    declaration([
        (
            "name",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        name_events.push("team.name", "output", value.clone())?;
                        Ok(value)
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "memberCount",
            UserFieldConfig {
                field_type: UserFieldType::Number,
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        count_events.push("team.memberCount", "output", value.clone())?;
                        if reject && removing.load(Ordering::SeqCst) {
                            return Err(AuthError::internal("team-remove-output-failed"));
                        }
                        Ok(value)
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "createdAt",
            UserFieldConfig {
                field_type: UserFieldType::Date,
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        date_events.push("team.createdAt", "output", value)?;
                        Ok(date(0).into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
    ])
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    reject: bool,
) -> AuthResult<()> {
    let events = Events::default();
    let removing = Arc::new(AtomicBool::new(false));
    let member_fields = declaration([(
        "createdAt",
        UserFieldConfig {
            field_type: UserFieldType::Date,
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| Ok(date(0).into()))),
                ..Default::default()
            }),
            ..Default::default()
        },
    )]);
    let auth = reader(
        raw,
        member_fields,
        Some(team_fields(&events, removing.clone(), reject)),
        false,
        false,
        "member-a",
    )
    .await?;
    let created = required(
        auth.store()
            .add_team_member(&"team-a".into(), "user-a", None)
            .await?,
        "Expected membership before removal",
    )?;
    assert_eq!(
        public(created)?,
        member("member-a", "team-a", "user-a", date(0).into())
    );
    storage
        .assert_rows(
            vec![physical(
                "member-a",
                "team-a",
                "user-a",
                &key("team-a", "user-a")?,
                0,
            )],
            [1, 0],
        )
        .await?;
    let _ = events.take()?;
    removing.store(true, Ordering::SeqCst);
    let result = auth.store().remove_team_member("team-a", "user-a").await;
    if reject {
        original_error(
            required(result.err(), "Expected original removal output error")?,
            "team-remove-output-failed",
        );
    } else {
        result?;
    }
    let mut expected = vec![
        event("team.name", "output", "Team A".into()),
        event("team.memberCount", "output", 0.into()),
    ];
    if !reject {
        expected.push(event("team.createdAt", "output", storage.stored_date(0)));
    }
    assert_eq!(events.take()?, expected);
    storage.assert_rows(vec![], [0, 0]).await?;
    auth.store().remove_team_member("team-a", "user-a").await?;
    assert_eq!(events.take()?, []);
    storage.assert_rows(vec![], [0, 0]).await
}

#[tokio::test]
async fn memory_removal_preserves_deleted_rows_and_released_seats_after_output_failure()
-> AuthResult<()> {
    for reject in [false, true] {
        let (raw, storage) = memory_fixture().await?;
        check(raw, storage, reject).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_removal_preserves_deleted_rows_and_released_seats_after_output_failure()
-> AuthResult<()> {
    for reject in [false, true] {
        let (raw, storage) = sqlite_fixture().await?;
        check(raw, storage, reject).await?;
    }
    Ok(())
}
