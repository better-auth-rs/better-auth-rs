use super::*;

fn output_identity(name: &'static str, events: &Events) -> UserFieldConfig {
    let events = events.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new(move |value| {
                events.push(name, "output", value.clone())?;
                Ok(value)
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn member_fields(
    events: &Events,
    team_id: UserFieldConfig,
    user_id: UserFieldConfig,
) -> UserConfig {
    let key_events = events.clone();
    let date_events = events.clone();
    declaration([
        ("teamId", team_id),
        ("userId", user_id),
        (
            "membershipKey",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        key_events.push("membershipKey", "output", value.clone())?;
                        Ok(format!(
                            "visible:{}",
                            required(value.as_str(), "Expected a stored TeamMember key")?
                        )
                        .into())
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
                    input: Some(UserFieldTransform::new(|_| Ok(date(0).into()))),
                    output: Some(UserFieldTransform::new(move |value| {
                        date_events.push("createdAt", "output", value)?;
                        Ok(date(1).into())
                    })),
                }),
                ..Default::default()
            },
        ),
    ])
}

fn team_name(events: &Events, reject_first: bool) -> UserFieldConfig {
    let events = events.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new(move |value| {
                events.push("team.name", "output", value.clone())?;
                if reject_first && value.as_str() == Some("Team A") {
                    return Err(AuthError::internal("team-member-team-name-failed"));
                }
                Ok(format!(
                    "Visible {}",
                    required(value.as_str(), "Expected a stored Team name")?
                )
                .into())
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn member_events(storage: &Storage) -> AuthResult<Vec<FieldValue>> {
    Ok(vec![
        event("teamId", "output", "team-a".into()),
        event("userId", "output", "user-a".into()),
        event("membershipKey", "output", key("team-a", "user-a")?.into()),
        event("createdAt", "output", storage.stored_date(0)),
    ])
}

async fn projected_parent<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    joins: bool,
) -> AuthResult<()> {
    let events = Events::default();
    let reading = Arc::new(AtomicBool::new(false));
    let output_reading = Arc::clone(&reading);
    let team_events = events.clone();
    let fields = member_fields(
        &events,
        UserFieldConfig {
            references: Some(UserFieldReference {
                model: "team".into(),
                field: "id".into(),
                ..Default::default()
            }),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    team_events.push("teamId", "output", value.clone())?;
                    Ok(if output_reading.load(Ordering::SeqCst) {
                        "team-b".into()
                    } else {
                        value
                    })
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
        output_identity("userId", &events),
    );
    let auth = reader(
        raw,
        fields,
        Some(declaration([("name", team_name(&events, false))])),
        false,
        joins,
        "member-a",
    )
    .await?;
    let store = auth.store();
    let created = required(
        store
            .add_team_member(&"team-a".into(), "user-a", None)
            .await?,
        "Expected the TeamMember seed",
    )?;
    assert_eq!(
        public(created)?,
        member("member-a", "team-a", "user-a", date(1).into())
    );
    let _ = events.take()?;
    reading.store(true, Ordering::SeqCst);

    let teams = store.list_user_teams("user-a").await?;
    let actual = teams
        .iter()
        .map(AuthRecordFields::field_values)
        .collect::<AuthResult<Vec<_>>>()?;
    let (id, raw_name, name) = if joins {
        ("team-a", "Team A", "Visible Team A")
    } else {
        ("team-b", "Team B", "Visible Team B")
    };
    assert_eq!(actual, vec![team(id, name, None)]);
    let mut expected_events = member_events(&storage)?;
    expected_events.push(event("team.name", "output", raw_name.into()));
    assert_eq!(events.take()?, expected_events);
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
        .await
}

#[derive(Clone, Copy)]
enum Relation {
    Missing,
    Many,
    ManyFirstError,
}

async fn replacement_relation<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    joins: bool,
    relation: Relation,
) -> AuthResult<()> {
    let events = Events::default();
    let member_id = match relation {
        Relation::Missing => "member-a",
        Relation::Many | Relation::ManyFirstError => "organization",
    };
    let fields = member_fields(
        &events,
        identity("teamId", &events),
        identity("userId", &events),
    );
    let writer = reader(Arc::clone(&raw), fields, None, false, joins, member_id).await?;
    let created = required(
        writer
            .store()
            .add_team_member(&"team-a".into(), "user-a", None)
            .await?,
        "Expected the TeamMember seed",
    )?;
    assert_eq!(
        public(created)?,
        member(member_id, "team-a", "user-a", date(1).into())
    );

    let mut user_id = identity("userId", &events);
    let mut team_fields = vec![(
        "name",
        team_name(&events, matches!(relation, Relation::ManyFirstError)),
    )];
    let date_events = events.clone();
    team_fields.push((
        "createdAt",
        UserFieldConfig {
            field_type: UserFieldType::Date,
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    date_events.push("team.createdAt", "output", value.clone())?;
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    ));
    match relation {
        Relation::Missing => {
            user_id.references = Some(UserFieldReference {
                model: "team".into(),
                field: "id".into(),
                ..Default::default()
            });
        }
        Relation::Many | Relation::ManyFirstError => {
            team_fields.push((
                "organizationId",
                UserFieldConfig {
                    references: Some(UserFieldReference {
                        model: "teamMember".into(),
                        field: "id".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ));
        }
    }
    let auth = reader(
        raw,
        member_fields(&events, identity("teamId", &events), user_id),
        Some(declaration(team_fields)),
        false,
        joins,
        member_id,
    )
    .await?;
    let _ = events.take()?;
    let result = auth.store().list_user_teams("user-a").await;
    let mut expected_events = member_events(&storage)?;
    match relation {
        Relation::Missing => {
            if let Err(AuthError::TypeError(message)) = &result {
                let backend = if matches!(&storage, Storage::Memory(_)) {
                    "memory"
                } else {
                    "sqlite"
                };
                eprintln!(
                    "TeamMember missing join error: backend={backend} joins={joins} class=TypeError message={message:?}"
                );
            }
            assert!(
                matches!(&result, Err(AuthError::TypeError(_))),
                "{result:?}"
            );
        }
        Relation::Many => {
            let actual = result?
                .iter()
                .map(AuthRecordFields::field_values)
                .collect::<AuthResult<Vec<_>>>()?;
            let expected: FieldMap = [
                ("0".into(), team("team-a", "Visible Team A", Some(1)).into()),
                ("1".into(), team("team-b", "Visible Team B", Some(0)).into()),
            ]
            .into();
            assert_eq!(actual, vec![expected]);
            expected_events.extend([
                event("team.name", "output", "Team A".into()),
                event("team.createdAt", "output", storage.stored_date(0)),
                event("team.name", "output", "Team B".into()),
                event("team.createdAt", "output", storage.stored_date(0)),
            ]);
        }
        Relation::ManyFirstError => {
            original_error(
                required(result.err(), "Expected first joined Team output failure")?,
                "team-member-team-name-failed",
            );
            expected_events.push(event("team.name", "output", "Team A".into()));
        }
    }
    assert_eq!(events.take()?, expected_events);
    storage
        .assert_rows(
            vec![physical(
                member_id,
                "team-a",
                "user-a",
                &key("team-a", "user-a")?,
                0,
            )],
            [1, 0],
        )
        .await
}

#[tokio::test]
async fn memory_joins_project_parent_fields_before_the_team() -> AuthResult<()> {
    for joins in [false, true] {
        let (raw, storage) = memory_fixture().await?;
        projected_parent(raw, storage, joins).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_joins_project_parent_fields_before_the_team() -> AuthResult<()> {
    for joins in [false, true] {
        let (raw, storage) = sqlite_fixture().await?;
        projected_parent(raw, storage, joins).await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_joins_preserve_replacement_relations() -> AuthResult<()> {
    for joins in [false, true] {
        for relation in [Relation::Missing, Relation::Many, Relation::ManyFirstError] {
            let (raw, storage) = memory_fixture().await?;
            replacement_relation(raw, storage, joins, relation).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_joins_preserve_replacement_relations() -> AuthResult<()> {
    for joins in [false, true] {
        for relation in [Relation::Missing, Relation::Many, Relation::ManyFirstError] {
            let (raw, storage) = sqlite_fixture().await?;
            replacement_relation(raw, storage, joins, relation).await?;
        }
    }
    Ok(())
}
