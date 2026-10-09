use super::*;
use better_auth_core::store::TeamDetails;

fn seed_fields() -> UserConfig {
    declaration([(
        "createdAt",
        UserFieldConfig {
            field_type: UserFieldType::Date,
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| Ok(date(0).into()))),
                ..Default::default()
            }),
            ..Default::default()
        },
    )])
}

pub(super) async fn seed_member<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    joins: bool,
    id: &'static str,
    team_id: &str,
    user_id: &str,
) -> AuthResult<()> {
    let writer = reader(raw, seed_fields(), None, false, joins, id).await?;
    let created = required(
        writer
            .store()
            .add_team_member(&team_id.into(), user_id, None)
            .await?,
        "Expected a membership seed",
    )?;
    assert_eq!(
        public(created)?,
        member(id, team_id, user_id, date(0).into())
    );
    Ok(())
}

pub(super) fn parent_fields(events: &Events, remap: bool) -> UserConfig {
    let events = events.clone();
    declaration([(
        "name",
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    events.push("team.name", "output", value.clone())?;
                    Ok(if remap { "team-b".into() } else { value })
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    )])
}

pub(super) fn member_fields(
    events: &Events,
    reference: &str,
    unique: bool,
    fail: bool,
) -> UserConfig {
    declaration(
        ["teamId", "userId", "membershipKey", "createdAt"]
            .into_iter()
            .map(|name| {
                let events = events.clone();
                let field_type = if name == "createdAt" {
                    UserFieldType::Date
                } else {
                    UserFieldType::String
                };
                (
                    name,
                    UserFieldConfig {
                        field_type,
                        references: (name == "teamId").then(|| UserFieldReference {
                            model: "team".into(),
                            field: reference.into(),
                            ..Default::default()
                        }),
                        unique: (name == "teamId").then_some(unique),
                        transform: Some(FieldTransforms {
                            output: Some(UserFieldTransform::new(move |value| {
                                events.push(name, "output", value.clone())?;
                                if fail && name == "userId" {
                                    return Err(AuthError::internal(
                                        "team-details-member-output-failed",
                                    ));
                                }
                                Ok(if name == "createdAt" {
                                    date(1).into()
                                } else {
                                    value
                                })
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
            }),
    )
}

pub(super) fn member_events(
    storage: &Storage,
    team_id: &str,
    user_id: &str,
) -> AuthResult<Vec<FieldValue>> {
    Ok(vec![
        event("teamId", "output", team_id.into()),
        event("userId", "output", user_id.into()),
        event("membershipKey", "output", key(team_id, user_id)?.into()),
        event("createdAt", "output", storage.stored_date(0)),
    ])
}

fn output(details: TeamDetails) -> AuthResult<FieldMap> {
    let (team, members) = details.into_public_parts(&UserConfig::default())?;
    let mut output = team.field_values()?;
    if let Some(members) = members {
        let members = members
            .into_iter()
            .map(public)
            .map(|row| row.map(FieldValue::from))
            .collect::<AuthResult<Vec<_>>>()?;
        let _ = output.insert("members".into(), members.into());
    }
    Ok(output)
}

fn expected_team(id: &str, name: &str, members: Option<Vec<FieldMap>>) -> FieldMap {
    let mut output = team(id, name, None);
    if let Some(members) = members {
        let _ = output.insert(
            "members".into(),
            members
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    output
}

async fn scoped<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    joins: bool,
) -> AuthResult<()> {
    seed_member(Arc::clone(&raw), joins, "member-a", "team-a", "user-a").await?;
    let events = Events::default();
    let input = events.clone();
    let visible = events.clone();
    let mut fields = parent_fields(&events, false);
    let _ = fields.fields_mut().insert(
        "organizationId".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    input.push("team.organizationId", "input", value.clone())?;
                    Ok(
                        required(value.as_str(), "Expected organization query string")?
                            .trim()
                            .into(),
                    )
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    visible.push("team.organizationId", "output", value)?;
                    Ok("visible-organization".into())
                })),
            }),
            ..Default::default()
        },
    );
    let auth = reader(
        Arc::clone(&raw),
        member_fields(&events, "id", false, true),
        Some(fields),
        false,
        joins,
        "unused",
    )
    .await?;
    let store = auth.store();
    for (id, organization) in [
        ("missing-team", "organization"),
        ("team-a", "wrong-organization"),
    ] {
        assert!(
            store
                .get_team_details_value(&id.into(), Some(&organization.into()), true)
                .await?
                .is_none()
        );
        assert_eq!(
            events.take()?,
            vec![event("team.organizationId", "input", organization.into())]
        );
    }
    for organization in [Some(" organization "), None, Some("")] {
        let scope = organization.map(FieldValue::from);
        let details = required(
            store
                .get_team_details_value(&"team-a".into(), scope.as_ref(), false)
                .await?,
            "Expected a scoped Team",
        )?;
        let mut expected = expected_team("team-a", "Team A", None);
        let _ = expected.insert("organizationId".into(), "visible-organization".into());
        assert_eq!(output(details)?, expected);
        let mut expected_events = Vec::new();
        if organization == Some(" organization ") {
            expected_events.push(event(
                "team.organizationId",
                "input",
                " organization ".into(),
            ));
        }
        expected_events.extend([
            event("team.name", "output", "Team A".into()),
            event("team.organizationId", "output", "organization".into()),
        ]);
        assert_eq!(events.take()?, expected_events);
    }
    let mut without_relationship = member_fields(&events, "id", false, true);
    required(
        without_relationship.fields_mut().get_mut("teamId"),
        "Expected TeamMember teamId declaration",
    )?
    .references = None;
    let auth = reader(
        raw,
        without_relationship,
        Some(parent_fields(&events, false)),
        false,
        joins,
        "unused",
    )
    .await?;
    let details = required(
        auth.store()
            .get_team_details_value(&"team-a".into(), Some(&"organization".into()), false)
            .await?,
        "Expected Team without join resolution",
    )?;
    assert_eq!(output(details)?, expected_team("team-a", "Team A", None));
    assert_eq!(
        events.take()?,
        vec![event("team.name", "output", "Team A".into())]
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
        .await
}

async fn remapped_parent<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    joins: bool,
) -> AuthResult<()> {
    seed_member(Arc::clone(&raw), joins, "member-a", "team-a", "user-a").await?;
    seed_member(Arc::clone(&raw), joins, "member-b", "team-b", "user-b").await?;
    let _ = raw
        .update_team(
            "team-a",
            UpdateTeam {
                name: Some("team-a".into()),
                updated_at: Some(Some(date(0))),
                ..Default::default()
            },
        )
        .await?;
    let events = Events::default();
    let auth = reader(
        raw,
        member_fields(&events, "name", false, false),
        Some(parent_fields(&events, true)),
        false,
        joins,
        "unused",
    )
    .await?;
    let selected = if joins {
        ("member-a", "team-a", "user-a")
    } else {
        ("member-b", "team-b", "user-b")
    };
    let actual = required(
        auth.store()
            .get_team_details_value(&"team-a".into(), Some(&"organization".into()), true)
            .await?,
        "Expected Team details",
    )?;
    assert_eq!(
        output(actual)?,
        expected_team(
            "team-a",
            "team-b",
            Some(vec![member(
                selected.0,
                selected.1,
                selected.2,
                date(1).into()
            )])
        )
    );
    let mut expected_events = vec![event("team.name", "output", "team-a".into())];
    expected_events.extend(member_events(&storage, selected.1, selected.2)?);
    assert_eq!(events.take()?, expected_events);
    assert_eq!(
        storage.rows(EntityRole::TeamMember).await?,
        vec![
            storage.stored(physical(
                "member-a",
                "team-a",
                "user-a",
                &key("team-a", "user-a")?,
                0
            )),
            storage.stored(physical(
                "member-b",
                "team-b",
                "user-b",
                &key("team-b", "user-b")?,
                0
            )),
        ]
    );
    assert_eq!(
        storage.rows(EntityRole::Team).await?,
        vec![
            storage.stored(team("team-a", "team-a", Some(1))),
            storage.stored(team("team-b", "Team B", Some(1)))
        ]
    );
    Ok(())
}

async fn limited_or_failed<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    joins: bool,
    fail: bool,
) -> AuthResult<()> {
    seed_member(Arc::clone(&raw), joins, "member-a", "team-a", "user-a").await?;
    seed_member(Arc::clone(&raw), joins, "member-b", "team-a", "user-b").await?;
    let events = Events::default();
    let auth = reader_with_limit(
        raw,
        member_fields(&events, "id", false, fail),
        Some(parent_fields(&events, false)),
        false,
        joins,
        "unused",
        (!fail).then_some(1.0),
    )
    .await?;
    let result = auth
        .store()
        .get_team_details_value(&"team-a".into(), Some(&"organization".into()), true)
        .await;
    let mut expected_events = vec![event("team.name", "output", "Team A".into())];
    if fail {
        original_error(
            required(result.err(), "Expected membership output failure")?,
            "team-details-member-output-failed",
        );
        expected_events.extend([
            event("teamId", "output", "team-a".into()),
            event("userId", "output", "user-a".into()),
        ]);
    } else {
        assert_eq!(
            output(required(result?, "Expected limited Team details")?)?,
            expected_team(
                "team-a",
                "Team A",
                Some(vec![member("member-a", "team-a", "user-a", date(1).into())])
            )
        );
        expected_events.extend(member_events(&storage, "team-a", "user-a")?);
    }
    assert_eq!(events.take()?, expected_events);
    storage
        .assert_rows(
            vec![
                physical("member-a", "team-a", "user-a", &key("team-a", "user-a")?, 0),
                physical("member-b", "team-a", "user-b", &key("team-a", "user-b")?, 0),
            ],
            [2, 0],
        )
        .await
}

async fn singular<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    joins: bool,
) -> AuthResult<()> {
    seed_member(Arc::clone(&raw), joins, "member-a", "team-a", "user-a").await?;
    let events = Events::default();
    let auth = reader(
        raw,
        member_fields(&events, "id", true, false),
        Some(parent_fields(&events, false)),
        false,
        joins,
        "unused",
    )
    .await?;
    let result = auth
        .store()
        .get_team_details_value(&"team-a".into(), Some(&"organization".into()), true)
        .await?
        .ok_or_else(|| AuthError::internal("Expected singular Team details"))?
        .into_public_parts(&UserConfig::default());
    assert!(matches!(result, Err(AuthError::TypeError(_))), "{result:?}");
    let mut expected_events = vec![event("team.name", "output", "Team A".into())];
    expected_events.extend(member_events(&storage, "team-a", "user-a")?);
    assert_eq!(events.take()?, expected_events);
    let missing = required(
        auth.store()
            .get_team_details_value(&"team-b".into(), Some(&"organization".into()), true)
            .await?,
        "Expected Team with no membership",
    )?;
    assert_eq!(
        output(missing)?,
        expected_team("team-b", "Team B", Some(Vec::new()))
    );
    assert_eq!(
        events.take()?,
        vec![event("team.name", "output", "Team B".into())]
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
        .await
}

#[tokio::test]
async fn memory_details_preserve_scope_projection_and_join_boundaries() -> AuthResult<()> {
    for joins in [false, true] {
        let (raw, storage) = memory_fixture().await?;
        scoped(raw, storage, joins).await?;
        let (raw, storage) = memory_fixture().await?;
        remapped_parent(raw, storage, joins).await?;
        let (raw, storage) = memory_fixture().await?;
        singular(raw, storage, joins).await?;
        for fail in [false, true] {
            let (raw, storage) = memory_fixture().await?;
            limited_or_failed(raw, storage, joins, fail).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_details_preserve_scope_projection_and_join_boundaries() -> AuthResult<()> {
    for joins in [false, true] {
        let (raw, storage) = sqlite_fixture().await?;
        scoped(raw, storage, joins).await?;
        let (raw, storage) = sqlite_fixture().await?;
        remapped_parent(raw, storage, joins).await?;
        let (raw, storage) = sqlite_fixture().await?;
        singular(raw, storage, joins).await?;
        for fail in [false, true] {
            let (raw, storage) = sqlite_fixture().await?;
            limited_or_failed(raw, storage, joins, fail).await?;
        }
    }
    Ok(())
}
