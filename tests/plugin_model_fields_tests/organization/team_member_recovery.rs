use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    OnceKey,
    OncePair,
    Persistent,
    Input,
}

fn declarations(events: &Events, mode: Failure) -> UserConfig {
    let key_input = events.clone();
    let key_output = events.clone();
    let outputs = Arc::new(AtomicUsize::new(0));
    let output = move |value: FieldValue| -> AuthResult<FieldValue> {
        key_output.push("membershipKey", "output", value.clone())?;
        if outputs.fetch_add(1, Ordering::SeqCst) == 0 || mode == Failure::Persistent {
            return Err(AuthError::internal("team-member-output-failed"));
        }
        Ok(format!(
            "visible:{}",
            required(value.as_str(), "Expected stored membership key")?
        )
        .into())
    };
    let output = if mode == Failure::OncePair {
        UserFieldTransform::new_async(move |value| {
            let result = output(value);
            async move { result }
        })
    } else {
        UserFieldTransform::new(output)
    };
    let date_input = events.clone();
    let date_output = events.clone();
    declaration([
        ("teamId", identity("teamId", events)),
        ("userId", identity("userId", events)),
        (
            "membershipKey",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        key_input.push("membershipKey", "input", value.clone())?;
                        if mode == Failure::Input {
                            return Err(AuthError::internal("team-member-input-failed"));
                        }
                        Ok(if mode == Failure::OncePair {
                            "alternate-key".into()
                        } else {
                            value
                        })
                    })),
                    output: Some(output),
                }),
                ..Default::default()
            },
        ),
        (
            "createdAt",
            UserFieldConfig {
                field_type: UserFieldType::Date,
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        date_input.service_date(value)?;
                        Ok(date(0).into())
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        date_output.push("createdAt", "output", value)?;
                        Ok(date(1).into())
                    })),
                }),
                ..Default::default()
            },
        ),
    ])
}

async fn recover<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    limited: bool,
    mode: Failure,
) -> AuthResult<()> {
    let events = Events::default();
    let auth = reader(
        raw,
        declarations(&events, mode),
        None,
        false,
        false,
        "member-a",
    )
    .await?;
    let started = chrono::Utc::now().timestamp_millis();
    let result = auth
        .store()
        .add_team_member(&"team-a".into(), "user-a", limited.then_some(1))
        .await;
    let failed = matches!(mode, Failure::Persistent | Failure::Input);
    if failed {
        original_error(
            required(result.err(), "Expected original TeamMember failure")?,
            if mode == Failure::Input {
                "team-member-input-failed"
            } else {
                "team-member-output-failed"
            },
        );
    } else {
        assert_eq!(
            public(required(
                result?,
                "Failed output must reread persisted membership"
            )?)?,
            member("member-a", "team-a", "user-a", date(1).into())
        );
    }
    events.assert_dates(
        usize::from(mode != Failure::Input),
        started,
        chrono::Utc::now().timestamp_millis(),
    )?;
    let hash = key("team-a", "user-a")?;
    let stored_key = if mode == Failure::OncePair {
        "alternate-key"
    } else {
        &hash
    };
    let mut expected = vec![
        event("teamId", "input", "team-a".into()),
        event("userId", "input", "user-a".into()),
        event("membershipKey", "input", hash.clone().into()),
    ];
    if mode != Failure::Input {
        expected.push(event("createdAt", "input", "native-date".into()));
        for _ in 0..2 {
            expected.extend([
                event("teamId", "output", "team-a".into()),
                event("userId", "output", "user-a".into()),
                event("membershipKey", "output", stored_key.into()),
            ]);
        }
        if !failed {
            expected.push(event("createdAt", "output", storage.stored_date(0)));
        }
    }
    assert_eq!(events.take()?, expected);
    storage
        .assert_rows(
            if failed {
                vec![]
            } else {
                vec![physical("member-a", "team-a", "user-a", stored_key, 0)]
            },
            [0, 0],
        )
        .await
}

async fn lookup<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    key_priority: bool,
) -> AuthResult<()> {
    let events = Events::default();
    let source_team = if key_priority { "team-b" } else { "team-a" };
    let source_user = if key_priority { "user-b" } else { "user-a" };
    let stored_key = if key_priority {
        key("team-a", "user-a")?
    } else {
        "alternate-key".into()
    };
    let configured_key = stored_key.clone();
    let key_output = events.clone();
    let date_output = events.clone();
    let fields = declaration([
        ("teamId", identity("teamId", &events)),
        ("userId", identity("userId", &events)),
        (
            "membershipKey",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |_| {
                        Ok(configured_key.clone().into())
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        key_output.push("membershipKey", "output", value.clone())?;
                        Ok(format!(
                            "visible:{}",
                            required(value.as_str(), "Expected stored lookup key")?
                        )
                        .into())
                    })),
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
                        date_output.push("createdAt", "output", value)?;
                        Ok(date(1).into())
                    })),
                }),
                ..Default::default()
            },
        ),
    ]);
    let auth = reader(raw, fields, None, false, false, "member-a").await?;
    let expected = member("member-a", source_team, source_user, date(1).into());
    assert_eq!(
        public(required(
            auth.store()
                .add_team_member(&source_team.into(), source_user, None)
                .await?,
            "Expected seeded membership"
        )?)?,
        expected
    );
    let _ = events.take()?;
    for maximum in [None, Some(0)] {
        assert_eq!(
            public(required(
                auth.store()
                    .add_team_member(&"team-a".into(), "user-a", maximum)
                    .await?,
                "Existing key or pair must precede capacity check"
            )?)?,
            expected
        );
        assert_eq!(
            events.take()?,
            [
                event("teamId", "output", source_team.into()),
                event("userId", "output", source_user.into()),
                event("membershipKey", "output", stored_key.clone().into()),
                event("createdAt", "output", storage.stored_date(0)),
            ]
        );
        storage
            .assert_rows(
                vec![physical(
                    "member-a",
                    source_team,
                    source_user,
                    &stored_key,
                    0,
                )],
                if key_priority { [0, 1] } else { [1, 0] },
            )
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_team_member_creation_preserves_original_failure_rereads_and_capacity()
-> AuthResult<()> {
    for limited in [false, true] {
        for mode in [
            Failure::OnceKey,
            Failure::OncePair,
            Failure::Persistent,
            Failure::Input,
        ] {
            let (raw, storage) = memory_fixture().await?;
            recover(raw, storage, limited, mode).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_team_member_creation_preserves_original_failure_rereads_and_capacity()
-> AuthResult<()> {
    for limited in [false, true] {
        for mode in [
            Failure::OnceKey,
            Failure::OncePair,
            Failure::Persistent,
            Failure::Input,
        ] {
            let (raw, storage) = sqlite_fixture().await?;
            recover(raw, storage, limited, mode).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_team_member_lookup_prefers_key_then_pair_before_capacity() -> AuthResult<()> {
    for priority in [true, false] {
        let (raw, storage) = memory_fixture().await?;
        lookup(raw, storage, priority).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_team_member_lookup_prefers_key_then_pair_before_capacity() -> AuthResult<()> {
    for priority in [true, false] {
        let (raw, storage) = sqlite_fixture().await?;
        lookup(raw, storage, priority).await?;
    }
    Ok(())
}
