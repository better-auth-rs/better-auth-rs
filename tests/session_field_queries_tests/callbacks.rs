use super::*;

fn reentrant_config<S: AuthSchema>(
    target: &Arc<OnceLock<Weak<dyn AuthStore<S>>>>,
    enabled: &Arc<AtomicBool>,
    events: &Events,
    fail_query: bool,
) -> AuthConfig {
    let mut config = AuthConfig::default();
    reference_token(&mut config);
    let target = target.clone();
    let enabled = enabled.clone();
    let events = events.clone();
    let _ = config.session.fields_mut().insert("label".into(), UserFieldConfig {
        field_name: Some("ipAddress".into()),
        transform: Some(FieldTransforms { output: None, input: Some(UserFieldTransform::new_async(move |value| {
            let target = target.clone();
            let enabled = enabled.clone();
            let events = events.clone();
            async move {
                if enabled.load(Ordering::SeqCst) {
                    events.push(json!({"kind":"input","value":value}))?;
                    let store = target.get().and_then(Weak::upgrade).ok_or_else(|| AuthError::internal("Session callback store is unavailable"))?;
                    let found = required(store.get_session("7").await?)?;
                    events.push(json!({"kind":"read","session":FieldMap::from(found)}))?;
                    if fail_query {
                        let result = store.get_session_by_token_value(&bad_token()).await;
                        assert!(matches!(result, Err(AuthError::TypeError(message)) if message == "No default value"));
                        events.push(json!({"kind":"caught","name":"TypeError","message":"No default value"}))?;
                    }
                }
                Ok(value)
            }
        })) }), ..Default::default()
    });
    // The internal creation path strips caller IDs; the Session default supplies the serial seed.
    let _ = config.session.fields_mut().insert(
        "id".into(),
        UserFieldConfig {
            default_value: Some("1".into()),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| {
                    Err(AuthError::internal("Application ID input must be replaced"))
                })),
                output: Some(UserFieldTransform::new(|_| {
                    Err(AuthError::internal(
                        "Application ID output must be replaced",
                    ))
                })),
            }),
            ..Default::default()
        },
    );
    config
}

async fn reentrant<S: AuthSchema>(
    fixture: Fixture<S>,
    target: Arc<OnceLock<Weak<dyn AuthStore<S>>>>,
    enabled: Arc<AtomicBool>,
    events: Events,
    fail_query: bool,
) -> TestResult {
    target
        .set(Arc::downgrade(&fixture.store))
        .map_err(|_| "Session callback store was already assigned")?;
    let mut seed = input("7", "1");
    let _ = seed
        .additional_fields
        .insert("label".into(), "seed-label".into());
    let before = FieldMap::from(fixture.store.create_session(seed).await?);
    assert_eq!(before.get("id"), Some(&"1".into()));
    enabled.store(true, Ordering::SeqCst);
    let result = required(
        fixture
            .store
            .update_session_fields(
                "7",
                [
                    ("label".into(), "outer".into()),
                    ("id".into(), "00100".into()),
                    ("updatedAt".into(), date(3).into()),
                ]
                .into(),
            )
            .await?,
    )?;
    let mut expected = before.clone();
    let _ = expected.insert("id".into(), if fail_query { "100" } else { "00100" }.into());
    let _ = expected.insert("ipAddress".into(), "outer".into());
    let _ = expected.insert("label".into(), "outer".into());
    let _ = expected.insert("updatedAt".into(), date(3).into());
    assert_eq!(FieldMap::from(result), expected);
    let mut expected_events = vec![
        json!({"kind":"input","value":"outer"}),
        json!({"kind":"read","session":before}),
    ];
    if fail_query {
        expected_events
            .push(json!({"kind":"caught","name":"TypeError","message":"No default value"}));
    }
    assert_eq!(events.take()?, expected_events);
    assert_eq!(
        FieldMap::from(required(fixture.store.get_session("7").await?)?),
        expected
    );
    let _ = expected.remove("label");
    if fixture.database.is_none() {
        let _ = expected.insert("token".into(), 7.into());
    }
    assert_eq!(
        fixture
            .raw
            .get_user_sessions("1")
            .await?
            .into_iter()
            .map(FieldMap::from)
            .collect::<Vec<_>>(),
        [expected]
    );
    Ok(())
}

#[tokio::test]
async fn session_failed_reentrant_query_restores_id_input_policy_after_output() -> TestResult {
    for fail_query in [false, true] {
        let target = Arc::new(OnceLock::new());
        let enabled = Arc::new(AtomicBool::new(false));
        let events = Events::default();
        let fixture = memory(
            reentrant_config(&target, &enabled, &events, fail_query),
            vec![],
        )?;
        reentrant(fixture, target, enabled, events, fail_query).await?;
        let target = Arc::new(OnceLock::new());
        let enabled = Arc::new(AtomicBool::new(false));
        let events = Events::default();
        let fixture = sqlite(
            reentrant_config(&target, &enabled, &events, fail_query),
            vec![],
        )
        .await?;
        reentrant(fixture, target, enabled, events, fail_query).await?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DeleteMode {
    Normal,
    OutputFailure,
    Cancel,
}

struct DeleteHooks {
    events: Events,
    mode: DeleteMode,
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for DeleteHooks {
    async fn before_delete_session(
        &self,
        session: &SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.events
            .push(json!({"kind":"before-delete","session":FieldMap::from(session.clone())}))?;
        Ok(if self.mode == DeleteMode::Cancel {
            DatabaseHookControl::Cancel
        } else {
            DatabaseHookControl::Continue
        })
    }

    async fn after_delete_session(
        &self,
        session: &SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.events
            .push(json!({"kind":"after-delete","session":FieldMap::from(session.clone())}))
    }
}

fn delete_config(events: &Events, enabled: &Arc<AtomicBool>, mode: DeleteMode) -> AuthConfig {
    let mut config = AuthConfig::default();
    let events = events.clone();
    let enabled = enabled.clone();
    let _ = config.session.fields_mut().insert(
        "ipAddress".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: None,
                output: Some(UserFieldTransform::new(move |value| {
                    if enabled.load(Ordering::SeqCst) {
                        events.push(json!({"kind":"output","value":value}))?;
                        if mode == DeleteMode::OutputFailure {
                            return Err(AuthError::internal("session-output-rejected"));
                        }
                    }
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    config
}

async fn deletion<S: AuthSchema>(
    fixture: Fixture<S>,
    events: Events,
    enabled: Arc<AtomicBool>,
    mode: DeleteMode,
) -> TestResult {
    let candidate = FieldMap::from(
        fixture
            .store
            .create_session(input("candidate", "1"))
            .await?,
    );
    let retained = fixture.store.create_session(input("retained", "2")).await?;
    enabled.store(true, Ordering::SeqCst);
    fixture
        .store
        .delete_session("candidate")
        .with_subscriber(tracing_subscriber::registry().with(events.clone()))
        .await?;
    let model = if fixture.database.is_some() {
        "sessions"
    } else {
        "session"
    };
    let mut expected = vec![
        json!({"kind":"query","operation":"findMany","model":model}),
        json!({"kind":"output","value":"seed-ip"}),
    ];
    if mode != DeleteMode::OutputFailure {
        expected.push(json!({"kind":"before-delete","session":candidate}));
    }
    if mode == DeleteMode::Normal {
        expected.push(json!({"kind":"query","operation":"delete","model":model}));
        expected.push(json!({"kind":"after-delete","session":candidate}));
    }
    assert_eq!(events.take()?, expected);
    let candidate_rows = fixture
        .raw
        .get_user_sessions("1")
        .await?
        .into_iter()
        .map(FieldMap::from)
        .collect::<Vec<_>>();
    assert_eq!(
        candidate_rows,
        if mode == DeleteMode::Normal {
            vec![]
        } else {
            vec![candidate]
        }
    );
    assert_eq!(fixture.raw.get_user_sessions("2").await?, [retained]);
    Ok(())
}

#[tokio::test]
async fn session_delete_projects_before_hooks_and_preserves_rows_after_failure_or_cancel()
-> TestResult {
    for mode in [
        DeleteMode::Normal,
        DeleteMode::OutputFailure,
        DeleteMode::Cancel,
    ] {
        let events = Events::default();
        let enabled = Arc::new(AtomicBool::new(false));
        let fixture = memory(
            delete_config(&events, &enabled, mode),
            vec![Arc::new(DeleteHooks {
                events: events.clone(),
                mode,
            })],
        )?;
        deletion(fixture, events, enabled, mode).await?;
        let events = Events::default();
        let enabled = Arc::new(AtomicBool::new(false));
        let fixture = sqlite(
            delete_config(&events, &enabled, mode),
            vec![Arc::new(DeleteHooks {
                events: events.clone(),
                mode,
            })],
        )
        .await?;
        deletion(fixture, events, enabled, mode).await?;
    }
    Ok(())
}
