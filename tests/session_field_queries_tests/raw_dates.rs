use super::*;

fn raw_date_fields() -> FieldMap {
    [
        ("id".into(), "raw-session".into()),
        ("token".into(), "raw-token".into()),
        ("userId".into(), "raw-user".into()),
        ("expiresAt".into(), date(100).into()),
        ("createdAt".into(), "created-is-not-a-date".into()),
        ("updatedAt".into(), date(0).into()),
        ("ipAddress".into(), "seed-ip".into()),
        ("userAgent".into(), "seed-agent".into()),
    ]
    .into()
}

fn raw_date_config(joins: bool, events: &Events) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.advanced.database.joins = Some(joins);
    config.advanced.database.generate_id = Some(better_auth_core::id::IdGeneration::Custom(
        better_auth_core::id::IdGenerator::new(|request| {
            Ok(Some(format!("raw-{}", request.model)))
        }),
    ));
    let events = events.clone();
    config.session.fields_mut().extend([
        ("createdAt".into(), UserFieldConfig::default()),
        (
            "expiresAt".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: None,
                    output: Some(UserFieldTransform::new(move |value| {
                        assert_eq!(value, FieldValue::from("expiry-is-not-a-date"));
                        events.push(json!({"kind":"output","field":"expiresAt","value":value}))?;
                        Ok(date(100).into())
                    })),
                }),
                ..Default::default()
            },
        ),
    ]);
    config
}

struct RawDateHooks(Events);

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> better_auth_core::store::database_hooks::DatabaseHooks<S> for RawDateHooks {
    async fn before_delete_session(
        &self,
        session: &better_auth_core::wire::SessionView,
        _: &better_auth_core::store::database_hooks::DatabaseHookContext<'_, S>,
    ) -> AuthResult<better_auth_core::store::database_hooks::DatabaseHookControl> {
        let fields = FieldMap::from(session.clone());
        assert_eq!(fields, raw_date_fields());
        self.0
            .push(json!({"kind":"before-delete","session":fields}))?;
        Ok(better_auth_core::store::database_hooks::DatabaseHookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        session: &better_auth_core::wire::SessionView,
        _: &better_auth_core::store::database_hooks::DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let fields = FieldMap::from(session.clone());
        assert_eq!(fields, raw_date_fields());
        self.0.push(json!({"kind":"after-delete","session":fields}))
    }
}

async fn raw_date_contract<S: AuthSchema>(fixture: Fixture<S>, events: &Events) -> TestResult {
    let owner = fixture
        .store
        .create_user(CreateUser {
            id: Some("raw-user".into()),
            name: Some("Raw dates owner".into()).into(),
            email: Some("raw-dates@example.test".into()),
            email_verified: Some(true),
            image: None::<String>.into(),
            created_at: Some(date(0)),
            updated_at: Some(date(0)),
            ..Default::default()
        })
        .await?;
    let expected_user = FieldMap::from(
        better_auth_core::UserView::with_internal_fields(
            &owner,
            &Default::default(),
            &Default::default(),
        )
        .await?,
    );
    let mut seed = input("raw-token", "raw-user");
    seed.additional_fields.extend([
        ("createdAt".into(), "created-is-not-a-date".into()),
        ("expiresAt".into(), "expiry-is-not-a-date".into()),
    ]);
    let expected = raw_date_fields();
    assert_eq!(
        FieldMap::from(fixture.store.create_session(seed).await?),
        expected
    );
    assert_eq!(
        FieldMap::from(required(fixture.store.get_session("raw-token").await?)?),
        expected
    );
    assert_eq!(
        fixture
            .store
            .get_user_sessions("raw-user")
            .await?
            .into_iter()
            .map(FieldMap::from)
            .collect::<Vec<_>>(),
        [expected.clone()]
    );
    let mut snapshots = vec![required(
        fixture.store.get_session_snapshot("raw-token").await?,
    )?];
    snapshots.extend(
        fixture
            .store
            .get_session_snapshots(&["raw-token".into()], false)
            .await?,
    );
    assert_eq!(snapshots.len(), 2);
    for (session, joined) in snapshots {
        assert_eq!(FieldMap::from(session), expected);
        let joined = required(joined)?;
        assert_eq!(FieldMap::from(joined.session), expected);
        let better_auth_core::store::JoinValue::One(Some(user)) = joined.user else {
            return Err(AuthError::internal("Raw-date Session did not join its owner").into());
        };
        assert_eq!(FieldMap::from(user), expected_user);
    }
    if let Some(database) = &fixture.database {
        use better_auth_seaorm::sea_orm::ConnectionTrait;
        let row = required(
            database
                .query_one_raw(better_auth_seaorm::sea_orm::Statement::from_string(
                    better_auth_seaorm::sea_orm::DbBackend::Sqlite,
                    "SELECT created_at, expires_at FROM sessions WHERE id = 'raw-session'",
                ))
                .await?,
        )?;
        assert_eq!(
            row.try_get::<String>("", "created_at")?,
            "created-is-not-a-date"
        );
        assert_eq!(
            row.try_get::<String>("", "expires_at")?,
            "expiry-is-not-a-date"
        );
    }
    let _ = events.take()?;
    fixture.store.delete_session("raw-token").await?;
    assert_eq!(
        serde_json::to_value(events.take()?)?,
        json!([
            {"kind":"output","field":"expiresAt","value":"expiry-is-not-a-date"},
            {"kind":"before-delete","session":expected},
            {"kind":"after-delete","session":expected},
        ])
    );
    assert!(fixture.store.get_session("raw-token").await?.is_none());
    assert!(
        fixture
            .store
            .get_user_sessions("raw-user")
            .await?
            .is_empty()
    );
    assert!(fixture.store.get_user_by_id("raw-user").await?.is_some());
    Ok(())
}

#[tokio::test]
async fn session_raw_date_replacements_survive_reads_joins_and_delete_hooks() -> TestResult {
    for joins in [false, true] {
        let events = Events::default();
        let fixture = memory(
            raw_date_config(joins, &events),
            vec![Arc::new(RawDateHooks(events.clone()))],
        )?;
        raw_date_contract(fixture, &events).await?;
        let events = Events::default();
        let fixture = sqlite(
            raw_date_config(joins, &events),
            vec![Arc::new(RawDateHooks(events.clone()))],
        )
        .await?;
        raw_date_contract(fixture, &events).await?;
    }
    Ok(())
}
