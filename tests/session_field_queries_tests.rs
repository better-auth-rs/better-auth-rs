#![cfg(feature = "seaorm2")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions compare complete rows and callback order; setup failures propagate"
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateSession, CreateUser, FieldDate,
    FieldMap, FieldValue, SessionView,
    id::IdGeneration,
    store::{
        EphemeralStore, RuntimeStore, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks},
    },
    user_fields::{
        FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform, UserFieldType,
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Schema},
    store::{
        __private_test_support::bundled_schema::BundledSchema,
        entities::{session, user},
    },
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex, OnceLock, Weak,
    atomic::{AtomicBool, Ordering},
};

#[path = "account_user_auth_boundary_reference_tests/recorder.rs"]
mod recorder;
use recorder::Events;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Fixture<S: AuthSchema> {
    store: Arc<dyn AuthStore<S>>,
    raw: Arc<dyn AuthStore<S>>,
    database: Option<DatabaseConnection>,
}

fn date(offset: i64) -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0 + offset as f64 * 1_000.0)
}

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Session query contract record is missing"))
}

fn input(token: &str, owner: &str) -> CreateSession {
    CreateSession {
        inherited_fields: FieldMap::new(),
        user_id: owner.into(),
        expires_at: date(100),
        ip_address: Some("seed-ip".into()),
        user_agent: Some("seed-agent".into()),
        impersonated_by: None,
        active_organization_id: None,
        additional_fields: [
            ("token".into(), token.into()),
            ("createdAt".into(), date(0).into()),
            ("updatedAt".into(), date(0).into()),
        ]
        .into(),
    }
}

fn raw_config(config: &AuthConfig) -> AuthConfig {
    let mut raw = AuthConfig::default();
    raw.advanced.database.generate_id = config.advanced.database.generate_id.clone();
    raw
}

fn memory(
    config: AuthConfig,
    hooks: Vec<Arc<dyn DatabaseHooks<StatelessSchema>>>,
) -> TestResult<Fixture<StatelessSchema>> {
    let raw = Arc::new(EphemeralStore::new(Arc::new(raw_config(&config))));
    let store = raw.with_runtime(Arc::new(config), hooks, Default::default())?;
    Ok(Fixture {
        store,
        raw,
        database: None,
    })
}

async fn sqlite(
    config: AuthConfig,
    hooks: Vec<Arc<dyn DatabaseHooks<BundledSchema>>>,
) -> TestResult<Fixture<BundledSchema>> {
    let mut options = ConnectOptions::new("sqlite::memory:");
    let _ = options.max_connections(1);
    let database = Database::connect(options).await?;
    let schema = Schema::new(database.get_database_backend());
    let _ = database
        .execute(&schema.create_table_from_entity(session::Entity))
        .await?;
    let _ = database
        .execute(&schema.create_table_from_entity(user::Entity))
        .await?;
    let raw = Arc::new(SeaOrmStore::<BundledSchema>::new(
        raw_config(&config),
        database.clone(),
    ));
    let store = raw.with_runtime(Arc::new(config), hooks, Default::default())?;
    Ok(Fixture {
        store,
        raw,
        database: Some(database),
    })
}

fn bad_token() -> FieldValue {
    FieldMap::from([("toString".into(), FieldValue::Null)]).into()
}

fn reference_token(config: &mut AuthConfig) {
    config.advanced.database.generate_id = Some(IdGeneration::Serial);
    let _ = config.session.fields_mut().insert(
        "token".into(),
        UserFieldConfig {
            references: Some(UserFieldReference {
                model: "user".into(),
                field: "id".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
}

fn priority_config(events: &Events) -> AuthConfig {
    let mut config = AuthConfig::default();
    reference_token(&mut config);
    let events = events.clone();
    let _ = config.session.fields_mut().insert(
        "ipAddress".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |_| {
                    events.push(json!({"kind":"input"}))?;
                    Err(AuthError::internal("session-input-rejected"))
                })),
                output: None,
            }),
            ..Default::default()
        },
    );
    config
}

async fn priority<S: AuthSchema>(fixture: Fixture<S>, events: Events) -> TestResult {
    let result = events
        .capture(fixture.store.update_session_fields_by_token_value(
            &bad_token(),
            [("ipAddress".into(), "changed".into())].into(),
        ))
        .await;
    assert!(matches!(result, Err(AuthError::TypeError(message)) if message == "No default value"));
    assert_eq!(events.take()?, Vec::<Value>::new());
    let result = events
        .capture(fixture.store.get_session_snapshot_value(&bad_token()))
        .await;
    assert!(matches!(result, Err(AuthError::TypeError(message)) if message == "No default value"));
    assert_eq!(events.take()?, Vec::<Value>::new());
    let error = fixture
        .store
        .get_session_snapshot("7")
        .await
        .err()
        .ok_or("Ambiguous Session join succeeded")?;
    assert!(error.to_string().contains("Multiple foreign keys"));
    assert!(fixture.raw.get_user_sessions("1").await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn session_query_errors_precede_input_callbacks_and_join_errors() -> TestResult {
    let events = Events::default();
    priority(memory(priority_config(&events), vec![])?, events).await?;
    let events = Events::default();
    priority(sqlite(priority_config(&events), vec![]).await?, events).await
}

fn update_config(events: &Events) -> AuthConfig {
    let mut config = AuthConfig::default();
    let input = events.clone();
    let output = events.clone();
    let _ = config.session.fields_mut().insert(
        "ipAddress".into(),
        UserFieldConfig {
            field_name: Some("userAgent".into()),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    input.push(json!("input"))?;
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    output.push(json!("output"))?;
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    let _ = config.session.fields_mut().insert(
        "userAgent".into(),
        UserFieldConfig {
            field_name: Some("ipAddress".into()),
            ..Default::default()
        },
    );
    config
}

async fn update_all<S: AuthSchema>(fixture: Fixture<S>, events: Events) -> TestResult {
    let first = fixture.store.create_session(input("shared", "1")).await?;
    let second = fixture.store.create_session(input("shared", "1")).await?;
    let retained = fixture.store.create_session(input("other", "2")).await?;
    let mut expected_first = FieldMap::from(first);
    let mut expected_second = FieldMap::from(second);
    for expected in [&mut expected_first, &mut expected_second] {
        let _ = expected.insert("ipAddress".into(), "changed".into());
        let _ = expected.insert("updatedAt".into(), date(3).into());
    }
    let _ = events.take()?;
    let result = required(
        fixture
            .store
            .update_session_fields(
                "shared",
                [
                    ("ipAddress".into(), "changed".into()),
                    ("updatedAt".into(), date(3).into()),
                ]
                .into(),
            )
            .await?,
    )?;
    assert_eq!(FieldMap::from(result), expected_first);
    assert_eq!(events.take()?, [json!("input"), json!("output")]);
    assert_eq!(
        fixture
            .store
            .get_user_sessions("1")
            .await?
            .into_iter()
            .map(FieldMap::from)
            .collect::<Vec<_>>(),
        [expected_first.clone(), expected_second.clone()]
    );
    assert_eq!(fixture.store.get_user_sessions("2").await?, [retained]);
    for expected in [&mut expected_first, &mut expected_second] {
        let _ = expected.insert("ipAddress".into(), "seed-agent".into());
        let _ = expected.insert("userAgent".into(), "changed".into());
    }
    assert_eq!(
        fixture
            .raw
            .get_user_sessions("1")
            .await?
            .into_iter()
            .map(FieldMap::from)
            .collect::<Vec<_>>(),
        [expected_first, expected_second]
    );
    Ok(())
}

#[tokio::test]
async fn session_update_changes_every_duplicate_token_but_projects_only_the_first() -> TestResult {
    let events = Events::default();
    update_all(memory(update_config(&events), vec![])?, events).await?;
    let events = Events::default();
    update_all(sqlite(update_config(&events), vec![]).await?, events).await
}

fn preserve_config(events: &Events, ending: &Arc<AtomicBool>) -> AuthConfig {
    let mut config = AuthConfig::default();
    let expiry_events = events.clone();
    let ending = ending.clone();
    let _ = config.session.fields_mut().insert(
        "expiresAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            field_name: Some("createdAt".into()),
            transform: Some(FieldTransforms {
                output: None,
                input: Some(UserFieldTransform::new(move |value| {
                    if ending.load(Ordering::SeqCst) {
                        assert!(matches!(value, FieldValue::Date(_)));
                        expiry_events.push(json!("expiry-input"))?;
                        return Ok(date(-1_000_000_000).into());
                    }
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    let _ = config.session.fields_mut().insert(
        "createdAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            field_name: Some("expiresAt".into()),
            ..Default::default()
        },
    );
    let update_events = events.clone();
    let input_events = events.clone();
    let _ = config.session.fields_mut().insert(
        "updatedAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            on_update: Some(Arc::new(move || {
                update_events.push(json!("updated-on-update"))?;
                Ok(date(9).into())
            })),
            transform: Some(FieldTransforms {
                output: None,
                input: Some(UserFieldTransform::new(move |value| {
                    input_events.push(json!("updated-input"))?;
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    config
}

async fn preserve<S: AuthSchema>(
    fixture: Fixture<S>,
    events: Events,
    ending: Arc<AtomicBool>,
) -> TestResult {
    let active = fixture.store.create_session(input("active", "1")).await?;
    let mut expired_input = input("expired", "1");
    expired_input.expires_at = date(-1_000_000_000);
    let _ = expired_input
        .additional_fields
        .insert("createdAt".into(), date(-1_000_000_000).into());
    let expired = fixture.store.create_session(expired_input).await?;
    let retained = fixture.store.create_session(input("other", "2")).await?;
    assert_eq!(
        fixture
            .store
            .get_user_session_snapshots_value(&"1".into(), true)
            .await?,
        [(active.clone(), None)]
    );
    let _ = events.take()?;
    ending.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .store
            .delete_user_sessions_optional("1", true)
            .await?,
        Some(1)
    );
    assert_eq!(
        events.take()?,
        [
            json!("expiry-input"),
            json!("updated-on-update"),
            json!("updated-input")
        ]
    );
    let mut ended = FieldMap::from(active);
    let _ = ended.insert("expiresAt".into(), date(-1_000_000_000).into());
    let _ = ended.insert("updatedAt".into(), date(9).into());
    assert_eq!(
        FieldMap::from(required(fixture.store.get_session("active").await?)?),
        ended
    );
    assert_eq!(
        fixture
            .store
            .get_user_sessions("1")
            .await?
            .into_iter()
            .map(FieldMap::from)
            .collect::<Vec<_>>(),
        [ended.clone(), FieldMap::from(expired.clone())]
    );
    // Kysely resolves WHERE aliases twice, so SQLite still filters the unchanged public createdAt.
    assert_eq!(
        fixture
            .store
            .get_user_session_snapshots_value(&"1".into(), true)
            .await?
            .into_iter()
            .map(|(session, snapshot)| (FieldMap::from(session), snapshot))
            .collect::<Vec<_>>(),
        if fixture.database.is_some() {
            vec![(ended.clone(), None)]
        } else {
            vec![]
        }
    );
    assert_eq!(fixture.store.get_user_sessions("2").await?, [retained]);
    let mut physical_ended = ended;
    let _ = physical_ended.insert("createdAt".into(), date(-1_000_000_000).into());
    let _ = physical_ended.insert("expiresAt".into(), date(0).into());
    let mut physical_expired = FieldMap::from(expired);
    let _ = physical_expired.insert("createdAt".into(), date(-1_000_000_000).into());
    let _ = physical_expired.insert("expiresAt".into(), date(-1_000_000_000).into());
    assert_eq!(
        fixture
            .raw
            .get_user_sessions("1")
            .await?
            .into_iter()
            .map(FieldMap::from)
            .collect::<Vec<_>>(),
        [physical_ended, physical_expired]
    );
    if fixture.database.is_none() {
        ending.store(false, Ordering::SeqCst);
        let _ = fixture
            .store
            .create_session(input("later-active", "1"))
            .await?;
        let mut invalid = input("later-invalid", "1");
        let _ = invalid
            .additional_fields
            .insert("expiresAt".into(), bad_token());
        let _ = fixture.store.create_session(invalid).await?;
        let before = fixture
            .raw
            .get_user_sessions("1")
            .await?
            .into_iter()
            .map(FieldMap::from)
            .collect::<Vec<_>>();
        let _ = events.take()?;
        ending.store(true, Ordering::SeqCst);
        let result = fixture.store.delete_user_sessions_optional("1", true).await;
        assert!(
            matches!(result, Err(AuthError::TypeError(message)) if message == "No default value")
        );
        assert_eq!(
            events.take()?,
            [
                json!("expiry-input"),
                json!("updated-on-update"),
                json!("updated-input")
            ]
        );
        assert_eq!(
            fixture
                .raw
                .get_user_sessions("1")
                .await?
                .into_iter()
                .map(FieldMap::from)
                .collect::<Vec<_>>(),
            before
        );
    }
    Ok(())
}

#[tokio::test]
async fn session_active_queries_and_preservation_follow_mapped_dates_and_on_update() -> TestResult {
    let events = Events::default();
    let ending = Arc::new(AtomicBool::new(false));
    preserve(
        memory(preserve_config(&events, &ending), vec![])?,
        events,
        ending,
    )
    .await?;
    let events = Events::default();
    let ending = Arc::new(AtomicBool::new(false));
    preserve(
        sqlite(preserve_config(&events, &ending), vec![]).await?,
        events,
        ending,
    )
    .await
}

#[path = "session_field_queries_tests/callbacks.rs"]
mod callbacks;
#[path = "session_field_queries_tests/raw_dates.rs"]
mod raw_dates;
