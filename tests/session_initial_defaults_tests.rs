#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateSession, CreateUser, FieldMap,
    FieldValue, SessionView,
    id::{IdGeneration, IdGenerator},
    store::{
        EphemeralStore, MemoryCacheAdapter, RuntimeStore, SecondaryStorage, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHooks},
        secondary::SecondaryStore,
        transaction,
    },
    user_fields::UserFieldConfig,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{Database, EntityTrait},
    store::{
        __private_test_support::{bundled_schema::BundledSchema, migrator},
        entities::{session, user},
    },
};
use serde_json::{Value as JsonValue, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc::{self, Sender},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[path = "session_initial_defaults_tests/plugin_precedence.rs"]
mod plugin_precedence;

fn additional_creation_fields(input: &FieldMap) -> FieldMap {
    let mut fields = input.clone();
    for name in [
        "token",
        "userId",
        "expiresAt",
        "createdAt",
        "updatedAt",
        "ipAddress",
        "userAgent",
    ] {
        let _ = fields.remove(name);
    }
    fields
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Missing,
    Caller,
    Undefined,
    RequiredNull,
    OptionalNull,
    Patched,
    Cancel,
    Failure,
    LiteralUndefinedId,
    FactoryUndefinedId,
    GeneratorFailure,
    DefaultFailure,
}

const CASES: [Case; 12] = [
    Case::Missing,
    Case::Caller,
    Case::Undefined,
    Case::RequiredNull,
    Case::OptionalNull,
    Case::Patched,
    Case::Cancel,
    Case::Failure,
    Case::LiteralUndefinedId,
    Case::FactoryUndefinedId,
    Case::GeneratorFailure,
    Case::DefaultFailure,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Ordinary,
    Transaction,
    Deferred,
}

#[derive(Debug, PartialEq)]
enum Event {
    Generate,
    Default(&'static str, FieldValue),
    Before(FieldMap),
    After(FieldValue, FieldMap),
}

fn emit(events: &Sender<Event>, event: Event) -> AuthResult<()> {
    events
        .send(event)
        .map_err(|error| AuthError::internal(error.to_string()))
}

struct Hooks {
    case: Case,
    events: Sender<Event>,
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn before_create_session(
        &self,
        input: &mut better_auth_core::FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<
        better_auth_core::store::database_hooks::DatabaseHookUpdate<better_auth_core::FieldMap>,
    > {
        emit(
            &self.events,
            Event::Before(additional_creation_fields(input)),
        )?;
        let patch = match self.case {
            Case::Undefined => Some(FieldValue::Undefined),
            Case::RequiredNull | Case::OptionalNull => Some(FieldValue::Null),
            Case::Patched => Some("P".into()),
            Case::Cancel => {
                return Ok(better_auth_core::store::database_hooks::DatabaseHookUpdate::Cancel);
            }
            Case::Failure => return Err(AuthError::bad_request("session hook failure")),
            _ => None,
        };
        if let Some(value) = patch {
            let _ = input.insert("label".into(), value);
        }
        Ok(better_auth_core::store::database_hooks::DatabaseHookUpdate::Continue)
    }

    async fn after_create_session(
        &self,
        session: &SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        emit(
            &self.events,
            Event::After(session.id.field_value(), session.additional_fields.clone()),
        )
    }
}

fn config(case: Case, pure: bool, events: &Sender<Event>) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.session.store_session_in_database = Some(!pure);
    let generator_events = events.clone();
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            assert_eq!(request.model, "session");
            emit(&generator_events, Event::Generate)?;
            if case == Case::GeneratorFailure {
                return Err(AuthError::bad_request("session generator failure"));
            }
            Ok(Some("G".into()))
        })));
    let id_events = events.clone();
    let id = if case == Case::LiteralUndefinedId {
        UserFieldConfig {
            default_value: Some(FieldValue::Undefined),
            ..Default::default()
        }
    } else {
        UserFieldConfig {
            default_value_fn: Some(Arc::new(move || {
                let value = if case == Case::FactoryUndefinedId {
                    FieldValue::Undefined
                } else {
                    "C".into()
                };
                emit(&id_events, Event::Default("id", value.clone()))?;
                Ok(value)
            })),
            ..Default::default()
        }
    };
    let label_events = events.clone();
    let calls = AtomicUsize::new(0);
    let label = UserFieldConfig {
        field_name: Some("active_organization_id".into()),
        required: Some(case == Case::RequiredNull),
        default_value_fn: Some(Arc::new(move || {
            let value = FieldValue::from(format!("D{}", calls.fetch_add(1, Ordering::SeqCst) + 1));
            emit(&label_events, Event::Default("label", value.clone()))?;
            if case == Case::DefaultFailure {
                return Err(AuthError::FieldInput {
                    code: "SESSION_DEFAULT_REJECTED",
                    message: "session default failure".into(),
                });
            }
            Ok(value)
        })),
        ..Default::default()
    };
    config.session.additional_fields = Some([("id".into(), id), ("label".into(), label)].into());
    config
}

fn input(case: Case) -> TestResult<CreateSession> {
    let mut additional_fields: FieldMap = [("id".into(), "caller-id".into())].into();
    if case == Case::Caller {
        let _ = additional_fields.insert("label".into(), "caller".into());
    }
    Ok(CreateSession {
        user_id: "owner".into(),
        expires_at: "2100-01-02T03:04:05Z"
            .parse::<chrono::DateTime<chrono::Utc>>()?
            .into(),
        ip_address: Some(String::new()),
        user_agent: Some(String::new()),
        impersonated_by: None,
        active_organization_id: None,
        additional_fields,
    })
}

fn expected_events(case: Case, pure: bool) -> Vec<Event> {
    let mut events = Vec::new();
    if pure {
        events.push(Event::Generate);
        if case == Case::GeneratorFailure {
            return events;
        }
    }
    let mut before = FieldMap::new();
    if case == Case::LiteralUndefinedId {
        if pure {
            let _ = before.insert("id".into(), "G".into());
        }
    } else {
        let id = if case == Case::FactoryUndefinedId {
            FieldValue::Undefined
        } else {
            "C".into()
        };
        events.push(Event::Default("id", id.clone()));
        let _ = before.insert("id".into(), id);
    }
    events.push(Event::Default("label", "D1".into()));
    if case == Case::DefaultFailure {
        return events;
    }
    let _ = before.insert(
        "label".into(),
        if case == Case::Caller { "caller" } else { "D1" }.into(),
    );
    events.push(Event::Before(before));
    if matches!(case, Case::Cancel | Case::Failure) {
        return events;
    }
    if !pure && matches!(case, Case::LiteralUndefinedId | Case::FactoryUndefinedId) {
        events.push(Event::Generate);
    }
    if !pure && matches!(case, Case::Undefined | Case::RequiredNull) {
        events.push(Event::Default("label", "D2".into()));
    }
    let id = match case {
        Case::FactoryUndefinedId if pure => FieldValue::Undefined,
        Case::FactoryUndefinedId | Case::LiteralUndefinedId => "G".into(),
        _ => "C".into(),
    };
    let label = match case {
        Case::Caller => "caller".into(),
        Case::Undefined if pure => FieldValue::Undefined,
        Case::RequiredNull | Case::OptionalNull if pure => FieldValue::Null,
        Case::Undefined | Case::RequiredNull => "D2".into(),
        Case::OptionalNull => FieldValue::Null,
        Case::Patched => "P".into(),
        _ => "D1".into(),
    };
    events.push(Event::After(id, [("label".into(), label)].into()));
    events
}

struct Run {
    case: Case,
    pure: bool,
    call: Call,
    config: AuthConfig,
    events: mpsc::Receiver<Event>,
}

#[derive(Default)]
struct ObservedCache {
    inner: MemoryCacheAdapter,
    writes: AtomicUsize,
}

#[async_trait::async_trait]
impl SecondaryStorage for ObservedCache {
    async fn get(&self, key: &str) -> AuthResult<Option<JsonValue>> {
        self.inner.get(key).await
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: Option<u64>) -> AuthResult<()> {
        let _ = self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.set(key, value, ttl_seconds).await
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        let _ = self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.delete(key).await
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<JsonValue>> {
        let _ = self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.get_and_delete(key).await
    }
}

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, run: Run) -> TestResult {
    let _ = raw
        .create_user(CreateUser {
            id: Some("owner".into()),
            name: Some("Owner".into()).into(),
            email: Some("owner@session-defaults.test".into()),
            ..Default::default()
        })
        .await?;
    let cache = Arc::new(ObservedCache::default());
    let store: Arc<dyn AuthStore<S>> = if run.pure {
        Arc::new(SecondaryStore::new(
            raw.clone(),
            cache.clone(),
            Arc::new(run.config),
            Default::default(),
        )?)
    } else {
        raw.clone()
    };
    let create_input = input(run.case)?;
    let started = chrono::Utc::now().timestamp_millis() as f64;
    let result = match run.call {
        Call::Ordinary => store.create_session_optional(create_input).await,
        Call::Transaction => {
            transaction(store.as_ref(), move |tx| {
                Box::pin(async move { tx.create_session_optional(create_input).await })
            })
            .await
        }
        Call::Deferred => {
            transaction(store.as_ref(), move |tx| {
                Box::pin(async move {
                    tx.create_session_with_deferred_secondary(create_input)
                        .await
                        .map(Some)
                })
            })
            .await
        }
    };
    let ended = chrono::Utc::now().timestamp_millis() as f64;
    if run.case == Case::DefaultFailure {
        assert_eq!(cache.writes.load(Ordering::SeqCst), 0);
    }
    let expected = expected_events(run.case, run.pure);
    assert_eq!(
        run.events.try_iter().collect::<Vec<_>>(),
        expected,
        "{:?}, {:?}, pure={}",
        run.case,
        run.call,
        run.pure
    );
    let failed = matches!(run.case, Case::Failure | Case::DefaultFailure)
        || (run.pure && run.case == Case::GeneratorFailure);
    if failed || (run.case == Case::Cancel && run.call == Call::Deferred) {
        let error = result
            .err()
            .ok_or("Session creation unexpectedly succeeded")?;
        let expected_error = if run.case == Case::Failure {
            AuthError::bad_request("session hook failure")
        } else if run.case == Case::DefaultFailure {
            assert!(matches!(
                &error,
                AuthError::FieldInput {
                    code: "SESSION_DEFAULT_REJECTED",
                    ..
                }
            ));
            AuthError::FieldInput {
                code: "SESSION_DEFAULT_REJECTED",
                message: "session default failure".into(),
            }
        } else if run.case == Case::GeneratorFailure {
            AuthError::bad_request("session generator failure")
        } else {
            AuthError::forbidden("session creation cancelled by database hook")
        };
        assert_eq!(error.to_string(), expected_error.to_string());
    } else if run.case == Case::Cancel {
        assert_eq!(result?, None);
    } else {
        let created = result?.ok_or("Session creation unexpectedly cancelled")?;
        let Some(Event::After(id, fields)) = expected.last() else {
            return Err("Session creation has no expected after hook".into());
        };
        assert_eq!(created.id.field_value(), *id);
        assert_eq!(created.additional_fields, *fields);
        assert_eq!(created.user_id, "owner");
        assert_eq!(created.expires_at, input(run.case)?.expires_at);
        assert_eq!(created.ip_address.as_deref(), Some(""));
        assert_eq!(created.user_agent.as_deref(), Some(""));
        assert!((started..=ended).contains(&created.created_at.milliseconds()));
        assert!((started..=ended).contains(&created.updated_at.milliseconds()));
        if run.pure {
            let cached = cache
                .get(&created.token)
                .await?
                .ok_or("Session cache is missing")?;
            let cached: JsonValue =
                serde_json::from_str(cached.as_str().ok_or("Session cache is not text")?)?;
            let mut expected_cache = FieldMap::from(created.clone());
            for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
                let _ = expected_cache.remove(name);
            }
            assert_eq!(
                cached.get("session"),
                Some(&JsonValue::Object(expected_cache.json()?))
            );
            assert_eq!(
                cached.get("user").and_then(|user| user.get("id")),
                Some(&json!("owner"))
            );
            let references = cache
                .get("active-sessions-owner")
                .await?
                .ok_or("Session references are missing")?;
            let references: JsonValue = serde_json::from_str(
                references
                    .as_str()
                    .ok_or("Session references are not text")?,
            )?;
            assert_eq!(
                references,
                json!([{"token":created.token, "expiresAt":created.expires_at.milliseconds() as i64}])
            );
        } else {
            assert_eq!(
                raw.get_session(&created.token).await?,
                Some(created.clone())
            );
            assert_eq!(raw.get_user_sessions("owner").await?, [created]);
        }
    }
    if run.pure || run.case == Case::Cancel || failed {
        assert!(raw.get_user_sessions("owner").await?.is_empty());
    }
    if !run.pure || run.case == Case::Cancel || failed {
        assert_eq!(cache.get("active-sessions-owner").await?, None);
    }
    Ok(())
}

#[tokio::test]
async fn memory_session_defaults_precede_hooks_and_secondary_generation() -> TestResult {
    for pure in [false, true] {
        for call in [Call::Ordinary, Call::Transaction, Call::Deferred] {
            for case in CASES {
                let (events, receiver) = mpsc::channel();
                let config = config(case, pure, &events);
                let store: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(
                    EphemeralStore::new(Arc::new(config.clone()))
                        .with_hooks(vec![Arc::new(Hooks { case, events })]),
                );
                contract(
                    store,
                    Run {
                        case,
                        pure,
                        call,
                        config,
                        events: receiver,
                    },
                )
                .await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn sql_session_defaults_precede_hooks_and_secondary_generation() -> TestResult {
    let database = Database::connect("sqlite::memory:").await?;
    migrator::run_migrations(&database).await?;
    for pure in [false, true] {
        for call in [Call::Ordinary, Call::Transaction, Call::Deferred] {
            for case in CASES {
                let _ = session::Entity::delete_many().exec(&database).await?;
                let _ = user::Entity::delete_many().exec(&database).await?;
                let (events, receiver) = mpsc::channel();
                let config = config(case, pure, &events);
                let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database.clone())
                    .with_runtime(
                        Arc::new(config.clone()),
                        vec![Arc::new(Hooks { case, events })],
                        Default::default(),
                    )?;
                contract(
                    store,
                    Run {
                        case,
                        pure,
                        call,
                        config,
                        events: receiver,
                    },
                )
                .await?;
            }
        }
    }
    Ok(())
}
