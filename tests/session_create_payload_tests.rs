#![cfg(feature = "seaorm2")]
#![allow(
    unreachable_pub,
    reason = "SeaORM entity derives require public generated model types"
)]

use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateSession, CreateUser, FieldDate,
    FieldMap, FieldValue, SessionView,
    id::{IdGeneration, IdGenerator},
    store::{
        EphemeralStore, MemoryCacheAdapter, RuntimeStore, SecondaryStorage, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
        secondary::SecondaryStore,
        transaction,
    },
};
use better_auth_seaorm::{
    AuthEntity, SeaOrmStore,
    sea_orm::{self, ConnectionTrait, Database, EntityTrait, Schema, entity::prelude::*},
    store::{__private_test_support::migrator, entities},
};
use chrono::Utc;
use serde_json::{Value as JsonValue, json};
use std::sync::{
    Arc,
    mpsc::{self, Receiver, Sender},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[path = "session_create_payload_tests/declared_fields.rs"]
mod declared_fields;

const SESSION_ID: &str = "generated-session-1";
const EXPIRY: &str = "2031-01-02T03:04:05Z";
const CHANGED_EXPIRY: &str = "2032-01-02T03:04:05Z";
const USER_DATE: &str = "2031-01-02T03:04:05Z";

mod session {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "session")]
    #[sea_orm(table_name = "payload_sessions")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub expires_at: DateTimeUtc,
        pub token: String,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: String,
        pub active: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

struct NativeSchema;
impl AuthSchema for NativeSchema {
    type User = entities::user::Model;
    type Session = session::Model;
    type Account = entities::account::Model;
    type Verification = entities::verification::Model;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Database,
    Secondary,
    Mirrored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Ordinary,
    Transaction,
    Deferred,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Generated,
    Mutate,
    Patch,
    EmptyPatch,
    PartialPatch,
    Cancel,
    Fail,
}

const RUNS: [(Mode, Call, Case); 12] = [
    (Mode::Database, Call::Ordinary, Case::Generated),
    (Mode::Database, Call::Transaction, Case::Mutate),
    (Mode::Secondary, Call::Ordinary, Case::Generated),
    (Mode::Secondary, Call::Ordinary, Case::Patch),
    (Mode::Secondary, Call::Transaction, Case::EmptyPatch),
    (Mode::Secondary, Call::Deferred, Case::Patch),
    (Mode::Mirrored, Call::Ordinary, Case::Mutate),
    (Mode::Mirrored, Call::Transaction, Case::Patch),
    (Mode::Mirrored, Call::Deferred, Case::EmptyPatch),
    (Mode::Mirrored, Call::Transaction, Case::PartialPatch),
    (Mode::Database, Call::Ordinary, Case::Cancel),
    (Mode::Secondary, Call::Ordinary, Case::Fail),
];

#[derive(Debug, PartialEq)]
enum Event {
    Generate(String, Option<usize>),
    Default(&'static str, FieldValue),
    Before(u8, FieldMap),
    After(u8, FieldMap),
    TransactionReturn(FieldMap),
    Get(String, Option<JsonValue>),
    Set(String, JsonValue, Option<u64>),
    Delete(String),
    Consume(String, Option<JsonValue>),
}

fn emit(events: &Sender<Event>, event: Event) -> AuthResult<()> {
    events
        .send(event)
        .map_err(|error| AuthError::internal(error.to_string()))
}

fn date(value: &str) -> AuthResult<FieldDate> {
    value
        .parse::<chrono::DateTime<Utc>>()
        .map(Into::into)
        .map_err(|error| AuthError::internal(error.to_string()))
}

fn replacements() -> AuthResult<FieldMap> {
    Ok([
        ("token".into(), "hook-token".into()),
        ("userId".into(), "other".into()),
        ("expiresAt".into(), date(CHANGED_EXPIRY)?.into()),
        ("createdAt".into(), date("2031-02-03T04:05:06Z")?.into()),
        ("updatedAt".into(), date("2031-02-03T04:05:07Z")?.into()),
    ]
    .into())
}

struct Hooks {
    stage: u8,
    case: Case,
    events: Sender<Event>,
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn before_create_session(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        emit(&self.events, Event::Before(self.stage, data.clone()))?;
        if self.stage == 1 {
            match self.case {
                Case::Generated => {}
                Case::Mutate => data.extend(replacements()?),
                Case::Patch => return Ok(DatabaseHookUpdate::Patch(replacements()?)),
                Case::EmptyPatch => return Ok(DatabaseHookUpdate::Patch(FieldMap::new())),
                Case::PartialPatch => {
                    let mut patch = FieldMap::new();
                    for (name, value) in replacements()? {
                        if matches!(name.as_str(), "token" | "updatedAt") {
                            let _ = patch.insert(name, value);
                        } else {
                            let _ = data.insert(name, value);
                        }
                    }
                    return Ok(DatabaseHookUpdate::Patch(patch));
                }
                Case::Cancel => return Ok(DatabaseHookUpdate::Cancel),
                Case::Fail => return Err(AuthError::bad_request("session payload hook failure")),
            }
        } else if self.case == Case::EmptyPatch {
            data.extend(replacements()?);
        }
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_create_session(
        &self,
        data: &SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        emit(&self.events, Event::After(self.stage, data.clone().into()))
    }
}

struct RecordingStorage {
    inner: MemoryCacheAdapter,
    events: Sender<Event>,
}

#[async_trait]
impl SecondaryStorage for RecordingStorage {
    async fn get(&self, key: &str) -> AuthResult<Option<JsonValue>> {
        let value = self.inner.get(key).await?;
        emit(&self.events, Event::Get(key.into(), value.clone()))?;
        Ok(value)
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> AuthResult<()> {
        self.inner.set(key, value, ttl).await?;
        emit(
            &self.events,
            Event::Set(key.into(), serde_json::from_str(value)?, ttl),
        )
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.inner.delete(key).await?;
        emit(&self.events, Event::Delete(key.into()))
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<JsonValue>> {
        let value = self.inner.get_and_delete(key).await?;
        emit(&self.events, Event::Consume(key.into(), value.clone()))?;
        Ok(value)
    }
}

fn config(mode: Mode, events: &Sender<Event>) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.session.store_session_in_database = Some(mode != Mode::Secondary);
    let events = events.clone();
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            emit(&events, Event::Generate(request.model.into(), request.size))?;
            Ok(Some(SESSION_ID.into()))
        })));
    config
}

fn hooks<S: AuthSchema>(case: Case, events: &Sender<Event>) -> Vec<Arc<dyn DatabaseHooks<S>>> {
    [1, 2]
        .into_iter()
        .map(|stage| {
            Arc::new(Hooks {
                stage,
                case,
                events: events.clone(),
            }) as Arc<dyn DatabaseHooks<S>>
        })
        .collect()
}

fn input() -> AuthResult<CreateSession> {
    Ok(CreateSession {
        user_id: "owner".into(),
        expires_at: date(EXPIRY)?,
        ip_address: Some("192.0.2.10".into()),
        user_agent: Some("session-payload-contract".into()),
        impersonated_by: None,
        active_organization_id: None,
        additional_fields: [("id".into(), "ignored-id".into())].into(),
    })
}

async fn seed_users<S: AuthSchema>(store: &dyn AuthStore<S>) -> TestResult {
    for (id, name) in [("owner", "Owner"), ("other", "Other")] {
        let _ = store
            .create_user(CreateUser {
                id: Some(id.into()),
                name: Some(name.into()).into(),
                email: Some(format!("{id}@session-payload.test")),
                email_verified: Some(true),
                image: None.into(),
                created_at: Some(date(USER_DATE)?),
                updated_at: Some(date(USER_DATE)?),
                ..Default::default()
            })
            .await?;
    }
    Ok(())
}

fn owner_json() -> JsonValue {
    json!({
        "id": "owner", "name": "Owner", "email": "owner@session-payload.test",
        "emailVerified": true, "image": null,
        "createdAt": "2031-01-02T03:04:05.000Z", "updatedAt": "2031-01-02T03:04:05.000Z"
    })
}

struct Run {
    mode: Mode,
    call: Call,
    case: Case,
    config: AuthConfig,
    events: Sender<Event>,
    receiver: Receiver<Event>,
}

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, run: Run) -> TestResult {
    seed_users(raw.as_ref()).await?;
    assert!(run.receiver.try_iter().next().is_none());
    let cache = Arc::new(RecordingStorage {
        inner: MemoryCacheAdapter::new(),
        events: run.events.clone(),
    });
    let store: Arc<dyn AuthStore<S>> = if run.mode == Mode::Database {
        raw.clone()
    } else {
        Arc::new(SecondaryStore::new(
            raw.clone(),
            cache.clone(),
            Arc::new(run.config),
            Default::default(),
        )?)
    };
    let create = input()?;
    let started = Utc::now().timestamp_millis();
    let result = if run.call == Call::Ordinary {
        store.create_session_optional(create).await
    } else {
        let events = run.events.clone();
        transaction(store.as_ref(), move |tx| {
            Box::pin(async move {
                let session = if run.call == Call::Deferred {
                    Some(tx.create_session_with_deferred_secondary(create).await?)
                } else {
                    tx.create_session_optional(create).await?
                };
                if let Some(session) = &session {
                    emit(&events, Event::TransactionReturn(session.clone().into()))?;
                }
                Ok(session)
            })
        })
        .await
    };
    let finished = Utc::now().timestamp_millis();
    let events: Vec<_> = run.receiver.try_iter().collect();
    let initial = events
        .iter()
        .find_map(|event| match event {
            Event::Before(1, fields) => Some(fields),
            _ => None,
        })
        .ok_or("First session hook did not run")?;
    let token = initial
        .get("token")
        .and_then(FieldValue::as_str)
        .ok_or("Session hook token is missing")?;
    assert_eq!(token.len(), 32);
    assert!(token.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    let created_at = initial
        .get("createdAt")
        .and_then(FieldValue::as_date)
        .ok_or("Session hook createdAt is missing")?;
    let updated_at = initial
        .get("updatedAt")
        .and_then(FieldValue::as_date)
        .ok_or("Session hook updatedAt is missing")?;
    assert!(!created_at.same_object(updated_at));
    for value in [created_at, updated_at] {
        assert!(value.milliseconds() >= started as f64);
        assert!(value.milliseconds() <= finished as f64);
    }
    let mut expected_initial: FieldMap = [
        ("token".into(), token.into()),
        ("userId".into(), "owner".into()),
        ("expiresAt".into(), date(EXPIRY)?.into()),
        ("createdAt".into(), created_at.clone().into()),
        ("updatedAt".into(), updated_at.clone().into()),
        ("ipAddress".into(), "192.0.2.10".into()),
        ("userAgent".into(), "session-payload-contract".into()),
    ]
    .into();
    if run.mode == Mode::Secondary {
        let _ = expected_initial.insert("id".into(), SESSION_ID.into());
    }
    assert_eq!(*initial, expected_initial);
    let mut expected_events = Vec::new();
    if run.mode == Mode::Secondary {
        expected_events.push(Event::Generate("session".into(), None));
    }
    expected_events.push(Event::Before(1, expected_initial.clone()));
    if matches!(run.case, Case::Cancel | Case::Fail) {
        if run.case == Case::Cancel {
            assert_eq!(result?, None);
        } else {
            let error = result
                .err()
                .ok_or("Session hook failure did not propagate")?;
            assert_eq!(
                error.to_string(),
                AuthError::bad_request("session payload hook failure").to_string()
            );
        }
        assert_eq!(events, expected_events);
        assert!(raw.get_user_sessions("owner").await?.is_empty());
        assert!(raw.get_user_sessions("other").await?.is_empty());
        assert_eq!(cache.inner.get("active-sessions-owner").await?, None);
        assert_eq!(cache.inner.get(token).await?, None);
        return Ok(());
    }
    let mut expected_final = expected_initial.clone();
    if run.case != Case::Generated {
        expected_final.extend(replacements()?);
    }
    expected_events.push(Event::Before(
        2,
        if run.case == Case::EmptyPatch {
            expected_initial.clone()
        } else {
            expected_final.clone()
        },
    ));
    let _ = expected_final.insert("id".into(), SESSION_ID.into());
    if run.mode != Mode::Secondary {
        expected_events.push(Event::Generate("session".into(), None));
    }
    let created = result?.ok_or("Session creation was unexpectedly cancelled")?;
    assert_eq!(FieldMap::from(created.clone()), expected_final);
    assert!(created.active);
    assert!(created.additional_fields.is_empty());
    assert_eq!(
        expected_final.get("token").and_then(FieldValue::as_str),
        Some(created.token.as_str())
    );
    assert_eq!(
        expected_final
            .get("createdAt")
            .and_then(FieldValue::as_date),
        Some(&created.created_at)
    );
    assert_eq!(
        expected_final
            .get("updatedAt")
            .and_then(FieldValue::as_date),
        Some(&created.updated_at)
    );
    let mirror_token = if run.case == Case::Mutate {
        "hook-token"
    } else {
        token
    };
    let mirror_expiry = date(if matches!(run.case, Case::Mutate | Case::PartialPatch) {
        CHANGED_EXPIRY
    } else {
        EXPIRY
    })?;
    let after = [
        Event::After(1, expected_final.clone()),
        Event::After(2, expected_final.clone()),
    ];
    let mut mirror_events = Vec::new();
    if run.mode != Mode::Database {
        let ttl = events
            .iter()
            .find_map(|event| match event {
                Event::Set(key, _, Some(ttl)) if key == mirror_token => Some(*ttl),
                _ => None,
            })
            .ok_or("Session mirror did not set its original token with a TTL")?;
        let expires_ms = mirror_expiry.milliseconds() as i64;
        let minimum = u64::try_from((expires_ms - finished).div_euclid(1000))?;
        let maximum = u64::try_from((expires_ms - started).div_euclid(1000))?;
        assert!((minimum..=maximum).contains(&ttl));
        let references = json!([{"token": mirror_token, "expiresAt": expires_ms}]);
        let payload = json!({"session": expected_final.json()?, "user": owner_json()});
        mirror_events = vec![
            Event::Get("active-sessions-owner".into(), None),
            Event::Set(
                "active-sessions-owner".into(),
                references.clone(),
                Some(ttl),
            ),
            Event::Set(mirror_token.into(), payload.clone(), Some(ttl)),
        ];
        for (key, expected) in [
            ("active-sessions-owner", references),
            (mirror_token, payload),
        ] {
            let value = cache
                .inner
                .get(key)
                .await?
                .ok_or("Expected cache entry is missing")?;
            let value: JsonValue =
                serde_json::from_str(value.as_str().ok_or("Cache entry is not text")?)?;
            assert_eq!(value, expected);
        }
        assert_eq!(cache.inner.get("active-sessions-other").await?, None);
        if mirror_token != created.token {
            assert_eq!(cache.inner.get(&created.token).await?, None);
        }
    }
    if run.call == Call::Deferred {
        expected_events.push(Event::TransactionReturn(expected_final.clone()));
        expected_events.extend(after);
        expected_events.extend(mirror_events);
    } else {
        expected_events.extend(mirror_events);
        if run.call == Call::Transaction {
            expected_events.push(Event::TransactionReturn(expected_final.clone()));
        }
        expected_events.extend(after);
    }
    assert_eq!(
        events, expected_events,
        "{:?}/{:?}/{:?}",
        run.mode, run.call, run.case
    );
    if run.mode == Mode::Secondary {
        assert!(raw.get_user_sessions("owner").await?.is_empty());
        assert!(raw.get_user_sessions("other").await?.is_empty());
    } else {
        assert_eq!(
            raw.get_session(&created.token).await?,
            Some(created.clone())
        );
        let user_id = if run.case == Case::Generated {
            "owner"
        } else {
            "other"
        };
        let absent = if user_id == "owner" { "other" } else { "owner" };
        assert_eq!(raw.get_user_sessions(user_id).await?, [created]);
        assert!(raw.get_user_sessions(absent).await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn memory_session_creation_preserves_native_hook_payload_and_cache_identity() -> TestResult {
    for (mode, call, case) in RUNS {
        let (events, receiver) = mpsc::channel();
        let config = config(mode, &events);
        let raw: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(
            EphemeralStore::new(Arc::new(config.clone())).with_hooks(hooks(case, &events)),
        );
        contract(
            raw,
            Run {
                mode,
                call,
                case,
                config,
                events,
                receiver,
            },
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_session_creation_preserves_native_hook_payload_and_cache_identity() -> TestResult {
    let database = Database::connect("sqlite::memory:").await?;
    migrator::run_migrations(&database).await?;
    let _ = database
        .execute(
            &Schema::new(database.get_database_backend()).create_table_from_entity(session::Entity),
        )
        .await?;
    for (mode, call, case) in RUNS {
        let _ = session::Entity::delete_many().exec(&database).await?;
        let _ = entities::user::Entity::delete_many()
            .exec(&database)
            .await?;
        let (events, receiver) = mpsc::channel();
        let config = config(mode, &events);
        let raw = SeaOrmStore::<NativeSchema>::new(config.clone(), database.clone()).with_runtime(
            Arc::new(config.clone()),
            hooks(case, &events),
            Default::default(),
        )?;
        contract(
            raw,
            Run {
                mode,
                call,
                case,
                config,
                events,
                receiver,
            },
        )
        .await?;
    }
    Ok(())
}
