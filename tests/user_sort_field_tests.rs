#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, CreateUser, FieldDate, FieldMap, FieldValue,
    ListUsersParams,
    id::{IdGeneration, IdGenerator},
    store::{EphemeralStore, StatelessSchema, UserStore},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};
use better_auth_seaorm::{
    AuthEntity, SeaOrmStore,
    sea_orm::{self, ConnectionTrait, Database, Schema, entity::prelude::*},
    store::entities,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

type Trace = Arc<Mutex<Vec<Value>>>;

fn take_events(trace: &Trace) -> AuthResult<Vec<Value>> {
    Ok(std::mem::take(&mut *trace.lock().map_err(|_| {
        AuthError::internal("Sort field trace lock poisoned")
    })?))
}

fn config(trace: &Trace) -> AuthConfig {
    let mut config = AuthConfig::new("ordinary-user-sort-field-secret-at-least-32-characters")
        .base_url("http://user-sort-field.test");
    let next_id = AtomicUsize::new(1);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |_| {
            Ok(Some(next_id.fetch_add(1, Ordering::SeqCst).to_string()))
        })));
    for (name, physical, field_type) in [
        ("label", "stored_label", UserFieldType::String),
        ("rank", "stored_rank", UserFieldType::Number),
    ] {
        let trace = trace.clone();
        let _ = config.user.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_type,
                field_name: Some(physical.into()),
                required: Some(false),
                transform: (name == "label").then(|| FieldTransforms {
                    input: None,
                    output: Some(UserFieldTransform::new(move |value| {
                        if value.is_undefined() {
                            return Err(AuthError::internal("Expected the supplied display label"));
                        }
                        trace
                            .lock()
                            .map_err(|_| AuthError::internal("Sort field trace lock poisoned"))?
                            .push(json!(["output", "label", value.json()?]));
                        Ok(value)
                    })),
                }),
                ..Default::default()
            },
        );
    }
    config
}

fn queries() -> Vec<(&'static str, ListUsersParams)> {
    [
        (
            "unknown-zero",
            Some("absent"),
            "unknownDisplay",
            "asc",
            10.0,
        ),
        ("unknown-one", Some("alpha"), "unknownDisplay", "asc", 10.0),
        ("unknown-two", None, "unknownDisplay", "asc", 10.0),
        ("logical-rank", None, "rank", "asc", 10.0),
        ("physical-rank", None, "stored_rank", "desc", 1.0),
    ]
    .into_iter()
    .map(|(name, filter, sort, direction, limit)| {
        (
            name,
            ListUsersParams {
                limit: Some(limit),
                offset: Some(0.0),
                sort_by: Some(sort.into()),
                sort_direction: Some(direction.into()),
                filter_field: filter.map(|_| "label".into()),
                filter_value: filter.map(FieldValue::from),
                filter_operator: filter.map(|_| "eq".into()),
                ..Default::default()
            },
        )
    })
    .collect()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryResult {
    users: Vec<Map<String, Value>>,
    total: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessObservation {
    name: String,
    events: Vec<Value>,
    result: QueryResult,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedError {
    kind: String,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorObservation {
    name: String,
    events: Vec<Value>,
    error: ObservedError,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Observation {
    Success(SuccessObservation),
    Error(ErrorObservation),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendObservation {
    backend: String,
    queries: Vec<Observation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    version: String,
    backends: Vec<BackendObservation>,
}

async fn observe<S: AuthSchema>(
    backend: &str,
    store: &impl UserStore<S>,
    trace: &Trace,
) -> AuthResult<BackendObservation> {
    let timestamp = "2030-01-01T00:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map(FieldDate::from)
        .map_err(|error| AuthError::internal(error.to_string()))?;
    for (label, name, rank) in [("alpha", "Sort Alpha", 20), ("beta", "Sort Beta", 3)] {
        let _ = store
            .create_user(CreateUser {
                name: Some(name.into()).into(),
                email: Some(format!("{label}@user-sort-field.test")),
                email_verified: Some(false),
                created_at: Some(timestamp.clone()),
                updated_at: Some(timestamp.clone()),
                additional_fields: FieldMap::from_iter([
                    ("label".into(), label.into()),
                    ("rank".into(), rank.into()),
                ]),
                ..Default::default()
            })
            .await?;
    }
    let _ = take_events(trace)?;
    let mut observations = Vec::new();
    for (name, params) in queries() {
        let result = store.list_users(params).await;
        let events = take_events(trace)?;
        observations.push(match result {
            Ok((users, total)) => Observation::Success(SuccessObservation {
                name: name.into(),
                events,
                result: QueryResult {
                    users: users
                        .into_iter()
                        .map(|user| user.additional_fields.json())
                        .collect::<AuthResult<Vec<_>>>()?,
                    total,
                },
            }),
            Err(AuthError::Internal(message)) => Observation::Error(ErrorObservation {
                name: name.into(),
                events,
                error: ObservedError {
                    kind: "Internal".into(),
                    message,
                },
            }),
            Err(error) => return Err(error),
        });
    }
    Ok(BackendObservation {
        backend: backend.into(),
        queries: observations,
    })
}

#[expect(unreachable_pub, reason = "SeaORM derives require public model items")]
mod user {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[sea_orm(table_name = "sort_field_users")]
    #[auth(role = "user")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub stored_label: Option<String>,
        pub stored_rank: Option<i64>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

struct Tables;
impl AuthSchema for Tables {
    type User = user::Model;
    type Account = entities::account::Model;
    type Session = entities::session::Model;
    type Verification = entities::verification::Model;
}

#[expect(
    clippy::panic,
    reason = "A different result variant must fail the complete upstream contract"
)]
async fn contract() -> Result<(), Box<dyn std::error::Error>> {
    let expected: Capture =
        serde_json::from_str(include_str!("fixtures/user-sort-field-1.7.6.json"))?;
    let memory_trace = Trace::default();
    let memory = EphemeralStore::new(config(&memory_trace).into());
    let memory = observe::<StatelessSchema>("memory", &memory, &memory_trace).await?;
    let sqlite_trace = Trace::default();
    let db = Database::connect("sqlite::memory:").await?;
    let _ = db
        .execute(&Schema::new(db.get_database_backend()).create_table_from_entity(user::Entity))
        .await?;
    let sqlite = SeaOrmStore::<Tables>::new(config(&sqlite_trace), db);
    let sqlite = observe("sqlite", &sqlite, &sqlite_trace).await?;
    let actual = [memory, sqlite];
    assert_eq!(expected.version, "1.7.6");
    assert_eq!(actual.len(), expected.backends.len());
    for (actual, expected) in actual.into_iter().zip(expected.backends) {
        assert_eq!(actual.backend, expected.backend);
        assert_eq!(actual.queries.len(), expected.queries.len());
        for (actual, expected) in actual.queries.into_iter().zip(expected.queries) {
            match (actual, expected) {
                (Observation::Success(actual), Observation::Success(expected)) => {
                    assert_eq!(actual.name, expected.name);
                    assert_eq!(actual.events, expected.events);
                    assert_eq!(actual.result.users, expected.result.users);
                    assert_eq!(actual.result.total, expected.result.total);
                }
                (Observation::Error(actual), Observation::Error(expected)) => {
                    assert_eq!(actual.name, expected.name);
                    assert_eq!(actual.events, expected.events);
                    assert_eq!(actual.error.kind, "Internal");
                    assert_eq!(expected.error.kind, "BetterAuthError");
                    assert_eq!(actual.error.message, expected.error.message);
                }
                (actual, expected) => {
                    panic!("User sort outcome differs: actual={actual:?}, expected={expected:?}")
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "Setup errors and complete sort field differences must fail this contract"
)]
async fn user_sort_declarations_match_pinned_memory_and_sqlite() {
    contract().await.expect("User sort field contract passes");
}
