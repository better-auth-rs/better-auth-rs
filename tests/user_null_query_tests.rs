#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, CreateUser, ListUsersParams, UserView,
    id::{IdGeneration, IdGenerator},
    store::{EphemeralStore, StatelessSchema, UserStore},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
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

fn observed(value: Option<&Value>) -> Value {
    match value {
        None => json!({"defined":false}),
        Some(value) => json!({"defined":true,"value":value}),
    }
}

fn display(user: UserView) -> Value {
    Value::Object(Map::from_iter(["marker", "label"].map(|name| {
        let value = user.additional_fields.get(name);
        (
            name.into(),
            json!({"own":value.is_some(),"value":observed(value)}),
        )
    })))
}

fn take_events(trace: &Trace) -> AuthResult<Vec<Value>> {
    Ok(std::mem::take(&mut *trace.lock().map_err(|_| {
        AuthError::internal("Nullable query trace lock poisoned")
    })?))
}

fn config(trace: &Trace) -> AuthConfig {
    let mut config = AuthConfig::new("ordinary-user-null-query-secret-at-least-32-characters")
        .base_url("http://user-null-query.test");
    let next_id = AtomicUsize::new(1);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |_| {
            Ok(Some(next_id.fetch_add(1, Ordering::SeqCst).to_string()))
        })));
    let _ = config.user.fields_mut().insert(
        "marker".into(),
        UserFieldConfig {
            field_type: UserFieldType::String,
            field_name: Some("stored_marker".into()),
            required: Some(false),
            ..Default::default()
        },
    );
    let trace = trace.clone();
    let _ = config.user.fields_mut().insert(
        "label".into(),
        UserFieldConfig {
            field_type: UserFieldType::String,
            field_name: Some("stored_label".into()),
            required: Some(false),
            transform: Some(FieldTransforms {
                input: None,
                output: Some(UserFieldTransform::new(move |value| {
                    trace
                        .lock()
                        .map_err(|_| AuthError::internal("Nullable query trace lock poisoned"))?
                        .push(json!(["output", "label", observed(value.as_ref())]));
                    Ok(Some(value.unwrap_or_else(|| json!("(missing)"))))
                })),
            }),
            ..Default::default()
        },
    );
    config
}

fn params(field: &str, value: Value, operator: &str) -> ListUsersParams {
    ListUsersParams {
        limit: Some(10.0),
        offset: Some(0.0),
        sort_by: Some("marker".into()),
        sort_direction: Some("asc".into()),
        filter_field: Some(field.into()),
        filter_value: Some(value),
        filter_operator: Some(operator.into()),
        ..Default::default()
    }
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
#[serde(deny_unknown_fields)]
struct BackendObservation {
    backend: String,
    queries: Vec<Value>,
    errors: Vec<ErrorObservation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    version: String,
    backends: Vec<BackendObservation>,
}

fn observe_error<T>(
    name: &str,
    result: AuthResult<T>,
    trace: &Trace,
) -> AuthResult<ErrorObservation> {
    match result {
        Err(AuthError::Internal(message)) => Ok(ErrorObservation {
            name: name.into(),
            events: take_events(trace)?,
            error: ObservedError {
                kind: "Internal".into(),
                message,
            },
        }),
        Err(error) => Err(error),
        Ok(_) => Err(AuthError::internal("The undeclared filter must fail")),
    }
}

async fn observe<S: AuthSchema>(
    backend: &str,
    store: &impl UserStore<S>,
    fields: &UserConfig,
    trace: &Trace,
) -> AuthResult<BackendObservation> {
    let timestamp = "2030-01-01T00:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|error| AuthError::internal(error.to_string()))?;
    for (marker, name, label) in [
        ("alpha", "Null Query Alpha", None),
        ("beta", "Null Query Beta", Some(Value::Null)),
        ("gamma", "Null Query Gamma", Some(json!("ordinary"))),
    ] {
        let mut additional_fields = Map::from_iter([("marker".into(), json!(marker))]);
        if let Some(label) = label {
            let _ = additional_fields.insert("label".into(), label);
        }
        let _ = store
            .create_user(CreateUser {
                name: Some(name.into()).into(),
                email: Some(format!("{marker}@user-null-query.test")),
                email_verified: Some(false),
                created_at: Some(timestamp),
                updated_at: Some(timestamp),
                additional_fields,
                ..Default::default()
            })
            .await?;
    }
    let _ = take_events(trace)?;
    let mut queries = Vec::new();
    for (name, field, operator) in [
        ("logical-eq-null", "label", "eq"),
        ("physical-eq-null", "stored_label", "eq"),
        ("logical-ne-null", "label", "ne"),
        ("physical-ne-null", "stored_label", "ne"),
    ] {
        let (users, total) = store
            .list_users(params(field, Value::Null, operator))
            .await?;
        queries.push(json!({
            "name":name,
            "events":take_events(trace)?,
            "result":{"users":users.into_iter().map(display).collect::<Vec<_>>(),"total":total},
        }));
    }
    let unknown = params("unknownLabel", json!("ordinary"), "eq");
    let list_error = observe_error(
        "unknown-list",
        store.list_users(unknown.clone()).await,
        trace,
    )?;
    let count_error = observe_error(
        "unknown-count",
        better_auth_core::user_query::count_users(
            std::iter::empty::<&UserView>(),
            &unknown,
            fields,
            |user| (user, &user.additional_fields),
        ),
        trace,
    )?;
    Ok(BackendObservation {
        backend: backend.into(),
        queries,
        errors: vec![list_error, count_error],
    })
}

#[expect(unreachable_pub, reason = "SeaORM derives require public model items")]
mod user {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[sea_orm(table_name = "nullable_query_users")]
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
        pub stored_marker: Option<String>,
        pub stored_label: Option<String>,
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

async fn contract() -> Result<(), Box<dyn std::error::Error>> {
    let expected: Capture =
        serde_json::from_str(include_str!("fixtures/user-null-query-1.7.6.json"))?;
    let memory_trace = Trace::default();
    let memory_config = config(&memory_trace);
    let memory = EphemeralStore::new(memory_config.clone().into());
    let memory =
        observe::<StatelessSchema>("memory", &memory, &memory_config.user, &memory_trace).await?;
    let sqlite_trace = Trace::default();
    let sqlite_config = config(&sqlite_trace);
    let db = Database::connect("sqlite::memory:").await?;
    let _ = db
        .execute(&Schema::new(db.get_database_backend()).create_table_from_entity(user::Entity))
        .await?;
    let sqlite = SeaOrmStore::<Tables>::new(sqlite_config.clone(), db);
    let sqlite = observe("sqlite", &sqlite, &sqlite_config.user, &sqlite_trace).await?;
    let actual = [memory, sqlite];
    assert_eq!(expected.version, "1.7.6");
    assert_eq!(actual.len(), expected.backends.len());
    for (actual, expected) in actual.into_iter().zip(expected.backends) {
        assert_eq!(actual.backend, expected.backend);
        assert_eq!(actual.queries, expected.queries);
        assert_eq!(actual.errors.len(), expected.errors.len());
        for (actual, expected) in actual.errors.into_iter().zip(expected.errors) {
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.events, expected.events);
            assert_eq!(actual.error.kind, "Internal");
            assert_eq!(expected.error.kind, "BetterAuthError");
            assert_eq!(actual.error.message, expected.error.message);
        }
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "Setup errors and complete nullable query differences must fail this contract"
)]
async fn nullable_user_display_queries_match_pinned_memory_and_sqlite() {
    contract()
        .await
        .expect("Nullable User query contract passes");
}

#[path = "user_null_query_tests/skipped_null.rs"]
mod skipped_null;
