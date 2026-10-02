#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, CreateUser, ListUsersParams,
    id::{IdGeneration, IdGenerator},
    store::{EphemeralStore, StatelessSchema, UserStore},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};
use better_auth_seaorm::{
    AuthEntity, SeaOrmStore,
    sea_orm::{self, ConnectionTrait, Database, Schema, entity::prelude::*},
    store::entities,
};
use serde_json::{Map, Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

type Trace = Arc<Mutex<Vec<Value>>>;

fn label_transform(trace: &Trace, phase: &'static str, suffix: &'static str) -> UserFieldTransform {
    let trace = trace.clone();
    UserFieldTransform::new(move |value| {
        trace
            .lock()
            .map_err(|_| AuthError::internal("Display query trace lock poisoned"))?
            .push(json!([phase, "label", value]));
        let value = value
            .as_ref()
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::internal("Expected the supplied display label"))?;
        Ok(Some(json!(format!("{value}:{suffix}"))))
    })
}

fn config(trace: &Trace) -> AuthConfig {
    let mut config = AuthConfig::new("ordinary-user-display-query-secret-at-least-32-characters")
        .base_url("http://user-display-query.test");
    let next_id = AtomicUsize::new(1);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |_| {
            Ok(Some(next_id.fetch_add(1, Ordering::SeqCst).to_string()))
        })));
    for (name, physical, field_type) in [
        ("label", "stored_label", UserFieldType::String),
        ("rank", "stored_rank", UserFieldType::Number),
        ("highlighted", "stored_highlighted", UserFieldType::Boolean),
    ] {
        let _ = config.user.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_type,
                field_name: Some(physical.into()),
                required: Some(false),
                transform: (name == "label").then(|| FieldTransforms {
                    input: Some(label_transform(trace, "input", "in")),
                    output: Some(label_transform(trace, "output", "out")),
                }),
                ..Default::default()
            },
        );
    }
    config
}

fn queries() -> Vec<(&'static str, ListUsersParams)> {
    [
        ("logical-label", "label", json!("alpha:in"), "eq"),
        ("physical-label", "stored_label", json!("alpha:in"), "eq"),
        ("pre-transform-label", "label", json!("alpha"), "eq"),
        ("numeric-string", "rank", json!("12"), "eq"),
        ("numeric-string-in", "stored_rank", json!(["3", "20"]), "in"),
        ("boolean-string", "highlighted", json!("true"), "eq"),
        ("paginated-total", "highlighted", json!("true"), "eq"),
    ]
    .into_iter()
    .map(|(name, field, value, operator)| {
        let paged = name == "paginated-total";
        (
            name,
            ListUsersParams {
                limit: Some(if paged { 1.0 } else { 10.0 }),
                offset: Some(if paged { 1.0 } else { 0.0 }),
                sort_by: Some(
                    if name == "numeric-string-in" {
                        "stored_rank"
                    } else {
                        "rank"
                    }
                    .into(),
                ),
                sort_direction: Some("asc".into()),
                filter_field: Some(field.into()),
                filter_value: Some(value),
                filter_operator: Some(operator.into()),
                ..Default::default()
            },
        )
    })
    .collect()
}

async fn observe<S: AuthSchema>(
    backend: &str,
    store: &impl UserStore<S>,
    trace: &Trace,
) -> AuthResult<Value> {
    let timestamp = "2030-01-01T00:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|error| AuthError::internal(error.to_string()))?;
    for (label, name, rank, highlighted) in [
        ("alpha", "Display Alpha", 20, true),
        ("beta", "Display Beta", 3, false),
        ("gamma", "Display Gamma", 12, true),
    ] {
        let _ = store
            .create_user(CreateUser {
                name: Some(name.into()).into(),
                email: Some(format!("{label}@user-display-query.test")),
                email_verified: Some(false),
                created_at: Some(timestamp),
                updated_at: Some(timestamp),
                additional_fields: Map::from_iter([
                    ("label".into(), json!(label)),
                    ("rank".into(), json!(rank)),
                    ("highlighted".into(), json!(highlighted)),
                ]),
                ..Default::default()
            })
            .await?;
    }
    trace
        .lock()
        .map_err(|_| AuthError::internal("Display query trace lock poisoned"))?
        .clear();
    let mut observations = Vec::new();
    for (name, params) in queries() {
        let (users, total) = store.list_users(params).await?;
        let events = std::mem::take(
            &mut *trace
                .lock()
                .map_err(|_| AuthError::internal("Display query trace lock poisoned"))?,
        );
        let users = users
            .into_iter()
            .map(|user| user.additional_fields)
            .collect::<Vec<_>>();
        observations.push(json!({
            "name":name,
            "events":events,
            "result":{"users":users, "total":total},
        }));
    }
    Ok(json!({"backend":backend, "queries":observations}))
}

#[expect(unreachable_pub, reason = "SeaORM derives require public model items")]
mod user {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[sea_orm(table_name = "display_query_users")]
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
        pub stored_highlighted: Option<bool>,
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
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/user-display-query-1.7.6.json"))?;
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
    assert_eq!(
        json!({"version":"1.7.6", "backends":[memory, sqlite]}),
        expected
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "Setup errors and complete ordinary query differences must fail this contract"
)]
async fn declared_user_display_queries_match_pinned_memory_and_sqlite() {
    contract()
        .await
        .expect("User display query contract passes");
}
