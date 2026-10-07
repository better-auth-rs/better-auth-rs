#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateUser, ListUsersParams,
    UserView,
    id::{IdGeneration, IdGenerator},
    plugin_runtime::ModelFields,
    store::{EphemeralStore, StatelessSchema, UserStore},
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::{
    AuthEntity, SeaOrmStore,
    sea_orm::{
        self, ConnectionTrait, Database, DatabaseConnection, QueryOrder, Schema, entity::prelude::*,
    },
    store::entities,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

type Trace = Arc<Mutex<Vec<Value>>>;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Slot {
    Implicit,
    BeforeLabel,
    AfterLabel,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Operation {
    Generated,
    GeneratorFailure,
    FieldFailure,
    SuppliedId,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Case {
    backend: String,
    slot: Slot,
    operation: Operation,
    before: Vec<Value>,
    events: Vec<Value>,
    result: Value,
    after: Vec<Value>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Capture {
    version: String,
    cases: Vec<Case>,
}

fn record(trace: &Trace, event: Value) -> AuthResult<()> {
    trace
        .lock()
        .map_err(|_| AuthError::internal("User ID trace lock poisoned"))?
        .push(event);
    Ok(())
}

fn take_events(trace: &Trace) -> AuthResult<Vec<Value>> {
    Ok(std::mem::take(&mut *trace.lock().map_err(|_| {
        AuthError::internal("User ID trace lock poisoned")
    })?))
}

fn field(name: &'static str, operation: Operation, trace: &Trace) -> UserFieldConfig {
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                record(
                    &input_trace,
                    json!(["input", format!("user.{name}"), value]),
                )?;
                if operation == Operation::FieldFailure && name == "label" {
                    return Err(AuthError::internal("label-input-failure"));
                }
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                record(
                    &output_trace,
                    json!(["output", format!("user.{name}"), value]),
                )?;
                Ok(value)
            })),
        }),
        ..Default::default()
    }
}

fn config(slot: Slot, operation: Operation, trace: &Trace) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    let generator_trace = trace.clone();
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |context| {
            record(&generator_trace, json!(["generateId", context.model]))?;
            if operation == Operation::GeneratorFailure {
                return Err(AuthError::internal("generator-failure"));
            }
            Ok(Some("generated-owner".into()))
        })));
    let _ = config
        .user
        .fields_mut()
        .insert("name".into(), field("name", operation, trace));
    if slot == Slot::BeforeLabel {
        let _ = config
            .user
            .fields_mut()
            .insert("id".into(), field("id", operation, trace));
    }
    let _ = config
        .user
        .fields_mut()
        .insert("label".into(), field("label", operation, trace));
    if slot == Slot::AfterLabel {
        let _ = config
            .user
            .fields_mut()
            .insert("id".into(), field("id", operation, trace));
    }
    config
}

async fn view(user: &UserView, fields: &UserConfig) -> AuthResult<Value> {
    let user = UserView::with_fields(user, fields, &Default::default()).await?;
    Ok(Value::Object(Map::from(user)))
}

async fn create<S: AuthSchema>(
    store: &impl UserStore<S>,
    operation: Operation,
    fields: &UserConfig,
) -> AuthResult<Value> {
    let timestamp = "2030-01-02T03:04:05.000Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let result = store
        .create_user(CreateUser {
            id: (operation == Operation::SuppliedId).then(|| "supplied-owner".into()),
            name: Some("Owner".into()).into(),
            email: Some("owner@user-id-order.test".into()),
            email_verified: Some(true),
            image: Some("owner-image".into()).into(),
            created_at: Some(timestamp),
            updated_at: Some(timestamp),
            additional_fields: Map::from_iter([("label".into(), json!("Label"))]),
            ..Default::default()
        })
        .await;
    match result {
        Ok(user) => view(&user, fields).await,
        Err(error) => Ok(json!({"error": error.instrumentation_message()})),
    }
}

async fn memory_rows(
    store: &dyn AuthStore<StatelessSchema>,
    fields: &UserConfig,
) -> AuthResult<Vec<Value>> {
    let (users, _) = store.list_users(ListUsersParams::default()).await?;
    let mut rows = Vec::with_capacity(users.len());
    for user in users {
        rows.push(view(&user, fields).await?);
    }
    Ok(rows)
}

#[expect(unreachable_pub, reason = "SeaORM derives require public model items")]
mod user {
    use super::*;

    #[derive(Clone, Debug, Serialize, DeriveEntityModel, AuthEntity)]
    #[sea_orm(table_name = "user")]
    #[auth(role = "user")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        #[sea_orm(column_name = "emailVerified")]
        pub email_verified: bool,
        pub image: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
        pub label: Option<String>,
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

async fn sqlite_rows(db: &DatabaseConnection) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let rows = user::Entity::find()
        .order_by_asc(user::Column::Id)
        .all(db)
        .await?;
    rows.into_iter()
        .map(|row| {
            let Value::Object(mut fields) = serde_json::to_value(&row)? else {
                return Err(AuthError::internal("User model must serialize to an object").into());
            };
            let _ = fields.insert("emailVerified".into(), json!(i64::from(row.email_verified)));
            // Compare typed timestamp values; SQLite writer text is a separate contract.
            for (name, value) in [("createdAt", row.created_at), ("updatedAt", row.updated_at)] {
                let _ = fields.insert(
                    name.into(),
                    json!(value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
                );
            }
            Ok(Value::Object(fields))
        })
        .collect()
}

async fn contract() -> Result<(), Box<dyn std::error::Error>> {
    let expected: Capture =
        serde_json::from_str(include_str!("fixtures/user-id-generation-order-1.7.6.json"))?;
    let mut cases = Vec::new();
    for backend in ["memory", "sqlite"] {
        for slot in [Slot::Implicit, Slot::BeforeLabel, Slot::AfterLabel] {
            for operation in [
                Operation::Generated,
                Operation::GeneratorFailure,
                Operation::FieldFailure,
                Operation::SuppliedId,
            ] {
                let trace = Trace::default();
                let config = config(slot, operation, &trace);
                let mut observer_config = config.clone();
                for field in observer_config.user.fields_mut().values_mut() {
                    field.transform = None;
                }
                let (before, result, after) = if backend == "memory" {
                    let store = EphemeralStore::new(Arc::new(config));
                    // A separate runtime reads the persisted rows without invoking application callbacks.
                    let observer = store.with_runtime(
                        Arc::new(observer_config.clone()),
                        Vec::new(),
                        ModelFields::default(),
                    )?;
                    let before = memory_rows(observer.as_ref(), &observer_config.user).await?;
                    let result =
                        create::<StatelessSchema>(&store, operation, &observer_config.user).await?;
                    let after = memory_rows(observer.as_ref(), &observer_config.user).await?;
                    (before, result, after)
                } else {
                    let db = Database::connect("sqlite::memory:").await?;
                    let _ = db
                        .execute(
                            &Schema::new(db.get_database_backend())
                                .create_table_from_entity(user::Entity),
                        )
                        .await?;
                    let store = SeaOrmStore::<Tables>::new(config, db.clone());
                    let before = sqlite_rows(&db).await?;
                    let result = create(&store, operation, &observer_config.user).await?;
                    let after = sqlite_rows(&db).await?;
                    (before, result, after)
                };
                cases.push(Case {
                    backend: backend.into(),
                    slot,
                    operation,
                    before,
                    events: take_events(&trace)?,
                    result,
                    after,
                });
            }
        }
    }
    assert_eq!(cases.len(), 24);
    assert_eq!(
        Capture {
            version: "1.7.6".into(),
            cases
        },
        expected
    );
    Ok(())
}

#[tokio::test]
async fn user_id_generation_matches_pinned_memory_and_sqlite()
-> Result<(), Box<dyn std::error::Error>> {
    contract().await
}
