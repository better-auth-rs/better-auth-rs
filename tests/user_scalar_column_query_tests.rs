#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, CreateUser, FieldMap, FieldValue,
    ListUsersParams, UserView,
    id::{IdGeneration, IdGenerator},
    store::{EphemeralStore, RuntimeStore, StatelessSchema, UserStore},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};
use better_auth_seaorm::{
    AuthEntity, SeaOrmStore, SqlNumber,
    sea_orm::{self, ConnectionTrait, Database, Schema, entity::prelude::*},
    store::entities,
};
use serde_json::{Map, Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

type Trace = Arc<Mutex<Vec<Value>>>;

fn event(field: &str, value: Option<&Value>) -> Value {
    let kind = match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    };
    json!({"field":field,"present":value.is_some(),"kind":kind,"value":value})
}

fn display(user: UserView) -> AuthResult<Value> {
    let fields = ["marker", "highlighted", "rank"]
        .into_iter()
        .map(|name| {
            let value = user.additional_fields.get(name);
            Ok((
                name.into(),
                json!({"own":value.is_some(),"present":value.is_some(),"value":value.map(FieldValue::json).transpose()?.flatten()}),
            ))
        })
        .collect::<AuthResult<Map<_, _>>>()?;
    Ok(Value::Object(fields))
}

fn take_events(trace: &Trace) -> AuthResult<Vec<Value>> {
    Ok(std::mem::take(&mut *trace.lock().map_err(|_| {
        AuthError::internal("Scalar column query trace lock poisoned")
    })?))
}

fn config(trace: Option<&Trace>) -> AuthConfig {
    let mut config =
        AuthConfig::new("ordinary-user-scalar-column-query-secret-at-least-32-characters")
            .base_url("http://user-scalar-column-query.test");
    let next_id = AtomicUsize::new(1);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |_| {
            Ok(Some(next_id.fetch_add(1, Ordering::SeqCst).to_string()))
        })));
    for (name, field_type) in [
        ("marker", UserFieldType::String),
        ("highlighted", UserFieldType::Boolean),
        ("rank", UserFieldType::Number),
    ] {
        let transform = if name == "marker" {
            None
        } else {
            trace.map(|trace| {
                let trace = trace.clone();
                FieldTransforms {
                    input: None,
                    output: Some(UserFieldTransform::new(move |value| {
                        trace
                            .lock()
                            .map_err(|_| {
                                AuthError::internal("Scalar column query trace lock poisoned")
                            })?
                            .push(event(name, value.json()?.as_ref()));
                        Ok(value)
                    })),
                }
            })
        };
        let _ = config.user.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_type,
                field_name: Some(format!("stored_{name}")),
                required: Some(name == "marker"),
                transform,
                ..Default::default()
            },
        );
    }
    config
}

async fn seed<S: AuthSchema>(
    writer: &(impl UserStore<S> + ?Sized),
    explicit_null: bool,
) -> AuthResult<()> {
    let timestamp = "2030-01-01T00:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|error| AuthError::internal(error.to_string()))?;
    for (marker, name, values) in [
        (
            "false",
            "Scalar Query False",
            Some((json!(false), json!(0.5))),
        ),
        ("null", "Scalar Query Null", None),
        (
            "true",
            "Scalar Query True",
            Some((json!(true), json!(12.5))),
        ),
    ] {
        let mut additional_fields = Map::from_iter([("marker".into(), json!(marker))]);
        if let Some((highlighted, rank)) = values {
            let _ = additional_fields.insert("highlighted".into(), highlighted);
            let _ = additional_fields.insert("rank".into(), rank);
        } else if explicit_null {
            let _ = additional_fields.insert("highlighted".into(), Value::Null);
            let _ = additional_fields.insert("rank".into(), Value::Null);
        }
        let _ = writer
            .create_user(CreateUser {
                name: Some(name.into()).into(),
                email: Some(format!("{marker}@user-scalar-column-query.test")),
                email_verified: Some(false),
                created_at: Some(timestamp.into()),
                updated_at: Some(timestamp.into()),
                additional_fields: FieldMap::from_json(additional_fields)?,
                ..Default::default()
            })
            .await?;
    }
    Ok(())
}

fn queries(sqlite: bool) -> Vec<(&'static str, ListUsersParams)> {
    let base = ListUsersParams {
        limit: Some(10.0),
        offset: Some(0.0),
        sort_by: Some("marker".into()),
        sort_direction: Some("asc".into()),
        ..Default::default()
    };
    let filter = |field: &str, value: FieldValue, operator: &str| ListUsersParams {
        filter_field: Some(field.into()),
        filter_value: Some(value),
        filter_operator: Some(operator.into()),
        ..base.clone()
    };
    let mut queries = Vec::new();
    if sqlite {
        queries.extend([
            (
                "logical-boolean-false",
                filter("highlighted", false.into(), "eq"),
            ),
            (
                "physical-boolean-false",
                filter("stored_highlighted", "false".into(), "eq"),
            ),
            (
                "logical-boolean-sort",
                ListUsersParams {
                    sort_by: Some("highlighted".into()),
                    ..base.clone()
                },
            ),
            (
                "physical-boolean-sort-page",
                ListUsersParams {
                    sort_by: Some("stored_highlighted".into()),
                    sort_direction: Some("desc".into()),
                    limit: Some(2.0),
                    ..base.clone()
                },
            ),
        ]);
    }
    queries.extend([
        (
            "logical-boolean-eq-null",
            filter("highlighted", FieldValue::Null, "eq"),
        ),
        (
            "physical-boolean-ne-null",
            filter("stored_highlighted", FieldValue::Null, "ne"),
        ),
        (
            "logical-number-eq-null",
            filter("rank", FieldValue::Null, "eq"),
        ),
        (
            "physical-number-ne-null",
            filter("stored_rank", FieldValue::Null, "ne"),
        ),
    ]);
    queries
}

async fn observe<S: AuthSchema>(
    backend: &str,
    reader: &(impl UserStore<S> + ?Sized),
    trace: &Trace,
) -> AuthResult<Value> {
    let mut observations = Vec::new();
    for (name, params) in queries(backend == "sqlite") {
        let (users, total) = reader.list_users(params).await?;
        observations.push(json!({
            "name":name,
            "events":take_events(trace)?,
            "result":{"users":users.into_iter().map(display).collect::<AuthResult<Vec<_>>>()?,"total":total},
        }));
    }
    Ok(json!({"backend":backend,"queries":observations}))
}

#[expect(unreachable_pub, reason = "SeaORM derives require public model items")]
mod user {
    use super::*;

    fn omit_false(value: &Option<bool>) -> bool {
        value.is_none_or(|value| !value)
    }

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[sea_orm(table_name = "scalar_column_query_users")]
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
        pub stored_marker: String,
        #[serde(skip_serializing_if = "omit_false")]
        pub stored_highlighted: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub stored_rank: Option<SqlNumber>,
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
        serde_json::from_str(include_str!("fixtures/user-scalar-column-query-1.7.6.json"))?;
    let db = Database::connect("sqlite::memory:").await?;
    let _ = db
        .execute(&Schema::new(db.get_database_backend()).create_table_from_entity(user::Entity))
        .await?;
    let writer = SeaOrmStore::<Tables>::new(config(None), db.clone());
    seed(&writer, false).await?;
    let trace = Trace::default();
    let reader = SeaOrmStore::<Tables>::new(config(Some(&trace)), db);
    let sqlite = observe("sqlite", &reader, &trace).await?;

    let writer = EphemeralStore::new(config(None).into());
    seed::<StatelessSchema>(&writer, true).await?;
    let trace = Trace::default();
    let reader =
        writer.with_runtime(config(Some(&trace)).into(), Vec::new(), Default::default())?;
    let memory = observe::<StatelessSchema>("memory", reader.as_ref(), &trace).await?;
    assert_eq!(
        json!({"version":"1.7.6","backends":[sqlite,memory]}),
        expected,
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "Setup errors and complete ordinary scalar query differences must fail this contract"
)]
async fn scalar_user_queries_preserve_sql_columns_and_nullable_display_values() {
    contract()
        .await
        .expect("Scalar column query contract passes");
}
