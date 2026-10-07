#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, CreateUser, FieldMap, FieldValue,
    ListUsersParams, UserView,
    id::{IdGeneration, IdGenerator},
    store::UserStore,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};
use better_auth_seaorm::{
    AuthEntity, SeaOrmStore, SqlNumber,
    sea_orm::{self, ConnectionTrait, Database, Schema, entity::prelude::*},
    store::entities,
};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

type Trace = Arc<Mutex<Vec<Value>>>;

fn event(field: &str, value: &FieldValue) -> AuthResult<Value> {
    let kind = match value {
        FieldValue::Undefined => "undefined",
        FieldValue::Null => "null",
        FieldValue::Bool(_) => "boolean",
        FieldValue::Number(_) => "number",
        FieldValue::String(_) | FieldValue::Utf16String(_) => "string",
        FieldValue::Date(_) => "date",
        FieldValue::Array(_) => "array",
        FieldValue::Object(_) => "object",
    };
    Ok(
        json!({"field":field,"present":!value.is_undefined(),"kind":kind,"value":value.json()?.unwrap_or(Value::Null)}),
    )
}

fn display(user: UserView) -> AuthResult<Value> {
    let mut output = Map::new();
    for name in [
        "marker",
        "rank",
        "highlighted",
        "displayAt",
        "settings",
        "tags",
        "scores",
    ] {
        let value = user.additional_fields.get(name);
        let _ = output.insert(
            name.into(),
            json!({
                "own":value.is_some(),
                "present":value.is_some_and(|value| !value.is_undefined()),
                "value":value.map(FieldValue::json).transpose()?.flatten().unwrap_or(Value::Null),
            }),
        );
    }
    Ok(Value::Object(output))
}

fn take_events(trace: &Trace) -> AuthResult<Vec<Value>> {
    Ok(std::mem::take(&mut *trace.lock().map_err(|_| {
        AuthError::internal("SQL extra output trace lock poisoned")
    })?))
}

fn config(trace: Option<&Trace>) -> AuthConfig {
    let mut config =
        AuthConfig::new("ordinary-sql-user-extra-output-secret-at-least-32-characters")
            .base_url("http://sql-user-extra-output.test");
    let next_id = AtomicUsize::new(1);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |_| {
            Ok(Some(next_id.fetch_add(1, Ordering::SeqCst).to_string()))
        })));
    for (name, field_type) in [
        ("marker", UserFieldType::String),
        ("rank", UserFieldType::Number),
        ("highlighted", UserFieldType::Boolean),
        ("displayAt", UserFieldType::Date),
        ("settings", UserFieldType::Json),
        ("tags", UserFieldType::StringArray),
        ("scores", UserFieldType::NumberArray),
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
                                AuthError::internal("SQL extra output trace lock poisoned")
                            })?
                            .push(event(name, &value)?);
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

#[expect(unreachable_pub, reason = "SeaORM derives require public model items")]
mod user {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, FromJsonQueryResult,
    )]
    #[serde(transparent)]
    pub struct StringArray(pub Vec<String>);

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, FromJsonQueryResult,
    )]
    #[serde(transparent)]
    pub struct NumberArray(pub Vec<f64>);

    fn omit_false(value: &Option<bool>) -> bool {
        value.is_none_or(|value| !value)
    }

    fn omit_empty_object(value: &Option<Json>) -> bool {
        value
            .as_ref()
            .is_none_or(|value| value.as_object().is_some_and(Map::is_empty))
    }

    fn omit_empty_tags(value: &Option<StringArray>) -> bool {
        value.as_ref().is_none_or(|value| value.0.is_empty())
    }

    fn omit_empty_scores(value: &Option<NumberArray>) -> bool {
        value.as_ref().is_none_or(|value| value.0.is_empty())
    }

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[sea_orm(table_name = "sql_extra_output_users")]
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
        #[serde(skip_serializing_if = "Option::is_none")]
        pub stored_rank: Option<SqlNumber>,
        #[serde(skip_serializing_if = "omit_false")]
        pub stored_highlighted: Option<bool>,
        #[serde(rename = "stored_displayAt", skip_serializing_if = "Option::is_none")]
        #[sea_orm(column_name = "stored_displayAt")]
        pub stored_display_at: Option<DateTimeUtc>,
        #[serde(skip_serializing_if = "omit_empty_object")]
        pub stored_settings: Option<Json>,
        #[serde(skip_serializing_if = "omit_empty_tags")]
        pub stored_tags: Option<StringArray>,
        #[serde(skip_serializing_if = "omit_empty_scores")]
        pub stored_scores: Option<NumberArray>,
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
        serde_json::from_str(include_str!("fixtures/sql-user-extra-output-1.7.6.json"))?;
    let db = Database::connect("sqlite::memory:").await?;
    let _ = db
        .execute(&Schema::new(db.get_database_backend()).create_table_from_entity(user::Entity))
        .await?;
    let writer = SeaOrmStore::<Tables>::new(config(None), db.clone());
    let timestamp = "2030-01-01T00:00:00Z".parse::<chrono::DateTime<chrono::Utc>>()?;
    let mut ids = BTreeMap::new();
    for (marker, name, mut additional_fields) in [
        ("a", "Extra Output A", FieldMap::new()),
        (
            "b",
            "Extra Output B",
            FieldMap::from([
                ("rank".into(), FieldValue::from(0.5)),
                ("highlighted".into(), FieldValue::from(false)),
                (
                    "displayAt".into(),
                    FieldValue::from(
                        "2030-01-02T03:04:05.006Z".parse::<chrono::DateTime<chrono::Utc>>()?,
                    ),
                ),
                ("settings".into(), FieldValue::from(FieldMap::new())),
                ("tags".into(), FieldValue::from(Vec::new())),
                ("scores".into(), FieldValue::from(Vec::new())),
            ]),
        ),
        (
            "c",
            "Extra Output C",
            FieldMap::from([
                ("rank".into(), FieldValue::from(12.5)),
                ("highlighted".into(), FieldValue::from(true)),
                (
                    "displayAt".into(),
                    FieldValue::from(
                        "2031-02-03T04:05:06.007Z".parse::<chrono::DateTime<chrono::Utc>>()?,
                    ),
                ),
                (
                    "settings".into(),
                    FieldValue::from(FieldMap::from([("theme".into(), FieldValue::from("blue"))])),
                ),
                (
                    "tags".into(),
                    FieldValue::from(vec![FieldValue::from("blue"), FieldValue::from("green")]),
                ),
                (
                    "scores".into(),
                    FieldValue::from(vec![FieldValue::from(1.25), FieldValue::from(2.5)]),
                ),
            ]),
        ),
        ("d", "Extra Output D", FieldMap::new()),
    ] {
        let _ = additional_fields.insert("marker".into(), FieldValue::from(marker));
        let created = writer
            .create_user(CreateUser {
                name: Some(name.into()).into(),
                email: Some(format!("{marker}@sql-user-extra-output.test")),
                email_verified: Some(false),
                created_at: Some(timestamp.into()),
                updated_at: Some(timestamp.into()),
                additional_fields,
                ..Default::default()
            })
            .await?;
        let _ = ids.insert(marker, created.id.typed()?.clone());
    }
    let literal_null_id = ids
        .get("d")
        .ok_or_else(|| AuthError::internal("The writer returns the JSON literal-null row ID"))?;
    // A typed JSON null isolates output from explicit-null create input binding.
    let changed = user::Entity::update_many()
        .col_expr(user::Column::StoredSettings, Expr::value(Some(Value::Null)))
        .filter(user::Column::Id.eq(literal_null_id.as_str()))
        .exec(&db)
        .await?;
    assert_eq!(
        changed.rows_affected, 1,
        "The fixture updates one display row"
    );

    let trace = Trace::default();
    let reader = SeaOrmStore::<Tables>::new(config(Some(&trace)), db);
    let mut points = Vec::new();
    for (name, marker) in [("sql-null", "a"), ("json-null", "d")] {
        let id = ids.get(marker).ok_or_else(|| {
            AuthError::internal("The writer returns the selected point-read row ID")
        })?;
        let row = reader
            .get_user_by_id(id)
            .await?
            .ok_or_else(|| AuthError::internal("The reader finds the selected display row"))?;
        points.push(json!({"name":name,"events":take_events(&trace)?,"result":display(row)?}));
    }
    let (rows, total) = reader
        .list_users(ListUsersParams {
            limit: Some(10.0),
            offset: Some(0.0),
            sort_by: Some("marker".into()),
            sort_direction: Some("asc".into()),
            ..Default::default()
        })
        .await?;
    assert_eq!(
        json!({
            "version":"1.7.6",
            "backend":"sqlite",
            "points":points,
            "batch":{
                "events":take_events(&trace)?,
                "result":{"users":rows.into_iter().map(display).collect::<AuthResult<Vec<_>>>()?,"total":total},
            },
        }),
        expected,
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "Setup errors and complete SQLite display projection differences must fail this contract"
)]
async fn sqlite_user_output_preserves_column_presence_and_decodes_after_callbacks() {
    contract()
        .await
        .expect("SQLite User extra output matches the pinned adapter");
}
