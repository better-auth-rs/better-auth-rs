#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, CreateUser, FieldMap, FieldValue,
    ListUsersParams, UserView,
    id::{IdGeneration, IdGenerator},
    store::UserStore,
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

fn observed(value: Option<&FieldValue>) -> AuthResult<Value> {
    Ok(match value.map(FieldValue::json).transpose()?.flatten() {
        None => json!({"defined":false}),
        Some(value) => json!({"defined":true,"value":value}),
    })
}

fn display(user: UserView) -> AuthResult<Value> {
    Ok(Value::Object(
        ["marker", "label", "note"]
            .into_iter()
            .map(|name| {
                let value = user.additional_fields.get(name);
                Ok((
                    name.into(),
                    json!({"own":value.is_some(),"value":observed(value)?}),
                ))
            })
            .collect::<AuthResult<Map<_, _>>>()?,
    ))
}

fn take_events(trace: &Trace) -> AuthResult<Vec<Value>> {
    Ok(std::mem::take(&mut *trace.lock().map_err(|_| {
        AuthError::internal("SQL String output trace lock poisoned")
    })?))
}

fn config(trace: Option<&Trace>) -> AuthConfig {
    let mut config =
        AuthConfig::new("ordinary-sql-user-string-output-secret-at-least-32-characters")
            .base_url("http://sql-user-string-output.test");
    let next_id = AtomicUsize::new(1);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |_| {
            Ok(Some(next_id.fetch_add(1, Ordering::SeqCst).to_string()))
        })));
    for (name, physical) in [
        ("marker", "stored_marker"),
        ("label", "stored_label"),
        ("note", "stored_note"),
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
                                AuthError::internal("SQL String output trace lock poisoned")
                            })?
                            .push(json!(["output", name, observed(Some(&value))?]));
                        Ok(value)
                    })),
                }
            })
        };
        let _ = config.user.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_type: UserFieldType::String,
                field_name: Some(physical.into()),
                required: Some(false),
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

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[sea_orm(table_name = "sql_string_output_users")]
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
        #[serde(skip_serializing_if = "Option::is_none")]
        pub stored_label: Option<String>,
        #[serde(skip_serializing_if = "String::is_empty")]
        pub stored_note: String,
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
        serde_json::from_str(include_str!("fixtures/sql-user-string-output-1.7.6.json"))?;
    let db = Database::connect("sqlite::memory:").await?;
    let _ = db
        .execute(&Schema::new(db.get_database_backend()).create_table_from_entity(user::Entity))
        .await?;
    let writer = SeaOrmStore::<Tables>::new(config(None), db.clone());
    let timestamp = "2030-01-01T00:00:00Z".parse::<chrono::DateTime<chrono::Utc>>()?;
    let mut first_id = None;
    for (marker, label, note, name) in [
        ("a", Value::Null, "", "String Output A"),
        ("b", json!("blue"), "visible", "String Output B"),
    ] {
        let created = writer
            .create_user(CreateUser {
                name: Some(name.into()).into(),
                email: Some(format!("{marker}@sql-user-string-output.test")),
                email_verified: Some(false),
                created_at: Some(timestamp.into()),
                updated_at: Some(timestamp.into()),
                additional_fields: FieldMap::from_json(Map::from_iter([
                    ("marker".into(), json!(marker)),
                    ("label".into(), label),
                    ("note".into(), json!(note)),
                ]))?,
                ..Default::default()
            })
            .await?;
        if first_id.is_none() {
            first_id = Some(created.id.typed()?.clone());
        }
    }
    let first_id = first_id
        .ok_or_else(|| AuthError::internal("The writer returns the first stored user ID"))?;
    let trace = Trace::default();
    let reader = SeaOrmStore::<Tables>::new(config(Some(&trace)), db);
    let point = reader
        .get_user_by_id(&first_id)
        .await?
        .ok_or_else(|| AuthError::internal("The reader finds the first stored row"))?;
    let point = json!({"events":take_events(&trace)?,"result":display(point)?});
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
            "point":point,
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
    reason = "Setup errors and complete SQL String projection differences must fail this contract"
)]
async fn sqlite_user_output_uses_columns_when_serde_omits_null_and_empty_strings() {
    contract()
        .await
        .expect("SQL User String output matches the pinned adapter");
}
