#![cfg(feature = "seaorm2")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract asserts complete native values, callback order, identity, and durable rows."
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthInitContext, AuthRecordFields, AuthResult, AuthSchema, FieldDate,
    FieldMap, FieldValue,
    store::{JoinValue, RuntimeStore, schema::EntityRole},
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Schema, Statement},
    store::entities,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[path = "sql_relation_property_tests/models.rs"]
mod models;

const DATE: &str = "2030-01-01T00:00:00.000Z";
const CHANGED: &str = "2030-01-01T00:00:01.000Z";
const COLLISION: &str = "stored-parent-property";
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Events = Arc<Mutex<Vec<(&'static str, FieldValue)>>>;

#[derive(Clone, Copy, Debug)]
enum Target {
    Account,
    User,
    Session,
}

impl Target {
    fn many(self) -> bool {
        matches!(self, Self::User)
    }
    fn parent(self) -> &'static str {
        match self {
            Self::Account => "linked_account",
            Self::User => "linked_user",
            Self::Session => "session",
        }
    }
    fn child(self) -> &'static str {
        if self.many() {
            "linked_account"
        } else {
            "linked_user"
        }
    }
    fn value_field(self) -> &'static str {
        if self.many() { "accessToken" } else { "name" }
    }
    fn fields(self, config: &mut AuthConfig) -> &mut indexmap::IndexMap<String, UserFieldConfig> {
        match self {
            Self::Account => &mut config.account.additional_fields,
            Self::User => config.user.fields_mut(),
            Self::Session => config.session.fields_mut(),
        }
    }
}

fn user(id: &str, name: &str) -> Value {
    json!({"id":id,"name":name,"email":format!("{id}@sql-relation-property.test"),"emailVerified":1,"image":null,"createdAt":DATE,"updatedAt":DATE})
}

fn account(id: &str, token: &str, owner: &str) -> Value {
    json!({"id":id,"accountId":id,"providerId":"provider","userId":owner,"accessToken":token,
        "refreshToken":"refresh","idToken":"id-token","accessTokenExpiresAt":DATE,
        "refreshTokenExpiresAt":DATE,"scope":"read","password":"password","createdAt":DATE,"updatedAt":DATE})
}

fn session() -> Value {
    json!({"id":"parent","token":"existing-token","userId":"child","expiresAt":"2100-01-01T00:00:00.000Z",
        "ipAddress":"127.0.0.1","userAgent":"native-sql-contract","createdAt":DATE,"updatedAt":DATE})
}

fn native(value: &Value) -> AuthResult<FieldValue> {
    FieldValue::from_json(value.clone())
}

fn projected(value: &Value) -> TestResult<FieldMap> {
    let mut fields = native(value)?
        .as_object()
        .ok_or("Expected row object")?
        .snapshot_fields()?;
    for name in [
        "createdAt",
        "updatedAt",
        "expiresAt",
        "accessTokenExpiresAt",
        "refreshTokenExpiresAt",
    ] {
        if let Some(FieldValue::String(text)) = fields.get(name) {
            let value = FieldDate::from(text.parse::<chrono::DateTime<chrono::Utc>>()?);
            let _ = fields.insert(name.into(), value.into());
        }
    }
    if let Some(value) = fields.get("emailVerified") {
        let value = value.is_truthy();
        let _ = fields.insert("emailVerified".into(), value.into());
    }
    Ok(fields)
}

fn relation(many: bool, rows: Vec<FieldValue>) -> FieldValue {
    if many {
        rows.into()
    } else {
        rows.into_iter().next().unwrap_or(FieldValue::Null)
    }
}

fn observe<T: AuthRecordFields>(rows: JoinValue<T>) -> AuthResult<FieldValue> {
    match rows {
        JoinValue::One(row) => row
            .map(|row| row.field_values().map(FieldValue::from))
            .transpose()
            .map(|row| row.unwrap_or(FieldValue::Null)),
        JoinValue::Many(rows) => rows
            .into_iter()
            .map(|row| row.field_values().map(FieldValue::from))
            .collect::<AuthResult<Vec<_>>>()
            .map(Into::into),
    }
}

async fn insert(database: &DatabaseConnection, table: &str, value: &Value) -> TestResult {
    let fields = value.as_object().ok_or("Expected seed object")?;
    let columns = fields
        .keys()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(",");
    let placeholders = vec!["?"; fields.len()].join(",");
    let values = fields
        .values()
        .map(|value| match value {
            Value::String(value) => Ok(value.clone().into()),
            Value::Number(value) => value
                .as_i64()
                .map(Into::into)
                .ok_or("Expected integer seed"),
            Value::Null => Ok(Option::<String>::None.into()),
            _ => Err("Expected scalar seed"),
        })
        .collect::<Result<Vec<better_auth_seaorm::sea_orm::Value>, _>>()?;
    let _ = database
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            format!("INSERT INTO \"{table}\" ({columns}) VALUES ({placeholders})"),
            values,
        ))
        .await?;
    Ok(())
}

async fn storage(database: &DatabaseConnection, table: &str, fields: &Value) -> TestResult<Value> {
    let fields = fields.as_object().ok_or("Expected storage shape")?;
    let columns = fields
        .keys()
        .map(|name| format!("'{name}',\"{name}\""))
        .collect::<Vec<_>>()
        .join(",");
    database
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            format!("SELECT json_object({columns}) AS value FROM \"{table}\" ORDER BY id"),
        ))
        .await?
        .into_iter()
        .map(|row| Ok(serde_json::from_str(&row.try_get::<String>("", "value")?)?))
        .collect::<TestResult<Vec<Value>>>()
        .map(Value::Array)
}

fn policy(output: UserFieldTransform) -> UserFieldConfig {
    UserFieldConfig {
        transform: Some(FieldTransforms {
            output: Some(output),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn check(target: Target, joins: bool, reject: bool, missing: bool) -> TestResult {
    let database = Database::connect("sqlite::memory:").await?;
    let schema = Schema::new(DbBackend::Sqlite);
    for table in [
        schema.create_table_from_entity(models::user::Entity),
        schema.create_table_from_entity(models::account::Entity),
        schema.create_table_from_entity(models::session::Entity),
    ] {
        let _ = database
            .execute_raw(DbBackend::Sqlite.build(&table))
            .await?;
    }
    let mut parent = match target {
        Target::User => user("parent", "Parent"),
        Target::Account => account("parent", "Parent", "child"),
        Target::Session => session(),
    };
    parent[target.child()] = json!(COLLISION);
    let children = if missing {
        Vec::new()
    } else if target.many() {
        vec![
            account("child", "Before", "parent"),
            account("second", "Second", "parent"),
        ]
    } else {
        vec![user("child", "Before")]
    };
    insert(&database, target.parent(), &parent).await?;
    for child in &children {
        insert(&database, target.child(), child).await?;
    }
    let before_parent = storage(&database, target.parent(), &parent).await?;
    let child_shape = if target.many() {
        account("", "", "")
    } else {
        user("", "")
    };
    let before_children = storage(&database, target.child(), &child_shape).await?;
    let raw = if joins {
        relation(
            target.many(),
            children.iter().map(native).collect::<AuthResult<_>>()?,
        )
    } else {
        COLLISION.into()
    };
    let events = Events::default();
    let captured = Arc::new(Mutex::new(FieldValue::Undefined));
    let mut config =
        AuthConfig::new("native-sql-relation-property-contract-secret-at-least-32-characters");
    config.advanced.database.joins = Some(joins);
    let collision = {
        let (database, events, captured, raw) = (
            database.clone(),
            events.clone(),
            captured.clone(),
            raw.clone(),
        );
        UserFieldTransform::new_async(move |value| {
            let (database, events, captured, raw) = (
                database.clone(),
                events.clone(),
                captured.clone(),
                raw.clone(),
            );
            async move {
                assert_eq!(value, raw);
                *captured
                    .lock()
                    .map_err(|_| AuthError::internal("Capture lock poisoned"))? = value.clone();
                events
                    .lock()
                    .map_err(|_| AuthError::internal("Trace lock poisoned"))?
                    .push(("collision", value.clone()));
                if !missing {
                    let _ = database
                        .execute_raw(Statement::from_sql_and_values(
                            DbBackend::Sqlite,
                            format!(
                                "UPDATE \"{}\" SET \"{}\"=?, \"updatedAt\"=? WHERE id=?",
                                target.child(),
                                target.value_field()
                            ),
                            ["After".into(), CHANGED.into(), "child".into()],
                        ))
                        .await
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                    assert_eq!(
                        value, raw,
                        "A database write must not mutate the SQL query snapshot"
                    );
                    events
                        .lock()
                        .map_err(|_| AuthError::internal("Trace lock poisoned"))?
                        .push(("after-write", value.clone()));
                }
                if reject {
                    return Err(AuthError::internal("raw-relation-output-rejected"));
                }
                Ok(value)
            }
        })
    };
    let mirror = {
        let (events, captured, raw) = (events.clone(), captured.clone(), raw.clone());
        UserFieldTransform::new(move |value| {
            assert_eq!(value, raw);
            assert!(
                value.strict_equals(
                    &*captured
                        .lock()
                        .map_err(|_| AuthError::internal("Capture lock poisoned"))?
                )
            );
            events
                .lock()
                .map_err(|_| AuthError::internal("Trace lock poisoned"))?
                .push(("mirror", value.clone()));
            Ok(value)
        })
    };
    let fields = target.fields(&mut config);
    let _ = fields.insert(target.child().into(), policy(collision));
    let _ = fields.insert(
        "relationMirror".into(),
        UserFieldConfig {
            field_name: Some(target.child().into()),
            ..policy(mirror)
        },
    );
    let child_policy = {
        let events = events.clone();
        policy(UserFieldTransform::new(move |value| {
            events
                .lock()
                .map_err(|_| AuthError::internal("Trace lock poisoned"))?
                .push(("child", value.clone()));
            Ok(format!(
                "visible:{}",
                value
                    .as_str()
                    .ok_or_else(|| AuthError::internal("Expected child text"))?
            )
            .into())
        }))
    };
    let fields = if target.many() {
        &mut config.account.additional_fields
    } else {
        config.user.fields_mut()
    };
    let _ = fields.insert(target.value_field().into(), child_policy);
    let config = Arc::new(config);
    let raw_store = Arc::new(SeaOrmStore::<models::Core>::new(
        (*config).clone(),
        database.clone(),
    ));
    let mut init = AuthInitContext::new(config.clone(), raw_store.clone());
    init.register_model_schema(EntityRole::User, Some("linked_user"), UserConfig::default())?;
    init.register_model_schema(
        EntityRole::Account,
        Some("linked_account"),
        UserConfig::default(),
    )?;
    let reader = raw_store.with_runtime(config, Vec::new(), init.into_parts().plugin_fields)?;
    let result: TestResult<(FieldMap, FieldValue)> = async {
        match target {
            Target::Account => {
                let row = reader
                    .get_account_owner("provider", "parent")
                    .await?
                    .ok_or("Missing Account parent")?;
                Ok((row.account.field_values()?, observe(row.user)?))
            }
            Target::User => {
                let row = reader
                    .get_user_with_accounts("parent@sql-relation-property.test")
                    .await?
                    .ok_or("Missing User parent")?;
                Ok((row.user.field_values()?, observe(row.accounts)?))
            }
            Target::Session => {
                let (_, row) = reader
                    .get_session_snapshot("existing-token")
                    .await?
                    .ok_or("Missing Session parent")?;
                let row = row.ok_or("Missing Session relation")?;
                Ok((FieldMap::from(row.session), observe(row.user)?))
            }
        }
    }
    .await;
    let mut expected_events = vec![("collision", raw.clone())];
    if !missing {
        expected_events.push(("after-write", raw.clone()));
    }
    if reject {
        assert!(
            result.is_err_and(|error| error.to_string().contains("raw-relation-output-rejected"))
        );
    } else {
        let (output, joined) = result?;
        let mut expected = projected(&parent)?;
        let _ = expected.insert(target.child().into(), raw.clone());
        let _ = expected.insert("relationMirror".into(), raw.clone());
        assert_eq!(output, expected);
        assert!(
            output
                .get("relationMirror")
                .ok_or("Missing mirror")?
                .strict_equals(&*captured.lock().map_err(|_| "Capture lock poisoned")?)
        );
        expected_events.push(("mirror", raw.clone()));
        let mut projected_children = Vec::new();
        for (index, child) in children.iter().enumerate() {
            let mut child = child.clone();
            if !joins && index == 0 {
                child[target.value_field()] = json!("After");
                child["updatedAt"] = json!(CHANGED);
            }
            let text = child[target.value_field()]
                .as_str()
                .ok_or("Expected child value")?;
            expected_events.push(("child", text.into()));
            child[target.value_field()] = json!(format!("visible:{text}"));
            projected_children.push(FieldValue::from(projected(&child)?));
        }
        assert_eq!(joined, relation(target.many(), projected_children));
    }
    assert_eq!(
        *events.lock().map_err(|_| "Trace lock poisoned")?,
        expected_events
    );
    assert_eq!(
        storage(&database, target.parent(), &parent).await?,
        before_parent
    );
    let mut after_children = before_children;
    if !missing {
        after_children[0][target.value_field()] = json!("After");
        after_children[0]["updatedAt"] = json!(CHANGED);
    }
    assert_eq!(
        storage(&database, target.child(), &child_shape).await?,
        after_children
    );
    Ok(())
}

#[tokio::test]
async fn sql_raw_relation_properties_match_upstream_snapshots() -> TestResult {
    for target in [Target::Account, Target::User, Target::Session] {
        for joins in [false, true] {
            for reject in [false, true] {
                check(target, joins, reject, false).await?;
            }
        }
        check(target, true, false, true).await?;
    }
    Ok(())
}
