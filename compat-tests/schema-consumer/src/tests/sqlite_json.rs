use std::sync::{Arc, Mutex};

use better_auth::{
    __private_core::store::OrganizationStore,
    AuthConfig, AuthResult, FieldMap, FieldValue,
    config::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
    plugins::organization::OrganizationConfig,
    prelude::{CreateOrganization, Organization, UpdateOrganization},
    seaorm::{Database, DatabaseConnection, SeaOrmStore, sea_orm::EntityTrait},
};
use serde_json::{Map, Value, json};

mod generated {
    include!(env!("BETTER_AUTH_SQLITE_JSON_SCHEMA"));
}

type Store = SeaOrmStore<generated::AppAuthSchema, generated::AppOrganizationSchema>;
type Events = Arc<Mutex<Vec<Value>>>;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn kind(value: &FieldValue) -> &'static str {
    match value {
        FieldValue::Undefined => "undefined",
        FieldValue::Null => "null",
        FieldValue::Bool(_) => "boolean",
        FieldValue::Number(_) => "number",
        FieldValue::String(_) | FieldValue::Utf16String(_) => "string",
        FieldValue::Array(_) => "array",
        FieldValue::Object(_) | FieldValue::Date(_) => "object",
        FieldValue::Function(_) => "function",
    }
}

fn present(value: Option<&FieldValue>) -> AuthResult<Map<String, Value>> {
    let value = value.map(FieldValue::json).transpose()?.flatten();
    let mut result = Map::from_iter([("present".into(), json!(value.is_some()))]);
    if let Some(value) = value {
        let _ = result.insert("value".into(), value);
    }
    Ok(result)
}

fn policy(field: &'static str, events: &Events) -> UserFieldConfig {
    let callback = |phase: &'static str| {
        let events = events.clone();
        UserFieldTransform::new(move |value| {
            let mut event = present(Some(&value))?;
            event.extend([
                ("phase".into(), json!(phase)),
                ("field".into(), json!(field)),
                ("kind".into(), json!(kind(&value))),
            ]);
            events
                .lock()
                .expect("display callback trace lock")
                .push(Value::Object(event));
            Ok(value)
        })
    };
    UserFieldConfig {
        field_type: UserFieldType::Json,
        field_name: Some(if field == "requiredSettings" {
            "stored_required_settings".into()
        } else {
            "stored_settings".into()
        }),
        required: Some(field == "requiredSettings"),
        default_value: (field == "requiredSettings")
            .then(|| FieldMap::from([("theme".into(), "default".into())]).into()),
        transform: Some(FieldTransforms {
            input: Some(callback("input")),
            output: Some(callback("output")),
        }),
        ..Default::default()
    }
}

async fn observe(
    row: &Organization,
    id: &str,
    database: &DatabaseConnection,
    events: &Events,
) -> Result<Value> {
    let trace = std::mem::take(&mut *events.lock().expect("display callback trace lock"));
    let result: Map<String, Value> = ["requiredSettings", "settings"]
        .into_iter()
        .map(|field| {
            let value = row.additional_fields.get(field);
            let mut display = present(value)?;
            let _ = display.insert(
                "own".into(),
                json!(row.additional_fields.contains_key(field)),
            );
            Ok((field.into(), Value::Object(display)))
        })
        .collect::<AuthResult<_>>()?;
    let stored = generated::organization::Entity::find_by_id(id)
        .one(database)
        .await?
        .expect("the physical display row exists");
    Ok(json!({
        "events": trace,
        "result": result,
        "storedPhysical": {
            "stored_required_settings": stored.required_settings,
            "stored_settings": stored.settings,
        },
    }))
}

async fn read(
    store: &Store,
    id: &str,
    database: &DatabaseConnection,
    events: &Events,
) -> Result<Value> {
    let row = store
        .get_organization_by_id(id)
        .await?
        .expect("the adapter finds the created display row");
    observe(&row, id, database, events).await
}

#[tokio::test]
async fn generated_sqlite_json_fields_preserve_scalar_bindings_and_text() -> Result<()> {
    let database = Database::connect("sqlite::memory:").await?;
    generated::create_auth_tables(&database).await?;
    let events: Events = Arc::default();
    let mut organization = OrganizationConfig::default();
    organization.schema.organization.additional_fields = Some(
        ["requiredSettings", "settings"]
            .into_iter()
            .map(|field| (field.into(), policy(field, &events)))
            .collect(),
    );
    let store = SeaOrmStore::<generated::AppAuthSchema>::new(
        AuthConfig::new("ordinary-sqlite-json-generation-secret-at-least-32-characters")
            .base_url("http://sqlite-json-generation.test"),
        database.clone(),
    )
    .with_organization_schema::<generated::AppOrganizationSchema>();
    store.configure_organization_fields(organization.schema)?;
    let mut cases = Vec::new();
    let mut object_id = None;
    for (name, settings) in [
        ("omitted", None),
        ("null", Some(Value::Null)),
        ("object", Some(json!({"theme": "light", "enabled": true}))),
        ("array", Some(json!(["display", 12]))),
        ("encoded-string", Some(json!("\"display\""))),
        ("invalid-text", Some(json!("not-json"))),
        (
            "whitespace-object",
            Some(json!(" { \"theme\": \"spaced\" } ")),
        ),
        ("integer", Some(json!(12))),
        ("fractional", Some(json!(12.5))),
        ("false", Some(json!(false))),
        ("true", Some(json!(true))),
    ] {
        let mut input = CreateOrganization::new(
            format!("JSON Generation {name}"),
            format!("json-generation-{name}"),
        );
        if let Some(settings) = settings {
            let _ = input
                .additional_fields
                .insert("settings".into(), FieldValue::from_json(settings)?);
        }
        let row = store.create_organization(input).await?;
        let id = row.id.typed()?.clone();
        if name == "object" {
            object_id = Some(id.clone());
        }
        cases.push(json!({
            "name": name,
            "create": observe(&row, &id, &database, &events).await?,
            "read": read(&store, &id, &database, &events).await?,
        }));
    }
    let object_id = object_id.expect("the object case supplies the display-update row");
    let mut updates = Vec::new();
    for (name, field, value) in [
        ("null", "settings", Value::Null),
        ("invalid-text", "settings", json!("not-json")),
        ("omitted", "requiredSettings", json!({"theme": "default"})),
    ] {
        let row = store
            .update_organization(
                &object_id,
                UpdateOrganization {
                    additional_fields: FieldMap::from([(
                        field.into(),
                        FieldValue::from_json(value)?,
                    )]),
                    ..Default::default()
                },
            )
            .await?;
        updates.push(json!({
            "name": name,
            "update": observe(&row, &object_id, &database, &events).await?,
            "read": read(&store, &object_id, &database, &events).await?,
        }));
    }
    let expected: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/sqlite-json-generation-1.7.6.json"
    ))?;
    assert_eq!(
        json!({"version": "1.7.6", "backend": "sqlite", "cases": cases, "updates": updates}),
        expected
    );
    database.close().await?;
    Ok(())
}
