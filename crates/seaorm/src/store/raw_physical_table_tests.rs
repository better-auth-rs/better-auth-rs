use super::*;
use crate::store::create_readback::ReadbackScope;
use sea_orm::{DatabaseConnection, Statement};
use std::sync::{Arc, Mutex, MutexGuard};

type Events = Arc<Mutex<Vec<serde_json::Value>>>;

fn locked(events: &Events) -> AuthResult<MutexGuard<'_, Vec<serde_json::Value>>> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Raw table callback lock is poisoned"))
}

fn callback(events: &Events, phase: &'static str) -> UserFieldTransform {
    let events = events.clone();
    UserFieldTransform::new(move |value| {
        locked(&events)?.push(serde_json::json!([phase, "name", value.json()?]));
        Ok(format!(
            "{}:{}",
            if phase == "input" {
                "stored"
            } else {
                "visible"
            },
            SchemaValue::<String>::from_field(value).display_string()?,
        )
        .into())
    })
}

async fn catalog(database: &DatabaseConnection) -> AuthResult<Vec<serde_json::Value>> {
    database
        .query_all_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT json_object('type', type, 'name', name, 'table', tbl_name, 'sql', sql) AS value FROM sqlite_schema ORDER BY type, name",
        ))
        .await
        .map_err(map_db_err)?
        .into_iter()
        .map(|row| {
            serde_json::from_str(&row.try_get::<String>("", "value").map_err(map_db_err)?)
                .map_err(|error| AuthError::internal(error.to_string()))
        })
        .collect()
}

async fn stored(database: &DatabaseConnection, table: &str) -> AuthResult<Vec<FieldMap>> {
    database
        .query_all_raw(Statement::from_string(
            database.get_database_backend(),
            format!("SELECT id, name FROM {table} ORDER BY id"),
        ))
        .await
        .map_err(map_db_err)?
        .into_iter()
        .map(|row| {
            Ok(FieldMap::from([
                (
                    "id".into(),
                    row.try_get::<String>("", "id").map_err(map_db_err)?.into(),
                ),
                (
                    "name".into(),
                    row.try_get::<String>("", "name")
                        .map_err(map_db_err)?
                        .into(),
                ),
            ]))
        })
        .collect()
}

async fn crud<M: SeaOrmPluginModel>(role: EntityRole, model: &str, table: &str) -> AuthResult<()> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    let _ = database
        .execute_unprepared(&format!(
            "CREATE TABLE {table} (id TEXT NOT NULL PRIMARY KEY, name TEXT)"
        ))
        .await
        .map_err(map_db_err)?;
    let schema = catalog(&database).await?;
    let mut store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("raw-physical-table-secret-at-least-thirty-two-characters"),
        database.clone(),
    );
    let events = Events::default();
    let mut model_fields = better_auth_core::plugin_runtime::ModelFields::default();
    model_fields.register_model_fields(
        role,
        UserConfig {
            additional_fields: Some(
                [(
                    "name".into(),
                    UserFieldConfig {
                        required: Some(false),
                        transform: Some(FieldTransforms {
                            input: Some(callback(&events, "input")),
                            output: Some(callback(&events, "output")),
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        },
    )?;
    store.model_fields = model_fields;
    store
        .model_fields
        .set_schema_configuration(&SchemaConfiguration {
            config: store.config.clone(),
            plugins: Vec::new(),
            metadata: Default::default(),
            secondary_storage: false,
            rate_limit: Default::default(),
        });
    let id = "mapping-row".into();
    for stage in [
        "create",
        "read",
        "list",
        "update",
        "read-updated",
        "delete",
        "missing",
    ] {
        let input = if matches!(stage, "create" | "read" | "list") {
            "source"
        } else {
            "next"
        };
        let actual = match stage {
            "create" => store
                .create_plugin_record::<M>(
                    &database,
                    ReadbackScope::Direct(&database),
                    role,
                    model,
                    [
                        ("id".into(), "mapping-row".into()),
                        ("name".into(), input.into()),
                    ]
                    .into(),
                )
                .await?
                .into_iter()
                .collect::<Vec<_>>(),
            "update" => store
                .update_plugin_record::<M>(
                    &database,
                    role,
                    &id,
                    [("name".into(), input.into())].into(),
                )
                .await?
                .into_iter()
                .collect(),
            "list" => store.list_plugin_records::<M>(&database, role).await?,
            "delete" => {
                store
                    .delete_plugin_record::<M>(&database, role, &id)
                    .await?;
                Vec::new()
            }
            _ => store
                .get_plugin_record::<M>(&database, role, &id)
                .await?
                .into_iter()
                .collect(),
        };
        let present = !matches!(stage, "delete" | "missing");
        let expected = if present {
            vec![FieldMap::from([
                ("name".into(), format!("visible:stored:{input}").into()),
                ("id".into(), "mapping-row".into()),
            ])]
        } else {
            Vec::new()
        };
        assert_eq!(actual, expected, "{model} {stage}");
        for record in actual {
            assert_eq!(
                record.keys().map(String::as_str).collect::<Vec<_>>(),
                ["name", "id"]
            );
        }
        let mut callbacks = Vec::new();
        if matches!(stage, "create" | "update") {
            callbacks.push(serde_json::json!(["input", "name", input]));
        }
        if present {
            callbacks.push(serde_json::json!([
                "output",
                "name",
                format!("stored:{input}")
            ]));
        }
        assert_eq!(*locked(&events)?, callbacks, "{model} {stage}");
        locked(&events)?.clear();
        let expected = if present {
            vec![FieldMap::from([
                ("id".into(), "mapping-row".into()),
                ("name".into(), format!("stored:{input}").into()),
            ])]
        } else {
            Vec::new()
        };
        assert_eq!(stored(&database, table).await?, expected, "{model} {stage}");
        assert_eq!(catalog(&database).await?, schema, "{model} {stage}");
    }
    Ok(())
}

#[tokio::test]
async fn api_key_and_passkey_raw_crud_accepts_sparse_physical_tables() -> AuthResult<()> {
    crud::<entities::api_key::Model>(EntityRole::ApiKey, "apikey", "api_keys").await?;
    crud::<entities::passkey::Model>(EntityRole::Passkey, "passkey", "passkeys").await
}
