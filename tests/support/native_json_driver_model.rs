use better_auth::AuthConfig;
use better_auth_core::{AuthStore, FieldValue};
use better_auth_seaorm::{
    PluginModels, SeaOrmStore,
    sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Schema, Statement},
    store::{
        __private_test_support::{bundled_schema::BundledSchema, migrator},
        entities::api_key,
    },
};
use serde_json::{Value, json};
use std::sync::Arc;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

macro_rules! model {
    ($module:ident, $payload:ty, $column_type:literal) => {
        #[expect(
            unreachable_pub,
            reason = "SeaORM derives require public fixture types"
        )]
        pub mod $module {
            use better_auth_seaorm::{
                AuthEntity, SqlNumber,
                sea_orm::{self, entity::prelude::*},
            };

            #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
            #[auth(role = "device_code")]
            #[sea_orm(table_name = "native_json_driver")]
            pub struct Model {
                #[sea_orm(primary_key, auto_increment = false)]
                pub id: String,
                #[sea_orm(column_name = "deviceCode")]
                #[serde(rename = "deviceCode")]
                pub device_code: String,
                #[sea_orm(column_name = "userCode")]
                #[serde(rename = "userCode")]
                pub user_code: String,
                #[sea_orm(column_name = "userId")]
                #[serde(rename = "userId")]
                pub user_id: Option<String>,
                #[sea_orm(column_name = "expiresAt")]
                #[serde(rename = "expiresAt")]
                pub expires_at: DateTimeUtc,
                pub status: String,
                #[sea_orm(column_name = "lastPolledAt")]
                #[serde(rename = "lastPolledAt")]
                pub last_polled_at: Option<DateTimeUtc>,
                #[sea_orm(column_name = "pollingInterval", column_type = "Integer", nullable)]
                #[serde(rename = "pollingInterval")]
                pub polling_interval: Option<SqlNumber>,
                #[sea_orm(column_name = "clientId")]
                #[serde(rename = "clientId")]
                pub client_id: Option<String>,
                pub scope: Option<String>,
                #[sea_orm(column_name = "stored_payload", column_type = $column_type, nullable)]
                #[serde(rename = "stored_payload")]
                pub payload: Option<$payload>,
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}
            impl ActiveModelBehavior for ActiveModel {}
        }
    };
}

model!(sqlite, String, "Text");
model!(native, serde_json::Value, "JsonBinary");

pub(crate) async fn setup(
    config: AuthConfig,
    database: DatabaseConnection,
) -> TestResult<Arc<dyn AuthStore<BundledSchema>>> {
    migrator::run_migrations(&database).await?;
    let backend = database.get_database_backend();
    let schema = Schema::new(backend);
    let statement = if backend == DbBackend::Sqlite {
        schema.create_table_from_entity(sqlite::Entity)
    } else {
        schema.create_table_from_entity(native::Entity)
    };
    let _ = database.execute_raw(backend.build(&statement)).await?;
    let store = SeaOrmStore::<BundledSchema>::new(config, database);
    Ok(if backend == DbBackend::Sqlite {
        Arc::new(store.with_plugin_schema::<PluginModels<api_key::Model, sqlite::Model>>())
    } else {
        Arc::new(store.with_plugin_schema::<PluginModels<api_key::Model, native::Model>>())
    })
}

pub(crate) async fn reset(database: &DatabaseConnection) -> TestResult<()> {
    let _ = database
        .execute_unprepared("DELETE FROM native_json_driver")
        .await?;
    Ok(())
}

pub(crate) async fn stored(database: &DatabaseConnection) -> TestResult<Value> {
    let backend = database.get_database_backend();
    let quote = if backend == DbBackend::MySql {
        '`'
    } else {
        '"'
    };
    let text = if backend == DbBackend::MySql {
        "CHAR"
    } else {
        "TEXT"
    };
    let payload = format!("{quote}stored_payload{quote}");
    let statement = Statement::from_string(
        backend,
        format!(
            "SELECT *, {payload} IS NULL AS {quote}payloadSqlNull{quote}, CAST({payload} AS {text}) AS {quote}payloadText{quote} FROM native_json_driver ORDER BY id"
        ),
    );
    let mut rows = Vec::new();
    for row in database.query_all_raw(statement).await? {
        let expires_at = if backend == DbBackend::Sqlite {
            json!(row.try_get::<String>("", "expiresAt")?)
        } else {
            super::values::observe(&FieldValue::from(
                row.try_get::<chrono::DateTime<chrono::Utc>>("", "expiresAt")?,
            ))?
        };
        let payload = if backend == DbBackend::Sqlite {
            json!(row.try_get::<Option<String>>("", "stored_payload")?)
        } else {
            row.try_get::<Option<Value>>("", "stored_payload")?
                .unwrap_or(Value::Null)
        };
        let sql_null = if backend == DbBackend::Postgres {
            json!(row.try_get::<bool>("", "payloadSqlNull")?)
        } else {
            json!(row.try_get::<i64>("", "payloadSqlNull")?)
        };
        rows.push(json!({
            "row": {
                "id": row.try_get::<String>("", "id")?,
                "deviceCode": row.try_get::<String>("", "deviceCode")?,
                "userCode": row.try_get::<String>("", "userCode")?,
                "userId": row.try_get::<Option<String>>("", "userId")?,
                "expiresAt": expires_at,
                "status": row.try_get::<String>("", "status")?,
                "lastPolledAt": row.try_get::<Option<chrono::DateTime<chrono::Utc>>>("", "lastPolledAt")?,
                "pollingInterval": row.try_get::<Option<i32>>("", "pollingInterval")?,
                "clientId": row.try_get::<Option<String>>("", "clientId")?,
                "scope": row.try_get::<Option<String>>("", "scope")?,
                "stored_payload": payload,
            },
            "payloadSqlNull": sql_null,
            "payloadText": row.try_get::<Option<String>>("", "payloadText")?,
        }));
    }
    Ok(Value::Array(rows))
}
