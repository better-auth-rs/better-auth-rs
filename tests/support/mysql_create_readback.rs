use super::{
    trace::{self, Trace},
    values,
};
use better_auth_core::{
    AuthConfig, AuthInitContext, AuthResult, AuthStore, FieldMap, FieldValue,
    error::DatabaseError,
    id::IdGeneration,
    store::schema::EntityRole,
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use better_auth_seaorm::{
    PluginModels, SeaOrmStore,
    sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
    },
    store::{__private_test_support::bundled_schema::BundledSchema, entities},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{future::Future, sync::Arc};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const CASES: [&str; 11] = [
    "explicit-id",
    "serial-id",
    "database-default-full-match",
    "mapped-unique-first-hit",
    "mapped-unique-first-miss-second-hit",
    "mapped-unique-null-skipped",
    "mapped-unique-empty-probed",
    "full-match-single-then-duplicate",
    "full-match-transaction-single-then-duplicate",
    "readback-error-direct",
    "readback-error-transaction",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    version: String,
    backend: String,
    model: String,
    cases: Vec<Case>,
    lifecycle: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    generation: Value,
    transaction: bool,
    declaration: Declaration,
    setup: Vec<String>,
    operations: Vec<Operation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Declaration {
    model_name: String,
    fields: serde_json::Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    input: Value,
    returned: bool,
    result: Option<Value>,
    keys: Option<Vec<String>>,
    error: Option<Value>,
    trace: Vec<Value>,
    stored: Value,
}

macro_rules! model {
    ($module:ident, $id:ty) => {
        #[expect(
            unreachable_pub,
            reason = "SeaORM derives require public fixture model types"
        )]
        mod $module {
            use better_auth_seaorm::{
                AuthEntity,
                sea_orm::{self, entity::prelude::*},
            };
            #[derive(Clone, Debug, DeriveEntityModel, AuthEntity)]
            #[auth(role = "jwk")]
            #[sea_orm(table_name = "readback_jwks")]
            pub struct Model {
                #[sea_orm(primary_key, auto_increment = false)]
                pub id: $id,
                #[sea_orm(column_name = "stored_public_key")]
                pub public_key: Option<String>,
                #[sea_orm(column_name = "stored_private_key")]
                pub private_key: String,
                #[sea_orm(column_name = "stored_created_at")]
                pub created_at: DateTimeUtc,
                #[sea_orm(column_name = "stored_expires_at")]
                pub expires_at: Option<DateTimeUtc>,
                #[sea_orm(column_name = "stored_algorithm")]
                pub alg: Option<String>,
                #[sea_orm(column_name = "stored_curve")]
                pub crv: Option<String>,
            }
            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}
            impl ActiveModelBehavior for ActiveModel {}
        }
    };
}
model!(text_id, String);
model!(serial_id, i64);

type Plugins<M> = PluginModels<
    entities::api_key::Model,
    entities::device_code::Model,
    entities::passkey::Model,
    entities::two_factor::Model,
    M,
>;

fn capture() -> TestResult<Capture> {
    let captured: Capture =
        serde_json::from_str(include_str!("../fixtures/create-readback-mysql-1.7.6.json"))?;
    assert_eq!(captured.version, "1.7.6");
    assert_eq!(captured.backend, "mysql");
    assert_eq!(captured.model, "jwks");
    assert_eq!(
        captured
            .cases
            .iter()
            .map(|case| case.name.as_str())
            .collect::<Vec<_>>(),
        CASES
    );
    assert_eq!(
        captured.lifecycle["cases"]
            .as_array()
            .expect("lifecycle cases")
            .len(),
        13
    );
    Ok(captured)
}

fn fields(declaration: &Declaration, trace: &Trace) -> AuthResult<UserConfig> {
    assert_eq!(declaration.model_name, "readback_jwks");
    let mut fields = UserConfig::default();
    for (name, declaration) in &declaration.fields {
        assert_eq!(declaration.as_object().expect("field declaration").len(), 4);
        let field_type = match declaration["type"].as_str().expect("field type") {
            "string" => UserFieldType::String,
            "date" => UserFieldType::Date,
            value => panic!("Unexpected readback field type {value}"),
        };
        let callback = |phase: &'static str| {
            let trace = trace.clone();
            let field = name.clone();
            UserFieldTransform::new(move |value| {
                trace.callback(
                    json!({"phase": phase, "field": field, "value": values::observe(&value)?}),
                );
                Ok(value)
            })
        };
        let _ = fields.fields_mut().insert(
            name.clone(),
            UserFieldConfig {
                field_type,
                field_name: Some(
                    declaration["fieldName"]
                        .as_str()
                        .expect("mapped column")
                        .into(),
                ),
                required: Some(declaration["required"].as_bool().expect("required flag")),
                unique: Some(declaration["unique"].as_bool().expect("unique flag")),
                transform: Some(FieldTransforms {
                    input: Some(callback("input")),
                    output: Some(callback("output")),
                }),
                ..Default::default()
            },
        );
    }
    Ok(fields)
}

pub(super) fn revive_fields(input: &Value) -> AuthResult<FieldMap> {
    input
        .as_object()
        .expect("complete input object")
        .iter()
        .map(|(key, value)| Ok((key.clone(), values::revive(value)?)))
        .collect()
}

pub(super) async fn jwk(mut database: DatabaseConnection, name: &str) -> TestResult {
    let case = capture()?
        .cases
        .into_iter()
        .find(|case| case.name == name)
        .expect("named JWK case");
    for sql in &case.setup {
        let _ = database.execute_unprepared(sql).await?;
    }
    let trace = Trace::default();
    trace.capture(&mut database);
    let mut config = AuthConfig::new("mysql-readback-test-secret-at-least-32-characters");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.advanced.database.generate_id = Some(match case.generation {
        Value::Bool(false) => IdGeneration::Database,
        Value::String(ref generation) if generation == "serial" => IdGeneration::Serial,
        ref value => panic!("Unsupported captured ID policy: {value}"),
    });
    let raw: Arc<dyn AuthStore<BundledSchema>> = if case.generation == "serial" {
        Arc::new(
            SeaOrmStore::<BundledSchema>::new(config.clone(), database.clone())
                .with_plugin_schema::<Plugins<serial_id::Model>>(),
        )
    } else {
        Arc::new(
            SeaOrmStore::<BundledSchema>::new(config.clone(), database.clone())
                .with_plugin_schema::<Plugins<text_id::Model>>(),
        )
    };
    let config = Arc::new(config);
    let mut init = AuthInitContext::new(config.clone(), raw.clone());
    init.register_model_fields(EntityRole::Jwk, fields(&case.declaration, &trace)?)?;
    let store = raw.with_runtime(config, Vec::new(), init.into_parts().plugin_fields)?;
    for (index, operation) in case.operations.into_iter().enumerate() {
        assert!(trace.take().is_empty(), "{name} starts with an empty trace");
        let input = revive_fields(&operation.input)?;
        let subscriber = tracing_subscriber::registry().with(trace.clone());
        let result = async {
            if case.transaction {
                better_auth_core::store::transaction(store.as_ref(), move |tx| {
                    Box::pin(async move { tx.create_jwk_record(input).await })
                })
                .await
            } else {
                store.create_jwk_record(input).await
            }
        }
        .with_subscriber(subscriber)
        .await;
        let label = format!("{name} operation {index}");
        trace::check_jwk(trace.take(), &operation.trace, index == 0, &label);
        assert_eq!(result.is_ok(), operation.returned, "{label}: {result:?}");
        match result {
            Ok(result) => {
                assert!(
                    operation.error.is_none(),
                    "{label} unexpected captured error"
                );
                let keys = result
                    .as_ref()
                    .map(|fields| fields.keys().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                assert_eq!(Some(keys), operation.keys, "{label} complete key order");
                let result = result
                    .map(|fields| values::observe(&FieldValue::from(fields)))
                    .transpose()?
                    .unwrap_or(Value::Null);
                assert_eq!(
                    result,
                    operation.result.unwrap_or(Value::Null),
                    "{label} complete result"
                );
            }
            Err(better_auth_core::AuthError::Database(DatabaseError::Query(message))) => {
                trace::check_missing_id_error(
                    operation.error.as_ref().expect("captured readback error"),
                );
                // SeaORM selects explicit columns, so MySQL reports the missing ID in the projection.
                assert_eq!(
                    message,
                    "Query Error: error returned from database: 1054 (42S22): Unknown column 'readback_jwks.id' in 'field list'",
                    "{label} SQLx diagnostic"
                );
            }
            Err(error) => return Err(error.into()),
        }
        let expected_id = if name.starts_with("readback-error-") {
            "database_id"
        } else {
            "id"
        };
        assert_eq!(
            stored(&database, "readback_jwks", expected_id).await?,
            operation.stored,
            "{label} raw rows and column order"
        );
        let _ = trace.take();
    }
    Ok(())
}

pub(super) async fn stored(
    database: &DatabaseConnection,
    table: &str,
    order: &str,
) -> TestResult<Value> {
    use better_auth_seaorm::sea_orm::sqlx::{Column, Row, TypeInfo, ValueRef};
    let mut observed = Vec::new();
    for row in database
        .query_all_raw(Statement::from_string(
            DbBackend::MySql,
            format!("SELECT * FROM `{table}` ORDER BY `{order}`"),
        ))
        .await?
    {
        let row = row.try_as_mysql_row().expect("real MySQL row");
        let mut fields = serde_json::Map::new();
        let mut keys = Vec::new();
        for column in row.columns() {
            let name = column.name();
            keys.push(name);
            let raw = row.try_get_raw(name)?;
            let value = if raw.is_null() {
                Value::Null
            } else {
                match raw.type_info().name() {
                    "CHAR" | "VARCHAR" | "TEXT" => json!(row.try_get::<String, _>(name)?),
                    "INT" => json!(row.try_get::<i32, _>(name)?),
                    "BIGINT" => json!(row.try_get::<i64, _>(name)?),
                    "BOOLEAN" | "TINYINT" => json!(row.try_get::<i8, _>(name)?),
                    "TIMESTAMP" => values::observe(&FieldValue::from(
                        row.try_get::<chrono::DateTime<chrono::Utc>, _>(name)?,
                    ))?,
                    "DATETIME" => values::observe(&FieldValue::from(
                        row.try_get::<chrono::NaiveDateTime, _>(name)?.and_utc(),
                    ))?,
                    kind => {
                        return Err(
                            format!("Unspecified MySQL storage type {kind} for {name}").into()
                        );
                    }
                }
            };
            let _ = fields.insert(name.into(), value);
        }
        observed.push(json!({"row": fields, "keys": keys}));
    }
    Ok(json!(observed))
}

pub(super) async fn in_mysql_catalog<F, Fut>(check: F) -> TestResult
where
    F: FnOnce(DatabaseConnection) -> Fut + Send + 'static,
    Fut: Future<Output = TestResult> + Send + 'static,
{
    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let name = format!("ba_readback_{}", uuid::Uuid::new_v4().simple());
    let _ = database
        .execute_unprepared(&format!("CREATE DATABASE `{name}`"))
        .await?;
    let result = async {
        let _ = database
            .execute_unprepared(&format!("USE `{name}`"))
            .await?;
        let worker = database.clone();
        tokio::spawn(async move { check(worker).await }).await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    let cleanup = database
        .execute_unprepared(&format!("DROP DATABASE `{name}`"))
        .await;
    let closed = database.close().await;
    let _ = cleanup?;
    closed?;
    result
}
