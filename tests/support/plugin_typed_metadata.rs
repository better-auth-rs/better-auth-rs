#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired metadata contract checks complete values, key order, callbacks, and physical storage."
)]

use async_trait::async_trait;
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRecordFields, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, AuthStore, FieldDate, FieldMap, FieldValue, FromFieldMap,
    store::{EphemeralStore, schema::EntityRole},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde_json::Value;
use std::{
    future::Future,
    sync::{Arc, Mutex},
};

#[path = "plugin_typed_metadata_models.rs"]
mod models;
#[path = "two_factor_fields.rs"]
mod native_factor;
use models::Model;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Event = (&'static str, String, FieldValue);
const ID: &str = "typed-metadata-record";

#[derive(Clone, Copy, Debug)]
enum Backend {
    Memory,
    Sqlite,
}

impl Backend {
    fn physical_value(self, value: &FieldValue) -> FieldValue {
        match (self, value) {
            (Self::Sqlite, FieldValue::Bool(value)) => {
                FieldValue::from(if *value { 1.0 } else { 0.0 })
            }
            _ => value.clone(),
        }
    }

    fn storage(self, model: Model, marker: &str, target: &FieldValue) -> AuthResult<Value> {
        let (_, marker_column, target_column) = model.columns();
        let mut row = FieldMap::new();
        if matches!(self, Self::Sqlite) {
            let _ = row.insert("id".into(), ID.into());
        }
        let _ = row.insert(marker_column.into(), marker.into());
        let _ = row.insert(target_column.into(), self.physical_value(target));
        if let Some((_, column, value)) = model.selector() {
            let _ = row.insert(column.into(), value.into());
        }
        if matches!(self, Self::Memory) {
            let _ = row.insert("id".into(), ID.into());
        }
        let keys = row.keys().cloned().collect::<Vec<_>>();
        Ok(serde_json::json!([{"row": row.json()?, "keys": keys}]))
    }
}

#[derive(Default)]
struct State {
    output: FieldValue,
    reject: Option<&'static str>,
    events: Vec<Event>,
}

struct Fields(EntityRole, UserConfig);
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "typed-metadata-fields"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    fn schema(
        &self,
        context: &mut better_auth_core::plugin_runtime::ModelFields,
    ) -> AuthResult<()> {
        context.register_model_fields(self.0, self.1.clone())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn config() -> AuthConfig {
    let mut config = AuthConfig::new("typed-metadata-contract-at-least-thirty-two-characters");
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    config.telemetry.enabled = false;
    config
}

fn lock(state: &Arc<Mutex<State>>) -> AuthResult<std::sync::MutexGuard<'_, State>> {
    state
        .lock()
        .map_err(|_| AuthError::internal("Typed metadata trace lock is poisoned"))
}

fn declaration(model: Model, state: &Arc<Mutex<State>>) -> UserConfig {
    let callback = |phase, name: &'static str| {
        let state = state.clone();
        UserFieldTransform::new(move |value| {
            let mut state = lock(&state)?;
            state.events.push((phase, name.into(), value.clone()));
            if name == model.target() {
                if state.reject == Some(phase) {
                    return Err(AuthError::internal(format!("typed-metadata-{phase}-stop")));
                }
                if phase == "output" {
                    return Ok(state.output.clone());
                }
            }
            Ok(value)
        })
    };
    let (_, marker, target) = model.columns();
    let fields = [
        (
            "marker".into(),
            UserFieldConfig {
                field_name: Some(marker.into()),
                required: Some(false),
                transform: Some(FieldTransforms {
                    input: Some(callback("input", "marker")),
                    output: Some(callback("output", "marker")),
                }),
                ..Default::default()
            },
        ),
        (
            model.target().into(),
            UserFieldConfig {
                field_name: Some(target.into()),
                field_type: model.field_type(),
                required: Some(false),
                transform: Some(FieldTransforms {
                    input: Some(callback("input", model.target())),
                    output: Some(callback("output", model.target())),
                }),
                ..Default::default()
            },
        ),
    ];
    let mut config = UserConfig {
        additional_fields: Some(fields.into()),
    };
    if let Some((name, column, _)) = model.selector() {
        let _ = config.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_name: Some(column.into()),
                required: Some(false),
                ..Default::default()
            },
        );
    }
    config
}

fn writes(stage: &str) -> bool {
    matches!(stage, "create" | "update" | "output-error" | "input-error")
}

fn exact(actual: &FieldMap, expected: &FieldMap) {
    assert_eq!(actual, expected, "Complete native and application fields");
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>(),
        "Missing and own Undefined must remain distinct"
    );
    for (name, value) in expected {
        assert!(
            actual
                .get(name)
                .is_some_and(|actual| actual.strict_equals(value)),
            "{name}: output object identity"
        );
    }
}

async fn contract<S, F, Fut>(
    raw: Arc<dyn AuthStore<S>>,
    backend: Backend,
    model: Model,
    typed: bool,
    snapshot: F,
) -> TestResult<Vec<Value>>
where
    S: AuthSchema,
    F: Fn() -> Fut,
    Fut: Future<Output = TestResult<Value>>,
{
    let state = Arc::new(Mutex::new(State::default()));
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(Fields(model.role(), declaration(model, &state)))
        .build()
        .await?;
    let object = FieldValue::from(FieldMap::from([("source".into(), "output".into())]));
    let mut observations = Vec::new();
    let mut stored_marker = "created";
    let mut stored_target = model.value(true);
    for stage in [
        "create",
        "object",
        "undefined",
        "null",
        "update",
        "output-error",
        "recover",
        "input-error",
    ] {
        let output = match stage {
            "object" | "update" => object.clone(),
            "undefined" => FieldValue::Undefined,
            "null" => FieldValue::Null,
            _ => "visible-output".into(),
        };
        let supplied = match stage {
            "update" => "updated",
            "output-error" => "persisted",
            "input-error" => "rejected",
            _ => stored_marker,
        };
        {
            let mut state = lock(&state)?;
            assert!(state.events.is_empty());
            state.output = output.clone();
            state.reject = match stage {
                "output-error" => Some("output"),
                "input-error" => Some("input"),
                _ => None,
            };
        }
        let before = snapshot().await?;
        let result = if typed {
            model.typed(auth.store().as_ref(), stage, supplied).await
        } else {
            model.raw(auth.store().as_ref(), stage, supplied).await
        };
        let stored = snapshot().await?;
        if !writes(stage) || stage == "input-error" {
            assert_eq!(
                stored, before,
                "Reads and input errors must preserve complete storage"
            );
        }
        if writes(stage) && stage != "input-error" {
            stored_marker = supplied;
            stored_target = model.value(stage == "create");
        }
        assert_eq!(
            stored,
            backend.storage(model, stored_marker, &stored_target)?,
            "{backend:?}/{model:?}/{stage}: complete physical fields, values, and property order"
        );
        let mut expected_events = Vec::new();
        if writes(stage) {
            expected_events.extend([
                ("input", "marker".into(), supplied.into()),
                (
                    "input",
                    model.target().into(),
                    model.value(stage == "create"),
                ),
            ]);
        }
        if stage != "input-error" {
            expected_events.extend([
                ("output", "marker".into(), stored_marker.into()),
                (
                    "output",
                    model.target().into(),
                    backend.physical_value(&stored_target),
                ),
            ]);
        }
        assert_eq!(
            std::mem::take(&mut lock(&state)?.events),
            expected_events,
            "{model:?}/{stage}: complete callback trace"
        );
        if matches!(stage, "input-error" | "output-error") {
            let phase = if stage == "input-error" {
                "input"
            } else {
                "output"
            };
            assert!(
                matches!(result, Err(AuthError::Internal(message)) if message == format!("typed-metadata-{phase}-stop"))
            );
        } else {
            let fields = result?;
            exact(&fields, &model.fields(stored_marker, output));
        }
        observations.push(stored);
    }
    Ok(observations)
}

#[tokio::test]
async fn sparse_memory_typed_plugin_operations_preserve_complete_declarations() -> TestResult {
    for model in Model::ALL {
        let mut lanes = Vec::new();
        for typed in [false, true] {
            let raw = Arc::new(EphemeralStore::new(Arc::new(config())));
            let snapshot = raw.clone();
            lanes.push(
                contract(raw, Backend::Memory, model, typed, move || {
                    let snapshot = snapshot.clone();
                    async move {
                        Ok(Value::Array(
                            snapshot
                                .plugin_storage_rows(model.role())?
                                .into_iter()
                                .map(|row| {
                                    let keys = row.keys().cloned().collect::<Vec<_>>();
                                    Ok(serde_json::json!({"row": row.json()?, "keys": keys}))
                                })
                                .collect::<AuthResult<_>>()?,
                        ))
                    }
                })
                .await?,
            );
        }
        assert_eq!(
            lanes.first(),
            lanes.last(),
            "{model:?}: actual typed writes must store the same complete rows as raw writes"
        );
    }
    Ok(())
}

#[tokio::test]
async fn sparse_sqlite_typed_plugin_operations_require_only_declared_columns() -> TestResult {
    for model in Model::ALL {
        let mut lanes = Vec::new();
        for typed in [false, true] {
            let (store, database) = native_factor::sqlite(config()).await;
            let (table, marker, target) = model.columns();
            let _ = database
                .execute_unprepared(&format!("DROP TABLE IF EXISTS {table}"))
                .await?;
            let kind = match model.field_type() {
                UserFieldType::Boolean => "BOOLEAN",
                UserFieldType::Number => "INTEGER",
                _ => "TEXT",
            };
            let selector = model
                .selector()
                .map(|(_, column, _)| format!(", {column} TEXT"))
                .unwrap_or_default();
            let _ = database.execute_unprepared(&format!("CREATE TABLE {table} (id TEXT PRIMARY KEY, {marker} TEXT, {target} {kind}{selector})")).await?;
            let mut columns = vec!["id", marker, target];
            if let Some((_, column, _)) = model.selector() {
                columns.push(column);
            }
            let columns = columns
                .iter()
                .map(|name| format!("'{name}', {name}"))
                .collect::<Vec<_>>()
                .join(", ");
            let snapshot = database.clone();
            lanes.push(contract(Arc::new(store), Backend::Sqlite, model, typed, move || {
                let database = snapshot.clone();
                let columns = columns.clone();
                async move {
                    let rows = database.query_all_raw(Statement::from_string(DbBackend::Sqlite, format!("SELECT json_object({columns}) AS record FROM {table} ORDER BY id"))).await?;
                    Ok(Value::Array(rows.into_iter().map(|row| {
                        let value: Value = serde_json::from_str(&row.try_get::<String>("", "record")?)?;
                        let keys = value.as_object().ok_or("Expected the physical SQL record")?.keys().cloned().collect::<Vec<_>>();
                        Ok(serde_json::json!({"row": value, "keys": keys}))
                    }).collect::<TestResult<_>>()?))
                }
            }).await?);
            database.close().await?;
        }
        assert_eq!(
            lanes.first(),
            lanes.last(),
            "{model:?}: database storage differs between raw and actual typed operations"
        );
    }
    Ok(())
}
