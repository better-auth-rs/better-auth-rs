use super::*;
use better_auth_core::{
    AuthConfig, AuthRecordFields, AuthSchema, AuthStore, CreatePasskey, FieldMap, FieldValue,
    Passkey, PasskeyCredentialState, PasskeyStorage, SchemaValue, UpdatePasskey,
    UpdatePasskeyAuthentication,
    id::{IdGeneration, IdGenerator},
    store::schema::{EntityRole, SchemaConfiguration},
    user_fields::{FieldTransforms, UserFieldTransform, UserFieldType},
    wire::PasskeyView,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement},
    store::__private_test_support::bundled_schema::BundledSchema,
};
use serde_json::Value;
use std::sync::{Mutex, MutexGuard};

#[path = "timestamps.rs"]
mod timestamps;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Event = (&'static str, &'static str, FieldValue);
type Events = Arc<Mutex<Vec<Event>>>;
const ID: &str = "typed-declaration-passkey";

fn locked(events: &Events) -> AuthResult<MutexGuard<'_, Vec<Event>>> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Passkey declaration trace lock is poisoned"))
}

fn config() -> AuthConfig {
    let mut config = AuthConfig::new("typed-passkey-declarations-at-least-thirty-two-characters");
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    config.telemetry.enabled = false;
    config.advanced.database.generate_id = Some(IdGeneration::Custom(IdGenerator::new(|_| {
        Ok(Some(ID.into()))
    })));
    config
}

fn callback(
    events: &Events,
    object: &FieldValue,
    phase: &'static str,
    field: &'static str,
) -> UserFieldTransform {
    let events = events.clone();
    let object = object.clone();
    UserFieldTransform::new(move |value| {
        locked(&events)?.push((phase, field, value.clone()));
        if field == "name" {
            if value.as_str()
                == Some(if phase == "input" {
                    "reject-input"
                } else {
                    "stored:reject-output"
                })
            {
                return Err(AuthError::internal(format!("passkey-{phase}-stop")));
            }
            if value.is_null() || value.is_undefined() {
                return Ok(value);
            }
            if phase == "output" {
                if value.as_str() == Some("stored:omit-output") {
                    return Ok(FieldValue::Undefined);
                }
                if value.as_str() == Some("stored:object-output") {
                    return Ok(object.clone());
                }
            }
            return Ok(format!(
                "{}:{}",
                if phase == "input" {
                    "stored"
                } else {
                    "visible"
                },
                SchemaValue::<String>::from_field(value).display_string()?
            )
            .into());
        }
        if phase == "input" {
            return Ok(value);
        }
        Ok(format!(
            "count:{}",
            SchemaValue::<String>::from_field(value).display_string()?
        )
        .into())
    })
}

fn fields(events: &Events, object: &FieldValue, name_column: &str) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            [
                (
                    "name".into(),
                    UserFieldConfig {
                        required: Some(false),
                        field_name: Some(name_column.into()),
                        transform: Some(FieldTransforms {
                            input: Some(callback(events, object, "input", "name")),
                            output: Some(callback(events, object, "output", "name")),
                        }),
                        ..Default::default()
                    },
                ),
                (
                    "counter".into(),
                    UserFieldConfig {
                        required: Some(false),
                        field_type: UserFieldType::Number,
                        field_name: Some("stored_counter".into()),
                        transform: Some(FieldTransforms {
                            input: Some(callback(events, object, "input", "counter")),
                            output: Some(callback(events, object, "output", "counter")),
                        }),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        ),
    }
}

fn input(name: FieldValue, counter: u64, storage: PasskeyStorage) -> CreatePasskey {
    CreatePasskey {
        name: SchemaValue::from_field(name),
        counter,
        user_id: "must-not-return-owner".into(),
        credential_id: "must-not-return-id".into(),
        public_key: "must-not-return-key".into(),
        device_type: "singleDevice".into(),
        backed_up: false,
        transports: Some("internal".into()),
        aaguid: Some("must-not-return-aaguid".into()).into(),
        credential: match storage {
            PasskeyStorage::Native => PasskeyCredentialState::Native,
            PasskeyStorage::Legacy => "private-create".into(),
        },
        additional_fields: [("mustNotReturn".into(), "extension".into())].into(),
    }
}

enum Storage {
    Memory(Box<EphemeralStore>),
    Sqlite(DatabaseConnection),
}

impl Storage {
    async fn rows(&self) -> TestResult<Vec<FieldMap>> {
        match self {
            Self::Memory(store) => Ok(store.storage_rows(EntityRole::Passkey)?),
            Self::Sqlite(database) => database.query_all_raw(Statement::from_string(DbBackend::Sqlite,
                "SELECT json_object('id',id,'stored_label',stored_label,'stored_counter',stored_counter) AS record FROM ordinary_passkey_fields ORDER BY id"
            )).await?.into_iter().map(|row| {
                let fields: Value = serde_json::from_str(&row.try_get::<String>("", "record")?)?;
                Ok(FieldValue::from_json(fields)?.as_object().ok_or("Expected complete physical Passkey row")?.snapshot_fields()?)
            }).collect(),
        }
    }
}

enum Returned {
    Typed(Box<Passkey>),
    Raw(FieldMap),
}

async fn execute<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    typed: bool,
    stage: &str,
    name: FieldValue,
    counter: u64,
) -> AuthResult<Option<Returned>> {
    let id = SchemaValue::<String>::from(ID);
    if stage == "delete" {
        store.delete_passkey(ID).await?;
        return Ok(None);
    }
    if stage == "create" {
        let data = input(name, counter, store.passkey_storage());
        return if typed {
            store
                .create_passkey(data)
                .await
                .map(|row| Some(Returned::Typed(Box::new(row))))
        } else {
            let mut fields = data.into_adapter_fields()?;
            let _ = fields.insert("id".into(), ID.into());
            store
                .create_passkey_record(fields)
                .await
                .map(|row| row.map(Returned::Raw))
        };
    }
    if matches!(stage, "read" | "read-error" | "missing") {
        return if typed {
            store
                .get_passkey_by_id(ID)
                .await
                .map(|row| row.map(|row| Returned::Typed(Box::new(row))))
        } else {
            store
                .get_passkey_record(&id)
                .await
                .map(|row| row.map(Returned::Raw))
        };
    }
    if stage == "auth" && typed {
        let update = match store.passkey_storage() {
            PasskeyStorage::Native => UpdatePasskeyAuthentication::Native { counter },
            PasskeyStorage::Legacy => UpdatePasskeyAuthentication::Legacy {
                counter,
                credential: "private-auth".into(),
                backed_up: true,
                device_type: "multiDevice".into(),
            },
        };
        return store
            .update_passkey_authentication(&id, update)
            .await
            .map(|row| Some(Returned::Typed(Box::new(row))));
    }
    let update = UpdatePasskey {
        name: if stage == "auth" {
            Default::default()
        } else {
            SchemaValue::from_field(name)
        },
        counter: Some(counter),
        ..Default::default()
    };
    if typed {
        store
            .update_passkey(&id, update)
            .await
            .map(|row| Some(Returned::Typed(Box::new(row))))
    } else {
        store
            .update_passkey_record(&id, update.into_adapter_fields()?)
            .await
            .map(|row| row.map(Returned::Raw))
    }
}

fn assert_record(actual: &FieldMap, expected: &FieldMap, stage: &str) {
    assert_eq!(actual, expected, "{stage} complete record");
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>(),
        "{stage} key order"
    );
}

fn visible_name(label: Option<&str>, object: &FieldValue) -> FieldValue {
    match label {
        None => FieldValue::Null,
        Some("omit-output") => FieldValue::Undefined,
        Some("object-output") => object.clone(),
        Some(label) => format!("visible:stored:{label}").into(),
    }
}

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, storage: Storage) -> TestResult {
    let events = Events::default();
    let object = FieldValue::from(FieldMap::from([("source".into(), "output".into())]));
    let config = Arc::new(config());
    let mut model_fields = better_auth_core::plugin_runtime::ModelFields::default();
    model_fields.register_model_fields(
        EntityRole::Passkey,
        fields(&events, &object, "stored_label"),
    )?;

    model_fields.set_schema_configuration(&SchemaConfiguration {
        config: config.clone(),
        plugins: Vec::new(),
        metadata: Default::default(),
        secondary_storage: false,
        rate_limit: Default::default(),
    });
    let store = raw.with_runtime(config, Vec::new(), model_fields)?;
    let mut raw_observations = Vec::new();
    for typed in [false, true] {
        let mut observations = Vec::new();
        let mut private_credential = "private-create";
        for (stage, label, counter) in [
            ("create", Some("Desk"), 1),
            ("read", Some("Desk"), 1),
            ("update", Some("Next"), 2),
            ("auth", Some("Next"), 3),
            ("null", None, 4),
            ("undefined-output", Some("omit-output"), 5),
            ("object-output", Some("object-output"), 6),
            ("output-error", Some("reject-output"), 7),
            ("read-error", Some("reject-output"), 7),
            ("recover", Some("Restored"), 8),
            ("input-error", Some("Restored"), 8),
            ("delete", None, 0),
            ("missing", None, 0),
        ] {
            let before = storage.rows().await?;
            let started = chrono::Utc::now().timestamp_millis() as f64;
            let supplied = if stage == "input-error" {
                "reject-input".into()
            } else {
                label.map_or(FieldValue::Null, FieldValue::from)
            };
            let result = execute(
                store.as_ref(),
                typed,
                stage,
                supplied.clone(),
                if stage == "input-error" { 9 } else { counter },
            )
            .await;
            let present = !matches!(stage, "delete" | "missing");
            let rejected = matches!(stage, "input-error" | "output-error" | "read-error");
            let mut callbacks = Vec::new();
            let write = !matches!(stage, "read" | "read-error" | "delete" | "missing");
            if write {
                if stage != "auth" {
                    callbacks.push(("input", "name", supplied));
                }
                if stage != "input-error" {
                    callbacks.push(("input", "counter", counter.into()));
                }
            }
            let stored_name =
                label.map_or(FieldValue::Null, |label| format!("stored:{label}").into());
            if present && stage != "input-error" {
                callbacks.push(("output", "name", stored_name.clone()));
                if !rejected {
                    callbacks.push(("output", "counter", counter.into()));
                }
            }
            assert_eq!(
                std::mem::take(&mut *locked(&events)?),
                callbacks,
                "typed={typed} {stage} callbacks"
            );
            let expected = FieldMap::from([
                ("name".into(), visible_name(label, &object)),
                ("counter".into(), format!("count:{counter}").into()),
                ("id".into(), ID.into()),
            ]);
            let returned = if rejected {
                let error = result.err().ok_or("Expected the original callback error")?;
                assert_eq!(
                    error.instrumentation_message()?,
                    if stage == "input-error" {
                        "passkey-input-stop"
                    } else {
                        "passkey-output-stop"
                    }
                );
                None
            } else {
                result?
            };
            let rows = storage.rows().await?;
            let private = typed
                && matches!(&storage, Storage::Memory(_))
                && store.passkey_storage() == PasskeyStorage::Legacy;
            if stage == "auth" {
                private_credential = "private-auth";
            }
            let mut physical = match &storage {
                Storage::Memory(_) => FieldMap::from([
                    ("stored_label".into(), stored_name.clone()),
                    ("stored_counter".into(), counter.into()),
                    ("id".into(), ID.into()),
                ]),
                Storage::Sqlite(_) => FieldMap::from([
                    ("id".into(), ID.into()),
                    ("stored_label".into(), stored_name),
                    ("stored_counter".into(), counter.into()),
                ]),
            };
            if present && private {
                let row = rows.first().ok_or("Expected private Passkey storage")?;
                let timestamp = row
                    .get("updatedAt")
                    .ok_or("Expected private updatedAt")?
                    .clone();
                let time = timestamp
                    .as_date()
                    .ok_or("Expected private Date")?
                    .milliseconds();
                if write && stage != "input-error" {
                    assert!(
                        time >= started && time <= chrono::Utc::now().timestamp_millis() as f64
                    );
                }
                let _ = physical.insert("credential".into(), private_credential.into());
                let _ = physical.insert("updatedAt".into(), timestamp);
            }
            if present {
                assert_eq!(rows.len(), 1);
                assert_record(
                    rows.first().ok_or("Expected complete stored row")?,
                    &physical,
                    stage,
                );
            } else {
                assert!(rows.is_empty());
            }
            if matches!(stage, "read" | "read-error" | "input-error" | "missing") {
                assert_eq!(rows, before, "{stage} unchanged storage");
            }
            let observed = match returned {
                Some(Returned::Typed(row)) => {
                    if store.passkey_storage() == PasskeyStorage::Native {
                        assert!(row.credential.field_value().is_undefined());
                        assert!(row.updated_at.field_value().is_undefined());
                    }
                    let view = PasskeyView::from(row.as_ref());
                    let public = view.field_values()?;
                    assert_record(&public, &expected, stage);
                    let json = serde_json::to_value(&view)?;
                    let expected_json = Value::Object(expected.json()?);
                    assert_eq!(json, expected_json, "{stage} complete public JSON");
                    assert_eq!(
                        json.as_object()
                            .ok_or("Expected public Passkey JSON")?
                            .keys()
                            .collect::<Vec<_>>(),
                        expected_json
                            .as_object()
                            .ok_or("Expected complete public JSON")?
                            .keys()
                            .collect::<Vec<_>>(),
                        "{stage} JSON key order"
                    );
                    if label == Some("object-output") {
                        assert!(row.name.field_value().strict_equals(&object));
                    }
                    assert!(
                        row.counter.typed().is_err(),
                        "cross-type output survives typed record construction"
                    );
                    let mut complete = expected.clone();
                    if private {
                        let _ = complete.insert(
                            "updatedAt".into(),
                            physical
                                .get("updatedAt")
                                .ok_or("Expected complete private timestamp")?
                                .clone(),
                        );
                        let _ = complete.insert("credential".into(), private_credential.into());
                        assert_eq!(row.credential.typed()?, private_credential);
                    }
                    assert_record(&row.field_values()?, &complete, stage);
                    Some(public)
                }
                Some(Returned::Raw(row)) => {
                    assert_record(&row, &expected, stage);
                    Some(row)
                }
                None => {
                    assert!(!present || rejected);
                    None
                }
            };
            observations.push((stage, observed, callbacks));
        }
        if typed {
            assert_eq!(
                observations, raw_observations,
                "typed CRUD uses the same public field policies as raw CRUD"
            );
        } else {
            raw_observations = observations;
        }
    }
    if let Storage::Sqlite(database) = storage {
        database.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_typed_passkey_declarations_match_raw_records_and_keep_private_state_separate()
-> TestResult {
    for raw in [
        EphemeralStore::new(Arc::new(config())),
        EphemeralStore::new(Arc::new(config())).with_passkey_storage(PasskeyStorage::Legacy),
    ] {
        contract(Arc::new(raw.clone()), Storage::Memory(Box::new(raw))).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_typed_passkey_declarations_need_only_declared_physical_columns() -> TestResult {
    let database = Database::connect("sqlite::memory:").await?;
    let _ = database.execute_unprepared("CREATE TABLE ordinary_passkey_fields (id TEXT PRIMARY KEY NOT NULL, stored_label TEXT, stored_counter INTEGER)").await?;
    let raw = SeaOrmStore::<BundledSchema>::new(config(), database.clone())
        .with_plugin_schema::<fixture::Plugins>();
    contract(Arc::new(raw), Storage::Sqlite(database)).await
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare private credentials, callbacks, and storage; Result propagates fixture and adapter errors"
)]
async fn memory_legacy_private_credentials_do_not_overwrite_declared_aliases_or_omission()
-> TestResult {
    for omit in [false, true] {
        let config = Arc::new(config());
        let raw = EphemeralStore::new(config.clone()).with_passkey_storage(PasskeyStorage::Legacy);
        let events = Events::default();
        let object = FieldValue::Null;
        let mut declaration = fields(&events, &object, "credential");
        if omit {
            let inputs = events.clone();
            declaration
                .fields_mut()
                .get_mut("name")
                .ok_or("Expected the declared name")?
                .transform
                .as_mut()
                .ok_or("Expected name transforms")?
                .input = Some(UserFieldTransform::new(move |value| {
                locked(&inputs)?.push(("input", "name", value));
                Ok(FieldValue::Undefined)
            }));
        }
        let raw_store: Arc<dyn AuthStore<better_auth_core::store::StatelessSchema>> =
            Arc::new(raw.clone());
        let mut model_fields = better_auth_core::plugin_runtime::ModelFields::default();
        model_fields.register_model_fields(EntityRole::Passkey, declaration)?;

        model_fields.set_schema_configuration(&SchemaConfiguration {
            config: config.clone(),
            plugins: Vec::new(),
            metadata: Default::default(),
            secondary_storage: false,
            rate_limit: Default::default(),
        });
        let store = raw_store.with_runtime(config, Vec::new(), model_fields)?;
        for (stage, counter) in [("create", 1), ("auth", 2)] {
            let started = chrono::Utc::now().timestamp_millis() as f64;
            let row = match execute(store.as_ref(), true, stage, "Desk".into(), counter).await? {
                Some(Returned::Typed(row)) => row,
                _ => return Err("Expected the typed Legacy Passkey".into()),
            };
            let credential = if omit {
                FieldValue::Undefined
            } else {
                "stored:Desk".into()
            };
            let public = FieldMap::from([
                (
                    "name".into(),
                    if omit {
                        FieldValue::Undefined
                    } else {
                        "visible:stored:Desk".into()
                    },
                ),
                ("counter".into(), format!("count:{counter}").into()),
                ("id".into(), ID.into()),
            ]);
            assert_record(
                &PasskeyView::from(row.as_ref()).field_values()?,
                &public,
                stage,
            );
            assert_eq!(
                row.credential.field_value(),
                credential,
                "{stage} private consumer observes the declared physical value"
            );
            let mut expected_events = if stage == "create" {
                vec![("input", "name", "Desk".into())]
            } else {
                Vec::new()
            };
            expected_events.extend([
                ("input", "counter", counter.into()),
                ("output", "name", credential.clone()),
                ("output", "counter", counter.into()),
            ]);
            assert_eq!(std::mem::take(&mut *locked(&events)?), expected_events);
            let timestamp = row.updated_at.field_value();
            let time = timestamp
                .as_date()
                .ok_or("Expected private updatedAt Date")?
                .milliseconds();
            assert!(time >= started && time <= chrono::Utc::now().timestamp_millis() as f64);
            let mut physical = FieldMap::new();
            if !omit {
                let _ = physical.insert("credential".into(), credential.clone());
            }
            physical.extend([
                ("stored_counter".into(), counter.into()),
                ("id".into(), ID.into()),
                ("updatedAt".into(), timestamp.clone()),
            ]);
            let stored = raw.storage_rows(EntityRole::Passkey)?;
            assert_eq!(stored.len(), 1);
            assert_record(
                stored.first().ok_or("Expected private collision storage")?,
                &physical,
                stage,
            );
            let mut complete = public.clone();
            let _ = complete.insert("updatedAt".into(), timestamp);
            if !omit {
                let _ = complete.insert("credential".into(), credential.clone());
            }
            assert_record(&row.field_values()?, &complete, stage);
            let raw_record = store
                .get_passkey_record(&ID.into())
                .await?
                .ok_or("Expected the same raw record")?;
            assert_record(&raw_record, &public, stage);
            assert_eq!(
                std::mem::take(&mut *locked(&events)?),
                [
                    ("output", "name", credential),
                    ("output", "counter", counter.into()),
                ]
            );
            assert_eq!(
                raw.storage_rows(EntityRole::Passkey)?,
                stored,
                "raw comparison does not mutate private storage"
            );
        }
    }
    Ok(())
}
