#![expect(
    clippy::expect_used,
    reason = "The paired contract must retain complete records, physical column checks, and callback traces."
)]

use super::{contract, display_fixture};
use better_auth::{
    __private_core::{
        AuthError, AuthResult, AuthSchema, AuthStore, CreatePasskey, CreateUser, Passkey,
        PasskeyCredentialState, PasskeyStorage, UpdatePasskeyAuthentication,
        store::EphemeralStore,
        user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
        wire::PasskeyView,
    },
    BetterAuth,
    seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU8, Ordering},
};

const MAPPINGS: [&str; 3] = ["default", "empty", "renamed"];
const OPERATIONS: [&str; 6] = [
    "create",
    "get-id",
    "get-credential",
    "list",
    "update-name",
    "update-auth",
];
const NATIVE: [&str; 11] = [
    "id",
    "name",
    "publicKey",
    "userId",
    "credentialID",
    "counter",
    "deviceType",
    "backedUp",
    "transports",
    "createdAt",
    "aaguid",
];
const FIRST: &str = "EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4";
const UPDATED: &str = "DD4EC289-E01D-41C9-BB89-70FA845D4BF2";
type Trace = Arc<Mutex<Vec<Value>>>;

fn push(trace: &Trace, value: Value) {
    trace.lock().expect("display trace lock").push(value);
}

fn take(trace: &Trace) -> Vec<Value> {
    std::mem::take(&mut *trace.lock().expect("display trace lock"))
}

fn policies(mapping: &str, events: Option<&Trace>, failure: &Arc<AtomicU8>) -> UserConfig {
    let mut fields = UserConfig::default();
    for name in ["aaguid", "name"] {
        let mut field = UserFieldConfig {
            required: Some(false),
            field_name: match mapping {
                "renamed" => Some(format!("stored_{name}")),
                "empty" => Some(String::new()),
                _ => None,
            },
            ..Default::default()
        };
        if let Some(events) = events {
            if name == "aaguid" {
                let events = events.clone();
                field.on_update = Some(Arc::new(move || {
                    push(&events, json!(["onUpdate", "aaguid"]));
                    json!(format!(" {UPDATED} "))
                }));
            }
            let input_events = events.clone();
            let output_events = events.clone();
            let input_failure = failure.clone();
            let output_failure = failure.clone();
            field.transform = Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    push(
                        &input_events,
                        json!([
                            "input",
                            name,
                            value.clone().unwrap_or_else(|| json!({"type":"undefined"}))
                        ]),
                    );
                    if name == "aaguid" && input_failure.load(Ordering::SeqCst) == 1 {
                        return Err(AuthError::internal("ordinary Passkey input error"));
                    }
                    Ok(value.map(|value| match value {
                        Value::String(text) if name == "aaguid" => {
                            json!(text.trim().to_ascii_lowercase())
                        }
                        Value::String(text) => json!(text.trim()),
                        value => value,
                    }))
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    push(
                        &output_events,
                        json!([
                            "output",
                            name,
                            value.clone().unwrap_or_else(|| json!({"type":"undefined"}))
                        ]),
                    );
                    if name == "aaguid" && output_failure.load(Ordering::SeqCst) == 2 {
                        return Err(AuthError::internal("ordinary Passkey output error"));
                    }
                    Ok(value.map(|value| match value {
                        Value::String(text) if name == "aaguid" => json!(text.to_ascii_uppercase()),
                        Value::String(text) => json!(format!("{text}:out")),
                        value => value,
                    }))
                })),
            });
        }
        let _ = fields.fields_mut().insert(name.into(), field);
    }
    fields
}

struct Fixture<'a, S: AuthSchema> {
    store: Arc<dyn AuthStore<S>>,
    reader: Arc<dyn AuthStore<S>>,
    database: Option<&'a DatabaseConnection>,
    mapping: &'a str,
    owner: String,
    identity: OnceLock<(String, Value)>,
    events: Trace,
    failure: Arc<AtomicU8>,
}

impl<'a, S: AuthSchema> Fixture<'a, S> {
    async fn new(
        raw: Arc<dyn AuthStore<S>>,
        mapping: &'a str,
        database: Option<&'a DatabaseConnection>,
    ) -> AuthResult<Self> {
        let failure = Arc::new(AtomicU8::new(0));
        let events = Trace::default();
        let reader = BetterAuth::new(contract::config())
            .store_arc(raw.clone())
            .plugin(contract::Fields(policies(mapping, None, &failure)))
            .build()
            .await?;
        let owner = reader
            .store()
            .create_user(
                CreateUser::new()
                    .with_name("Passkey field owner")
                    .with_email("owner@passkey-fields.test")
                    .with_email_verified(false),
            )
            .await?
            .id
            .typed()?
            .clone();
        let auth = BetterAuth::new(contract::config())
            .store_arc(raw)
            .plugin(contract::Fields(policies(mapping, Some(&events), &failure)))
            .build()
            .await?;
        let fixture = Self {
            store: auth.store().clone(),
            reader: reader.store().clone(),
            database,
            mapping,
            owner,
            identity: OnceLock::new(),
            events,
            failure,
        };
        if let Some(database) = database {
            let columns = database
                .query_all_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "PRAGMA table_info(ordinary_mapped_passkey)".to_owned(),
                ))
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let mut actual = columns
                .iter()
                .map(|column| column.try_get::<String>("", "name"))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let mut expected = NATIVE.map(|name| fixture.column(name)).to_vec();
            actual.sort_unstable();
            expected.sort_unstable();
            assert_eq!(actual, expected);
        }
        Ok(fixture)
    }

    fn column(&self, name: &str) -> String {
        if self.mapping == "renamed" && matches!(name, "name" | "aaguid") {
            format!("stored_{name}")
        } else {
            name.into()
        }
    }

    fn input(&self) -> CreatePasskey {
        CreatePasskey {
            user_id: self.owner.clone(),
            name: Some(" Desk ".into()).into(),
            credential_id: "ordinary-credential".into(),
            public_key: "ordinary-public-key".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: None,
            credential: match self.store.passkey_storage() {
                PasskeyStorage::Native => PasskeyCredentialState::Native,
                PasskeyStorage::Legacy => "ordinary-private-record".into(),
            },
            aaguid: Some(format!(" {FIRST} ")).into(),
            additional_fields: Default::default(),
        }
    }

    #[expect(
        clippy::panic_in_result_fn,
        reason = "The contract asserts Passkey identity and native fields before propagating serialization errors"
    )]
    fn visible(&self, row: &Passkey) -> AuthResult<Value> {
        let id = row.id.typed()?;
        assert!(!id.is_empty());
        assert_eq!(row.user_id, self.owner);
        assert_eq!(row.credential_id, "ordinary-credential");
        assert_eq!(row.public_key, "ordinary-public-key");
        assert_eq!(row.device_type, "singleDevice");
        assert!(!row.backed_up);
        assert_eq!(row.transports, None);
        assert!(row.created_at.typed()?.is_some());
        let created = serde_json::to_value(&row.created_at)?;
        let identity = self.identity.get_or_init(|| (id.clone(), created.clone()));
        assert_eq!(id, &identity.0);
        assert_eq!(created, identity.1);
        let mut value = serde_json::to_value(row)?;
        let object = value.as_object_mut().expect("complete Passkey object");
        match self.store.passkey_storage() {
            PasskeyStorage::Native => {
                assert!(row.credential.is_undefined());
                assert!(row.updated_at.is_undefined());
            }
            PasskeyStorage::Legacy => {
                assert_eq!(row.credential.typed()?, "ordinary-private-record");
                let _ = row.updated_at.typed()?;
            }
        }
        // The legacy Rust envelope has an update timestamp outside the upstream Passkey model.
        let _ = object.remove("updatedAt");
        assert_eq!(&value, &serde_json::to_value(PasskeyView::from(row))?);
        let object = value.as_object_mut().expect("complete Passkey object");
        let mut names = object.keys().map(String::as_str).collect::<Vec<_>>();
        let mut expected = NATIVE.to_vec();
        names.sort_unstable();
        expected.sort_unstable();
        assert_eq!(names, expected);
        let _ = object.insert("id".into(), json!("<passkey-id>"));
        let _ = object.insert("userId".into(), json!("<owner-id>"));
        let _ = object.insert("createdAt".into(), json!("<created-at>"));
        Ok(value)
    }

    async fn stored(&self) -> AuthResult<Value> {
        let rows = self.reader.list_passkeys_by_user(&self.owner).await?;
        assert!(rows.len() <= 1);
        if let Some(database) = self.database {
            let name = self.column("name");
            let aaguid = self.column("aaguid");
            let raw = database
                .query_all_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    format!("SELECT id, {name}, {aaguid}, counter FROM ordinary_mapped_passkey"),
                ))
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            assert_eq!(raw.len(), rows.len());
            for (stored, row) in raw.iter().zip(&rows) {
                let get = |column: &str| {
                    stored
                        .try_get::<Option<String>>("", column)
                        .map_err(|error| AuthError::internal(error.to_string()))
                };
                assert_eq!(get("id")?.as_ref(), Some(row.id.typed()?));
                assert_eq!(&get(&name)?, row.name.typed()?);
                assert_eq!(&get(&aaguid)?, row.aaguid.typed()?);
                assert_eq!(
                    stored
                        .try_get::<i64>("", "counter")
                        .map_err(|error| AuthError::internal(error.to_string()))?,
                    i64::try_from(row.counter).expect("fixture counter fits SQL")
                );
            }
        }
        Ok(json!(
            rows.iter()
                .map(|row| self.visible(row))
                .collect::<AuthResult<Vec<_>>>()?
        ))
    }

    async fn execute(&self, operation: &str, seed: Option<&Passkey>) -> AuthResult<Vec<Passkey>> {
        if operation == "create" {
            return self
                .store
                .create_passkey(self.input())
                .await
                .map(|row| vec![row]);
        }
        let seed = seed.expect("seeded Passkey");
        let id = seed.id.typed()?;
        Ok(match operation {
            "get-id" => self
                .store
                .get_passkey_by_id(id)
                .await?
                .into_iter()
                .collect(),
            "get-credential" => self
                .store
                .get_passkey_by_credential_id(&seed.credential_id)
                .await?
                .into_iter()
                .collect(),
            "list" => self.store.list_passkeys_by_user(&self.owner).await?,
            "update-name" => vec![self.store.update_passkey_name(id, " Desk-renamed ").await?],
            "update-auth" => vec![
                self.store
                    .update_passkey_authentication(
                        &seed.id,
                        match self.store.passkey_storage() {
                            PasskeyStorage::Native => {
                                UpdatePasskeyAuthentication::Native { counter: 1 }
                            }
                            PasskeyStorage::Legacy => UpdatePasskeyAuthentication::Legacy {
                                credential: seed.credential.typed()?.clone(),
                                counter: 1,
                                backed_up: seed.backed_up,
                                device_type: seed.device_type.clone(),
                            },
                        },
                    )
                    .await?,
            ],
            _ => return Err(AuthError::internal("Unknown Passkey mapping operation")),
        })
    }

    async fn observe(&self, name: &str, result: Value) -> AuthResult<Value> {
        let events = take(&self.events);
        let stored = self.stored().await?;
        Ok(json!({"name":name,"events":events,"result":result,"stored":stored}))
    }

    async fn operations(&self) -> AuthResult<Value> {
        let mut seed = None;
        let mut observations = Vec::new();
        for operation in OPERATIONS {
            let rows = self.execute(operation, seed.as_ref()).await?;
            assert_eq!(rows.len(), 1);
            let result = rows
                .iter()
                .map(|row| self.visible(row))
                .collect::<AuthResult<Vec<_>>>()?;
            if operation == "create" {
                seed = rows.first().cloned();
            }
            observations.push(self.observe(operation, json!(result)).await?);
        }
        Ok(json!(observations))
    }

    async fn failure(&self, operation: &str, phase: u8) -> AuthResult<Value> {
        let seed = if operation == "create" {
            None
        } else {
            Some(self.store.create_passkey(self.input()).await?)
        };
        let before = self.stored().await?;
        let _ = take(&self.events);
        self.failure.store(phase, Ordering::SeqCst);
        let result = self.execute(operation, seed.as_ref()).await;
        self.failure.store(0, Ordering::SeqCst);
        let phase_name = if phase == 1 { "input" } else { "output" };
        let message = format!("ordinary Passkey {phase_name} error");
        match result {
            Err(AuthError::Internal(actual)) => assert_eq!(actual, message),
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(AuthError::internal(
                    "Passkey callback did not reject the mapped operation",
                ));
            }
        }
        let observation = self
            .observe(
                &format!("{operation}-{phase_name}-error"),
                json!({"sameError":true,"message":message}),
            )
            .await?;
        if phase == 1 {
            assert_eq!(observation.get("stored"), Some(&before));
        }
        Ok(observation)
    }
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    mapping: &str,
    database: Option<&DatabaseConnection>,
    scenario: contract::Scenario,
) -> AuthResult<()> {
    let expected: Value = serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/passkey-display-mapping-1.7.6.json"
        ))
        .map_err(|error| AuthError::internal(error.to_string()))?,
    )?;
    assert_eq!(
        expected.get("version").and_then(Value::as_str),
        Some("1.7.6")
    );
    let backends = expected
        .get("backends")
        .and_then(Value::as_array)
        .expect("captured backends");
    assert_eq!(
        backends
            .iter()
            .map(|case| case.get("backend").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        [Some("memory"), Some("sqlite")]
    );
    let cases = backends
        .iter()
        .find(|case| case.get("backend").and_then(Value::as_str) == Some(backend))
        .expect("captured backend")
        .get("cases")
        .and_then(Value::as_array)
        .expect("captured mappings");
    assert_eq!(
        cases
            .iter()
            .map(|case| case.get("mapping").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        MAPPINGS.map(Some)
    );
    let expected = cases
        .iter()
        .find(|case| case.get("mapping").and_then(Value::as_str) == Some(mapping))
        .expect("captured mapping");
    let operations = expected.get("operations").expect("captured operations");
    assert_eq!(
        operations
            .as_array()
            .expect("captured operations")
            .iter()
            .map(|operation| operation.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        OPERATIONS.map(Some)
    );
    let failures = expected
        .get("failures")
        .and_then(Value::as_array)
        .expect("captured failures");
    assert_eq!(failures.len(), 6);
    let fixture = Fixture::new(raw, mapping, database).await?;
    match scenario {
        contract::Scenario::Operations => assert_eq!(
            &fixture.operations().await?,
            operations,
            "{backend}/{mapping}"
        ),
        contract::Scenario::Failure { operation, phase } => {
            let observed = fixture.failure(operation, phase).await?;
            let name = observed.get("name").expect("observed failure name");
            let expected = failures
                .iter()
                .find(|failure| failure.get("name") == Some(name))
                .expect("captured failure");
            assert_eq!(&observed, expected, "{backend}/{mapping}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_display_mappings_match_complete_upstream_operations_and_errors() -> AuthResult<()> {
    for mapping in MAPPINGS {
        for scenario in contract::Scenario::ALL {
            check(
                Arc::new(EphemeralStore::new(Arc::new(contract::config()))),
                "memory",
                mapping,
                None,
                scenario,
            )
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_display_mappings_match_complete_upstream_operations_and_errors()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for mapping in MAPPINGS {
        for scenario in contract::Scenario::ALL {
            if mapping == "renamed" {
                let (store, database) =
                    display_fixture::sqlite::<display_fixture::renamed::Model>(contract::config())
                        .await;
                check(
                    Arc::new(store),
                    "sqlite",
                    mapping,
                    Some(&database),
                    scenario,
                )
                .await?;
                database.close().await?;
            } else {
                let (store, database) =
                    display_fixture::sqlite::<display_fixture::default::Model>(contract::config())
                        .await;
                check(
                    Arc::new(store),
                    "sqlite",
                    mapping,
                    Some(&database),
                    scenario,
                )
                .await?;
                database.close().await?;
            }
        }
    }
    Ok(())
}
