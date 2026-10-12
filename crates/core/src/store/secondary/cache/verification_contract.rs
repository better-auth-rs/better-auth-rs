#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Pinned native contracts must fail immediately when the fixture shape or setup changes."
)]

use crate::observability::{LogArgument, LogLevel, LogSink};
use crate::store::database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks};
use crate::store::schema::EntityRole;
use crate::store::secondary::SecondaryStore;
use crate::store::{EphemeralStore, SecondaryStorage, StatelessSchema, VerificationStore};
use crate::{AuthConfig, AuthContext, AuthError, AuthResult, FieldMap, FieldValue};
use async_trait::async_trait;
use serde_json::{Value as Json, json};
use std::sync::{Arc, Mutex};

mod object;
use crate::native_test_observation as observation;
use crate::native_test_replay_failures::ReplayFailures;
mod read_write;
mod values;

use observation::{NativeObservation, assert_replay};

const NOW: i64 = 2_000_000_000_000;
const TARGET: &str = "verification:subject";
const RETAINED: &str = "verification:retained";
type Observer = Arc<Mutex<NativeObservation>>;
type Entries = Arc<Mutex<indexmap::IndexMap<String, FieldValue>>>;

fn date(offset: i64) -> FieldValue {
    crate::FieldDate::from_milliseconds((NOW + offset) as f64).into()
}

fn database(inner: &EphemeralStore) -> AuthResult<FieldValue> {
    Ok([
        ("user", EntityRole::User),
        ("session", EntityRole::Session),
        ("account", EntityRole::Account),
        ("verification", EntityRole::Verification),
    ]
    .into_iter()
    .map(|(name, role)| {
        Ok((
            name.into(),
            inner
                .storage_rows(role)?
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        ))
    })
    .collect::<AuthResult<FieldMap>>()?
    .into())
}

struct Hooks(Observer);

impl Hooks {
    fn record(&self, phase: &str, data: &crate::VerificationView) -> AuthResult<()> {
        let mut observer = self.0.lock().unwrap();
        let data = observer.observe(&data.fields()?.into())?;
        observer.record(phase, [("data".into(), data)]);
        Ok(())
    }
}

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Hooks {
    async fn before_delete_verification(
        &self,
        data: &crate::VerificationView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("hook:delete:before", data)?;
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_verification(
        &self,
        data: &crate::VerificationView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.record("hook:delete:after", data)
    }
}

struct Storage {
    entries: Entries,
    observer: Observer,
    input: FieldValue,
}

impl Storage {
    fn cache(&self) -> FieldValue {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(|(key, value)| vec![key.clone().into(), value.clone()].into())
            .collect::<Vec<FieldValue>>()
            .into()
    }

    fn keys(&self) -> Vec<String> {
        self.entries.lock().unwrap().keys().cloned().collect()
    }

    fn target_present(&self) -> bool {
        self.entries.lock().unwrap().contains_key(TARGET)
    }

    fn retained_is(&self, expected: &FieldValue) -> bool {
        self.entries
            .lock()
            .unwrap()
            .get(RETAINED)
            .is_some_and(|value| value.strict_equals(expected))
    }
}

#[async_trait]
impl SecondaryStorage for Storage {
    async fn get(&self, _: &str) -> AuthResult<Option<Json>> {
        Err(AuthError::internal(
            "Verification consumption must use atomic get_and_delete",
        ))
    }

    async fn set_native(
        &self,
        key: &FieldValue,
        value: &FieldValue,
        ttl: Option<f64>,
    ) -> AuthResult<()> {
        let mut observer = self.observer.lock().unwrap();
        let observed = observer.observe(value)?;
        let ttl = observer.observe(&ttl.map_or(FieldValue::Undefined, FieldValue::from))?;
        observer.record(
            "storage.set",
            [
                ("key".into(), key.decode()?),
                ("value".into(), observed),
                ("ttl".into(), ttl),
            ],
        );
        let _ = self
            .entries
            .lock()
            .unwrap()
            .insert(key.decode()?, value.clone());
        Ok(())
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.observer
            .lock()
            .unwrap()
            .record("storage.delete", [("key".into(), key.into())]);
        let _ = self.entries.lock().unwrap().shift_remove(key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Json>> {
        self.get_and_delete_native(&key.into())
            .await?
            .map(|value| value.decode())
            .transpose()
    }

    async fn get_and_delete_native(&self, key: &FieldValue) -> AuthResult<Option<FieldValue>> {
        let key: String = key.decode()?;
        let (removed, remaining) = {
            let mut entries = self.entries.lock().unwrap();
            let removed = entries.shift_remove(&key);
            (removed, entries.keys().cloned().collect::<Vec<_>>())
        };
        let same = removed
            .as_ref()
            .unwrap_or(&FieldValue::Null)
            .strict_equals(&self.input);
        self.observer.lock().unwrap().record(
            "storage.getAndDelete",
            [
                ("key".into(), key.into()),
                ("present".into(), removed.is_some().into()),
                ("sameInput".into(), same.into()),
                ("remainingKeys".into(), json!(remaining)),
            ],
        );
        Ok(removed)
    }
}

struct Logger {
    observer: Observer,
    original: FieldValue,
}

impl LogSink for Logger {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> crate::AuthResult<()> {
        assert_eq!(level, LogLevel::Error);
        assert_eq!(arguments.len(), 1);
        let argument = arguments
            .first()
            .and_then(|argument| match argument {
                LogArgument::Native(value) => Some(*value),
                _ => None,
            })
            .unwrap();
        let argument_keys = argument
            .enumerable_fields()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let error = argument.model_property("error").unwrap();
        let observed = FieldMap::from([
            ("name".into(), error.model_property("name").unwrap()),
            ("message".into(), error.model_property("message").unwrap()),
        ]);
        let mut observer = self.observer.lock().unwrap();
        let observed = observer.observe(&observed.into()).unwrap();
        observer.record(
            "logger:error",
            [
                ("message".into(), message.to_string().into()),
                ("argumentCount".into(), arguments.len().into()),
                ("argumentKeys".into(), json!(argument_keys)),
                (
                    "sameOriginal".into(),
                    error.strict_equals(&self.original).into(),
                ),
                ("error".into(), observed),
            ],
        );
        Ok(())
    }
}

async fn capture(name: &str, in_transaction: bool) -> AuthResult<Json> {
    let entries = Entries::default();
    let observer = Observer::default();
    let input = values::Input::new(name, entries.clone(), observer.clone())?;
    let retained: FieldValue = FieldMap::from([
        ("id".into(), "retained-row".into()),
        ("value".into(), "unchanged".into()),
        ("expiresAt".into(), date(90_000)),
        (
            "nested".into(),
            FieldMap::from([
                ("ownUndefined".into(), FieldValue::Undefined),
                ("order".into(), vec!["first".into(), "last".into()].into()),
            ])
            .into(),
        ),
    ])
    .into();
    entries.lock().unwrap().extend([
        (TARGET.into(), input.value.clone()),
        (RETAINED.into(), retained.clone()),
    ]);
    let cache = Arc::new(Storage {
        entries,
        observer: observer.clone(),
        input: input.value.clone(),
    });
    let mut config = AuthConfig::default();
    config.verification.store_in_database = false;
    config.logger = crate::LoggerConfig {
        level: Some(LogLevel::Debug),
        log: Some(Arc::new(Logger {
            observer: observer.clone(),
            original: input.original.clone(),
        })),
        ..Default::default()
    }
    .into();
    config
        .initialize_logger()
        .expect("fixture initialization succeeds");
    let config = Arc::new(config);
    let inner = Arc::new(
        EphemeralStore::new(config.clone()).with_hooks(vec![Arc::new(Hooks(observer.clone()))]),
    );
    let store = SecondaryStore::new(
        inner.clone(),
        cache.clone(),
        config.clone(),
        Default::default(),
    )?
    .with_clock(|| chrono::DateTime::from_timestamp_millis(NOW).unwrap());
    let context = AuthContext::new(config, inner.clone()).expect("fixture context initializes");
    let before = observer.lock().unwrap().observe(
        &FieldMap::from([
            ("database".into(), database(&inner)?),
            (
                "storageKeys".into(),
                cache
                    .keys()
                    .into_iter()
                    .map(FieldValue::from)
                    .collect::<Vec<_>>()
                    .into(),
            ),
            ("targetPresent".into(), cache.target_present().into()),
            ("retained".into(), retained.clone()),
            (
                "retainedSameObject".into(),
                cache.retained_is(&retained).into(),
            ),
        ])
        .into(),
    )?;
    let result = context
        .with_endpoint_context(|_| async {
            if in_transaction {
                crate::store::transaction(&store, |transaction| {
                    Box::pin(async move {
                        transaction
                            .consume_verification_by_identifier("subject")
                            .await
                    })
                })
                .await
            } else {
                store.consume_verification_by_identifier("subject").await
            }
        })
        .await
        .and_then(|value| {
            value.map_or(Ok(FieldValue::Null), |value| {
                value.fields().map(FieldValue::from)
            })
        });
    let returned = result
        .as_ref()
        .ok()
        .cloned()
        .unwrap_or(FieldValue::Undefined);
    let outcome = observer.lock().unwrap().outcome(result, &input.original)?;
    let identities = input.identities(&returned)?;
    let input_state = input.state()?;
    let after = observer.lock().unwrap().observe(
        &FieldMap::from([
            ("database".into(), database(&inner)?),
            ("cache".into(), cache.cache()),
            ("targetPresent".into(), cache.target_present().into()),
            (
                "retainedSameObject".into(),
                cache.retained_is(&retained).into(),
            ),
        ])
        .into(),
    )?;
    let observer = observer.lock().unwrap();
    Ok(
        json!({"before":before,"outcome":outcome,"events":observer.events,"identities":identities,
        "inputState":input_state,"after":after,"functionIds":observer.function_ids()}),
    )
}

#[tokio::test]
async fn verification_native_consumption_matches_complete_upstream_runtime() -> AuthResult<()> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/verification-consume-native-1.7.6.json");
    let fixture: Json = serde_json::from_str(&std::fs::read_to_string(path).unwrap())?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 27);
    let mut failures = ReplayFailures::default();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        for in_transaction in [false, true] {
            let actual = capture(name, in_transaction).await?;
            let label = format!("{name}/transaction={in_transaction}");
            failures.record(&label, || assert_replay(&actual, &case["runtime"], &label));
        }
    }
    failures.finish();
    Ok(())
}
