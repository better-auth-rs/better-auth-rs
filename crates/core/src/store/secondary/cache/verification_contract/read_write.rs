#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::*;
use crate::store::database_hooks::{DatabaseHookUpdate, VerificationUpdate};

mod inputs;

struct UpdateHooks(Observer);

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for UpdateHooks {
    async fn before_update_verification(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        let mut observer = self.0.lock().unwrap();
        let data = observer.observe(&data.clone().into())?;
        observer.record("hook:update:before", [("data".into(), data)]);
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_verification(
        &self,
        data: Option<&crate::VerificationView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        let value = data.map_or(Ok(FieldValue::Null), |data| data.fields().map(Into::into))?;
        let mut observer = self.0.lock().unwrap();
        let data = observer.observe(&value)?;
        observer.record("hook:update:after", [("data".into(), data)]);
        Ok(())
    }
}

struct Cache {
    synchronous_storage: bool,
    entries: Entries,
    observer: Observer,
    set_error: Option<FieldValue>,
}

impl Cache {
    fn state(&self, inner: &EphemeralStore) -> AuthResult<FieldValue> {
        let entries = self
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|(key, value)| vec![key.clone().into(), value.clone()].into())
            .collect::<Vec<FieldValue>>();
        Ok(FieldMap::from([
            ("database".into(), database(inner)?),
            ("cache".into(), entries.into()),
        ])
        .into())
    }
}

impl Cache {
    fn read(&self, key: &FieldValue) -> AuthResult<Option<FieldValue>> {
        let key: String = key.decode()?;
        let value = self.entries.lock().unwrap().get(&key).cloned();
        let value = value.filter(|value| !value.is_null() && !value.is_undefined());
        let mut observer = self.observer.lock().unwrap();
        let observed = observer.observe(value.as_ref().unwrap_or(&FieldValue::Null))?;
        observer.record(
            "storage.get",
            [("key".into(), key.into()), ("value".into(), observed)],
        );
        Ok(value)
    }

    fn write(&self, key: &FieldValue, value: &FieldValue, ttl: Option<f64>) -> AuthResult<()> {
        let key: String = key.decode()?;
        let mut observer = self.observer.lock().unwrap();
        let observed = observer.observe(value)?;
        let ttl = observer.observe(&ttl.map_or(FieldValue::Undefined, FieldValue::from))?;
        observer.record(
            "storage.set",
            [
                ("key".into(), key.clone().into()),
                ("value".into(), observed),
                ("ttl".into(), ttl),
            ],
        );
        if let Some(original) = &self.set_error {
            let error = observer.observe(original)?;
            observer.record("storage.reject", [("error".into(), error)]);
            return Err(AuthError::from_thrown(original.clone()));
        }
        let _ = self.entries.lock().unwrap().insert(key, value.clone());
        Ok(())
    }

    fn remove(&self, key: &str) -> AuthResult<()> {
        self.observer
            .lock()
            .unwrap()
            .record("storage.delete", [("key".into(), key.into())]);
        let _ = self.entries.lock().unwrap().shift_remove(key);
        Ok(())
    }
}

#[async_trait]
impl SecondaryStorage for Cache {
    fn invoke_get_native(
        self: Arc<Self>,
        key: FieldValue,
    ) -> AuthResult<crate::store::SecondaryStorageFuture<Option<FieldValue>>> {
        if self.synchronous_storage {
            let value = self.read(&key)?;
            Ok(Box::pin(async move { Ok(value) }))
        } else {
            Ok(Box::pin(async move { self.get_native(&key).await }))
        }
    }

    fn invoke_set_native(
        self: Arc<Self>,
        key: FieldValue,
        value: FieldValue,
        ttl: Option<Option<f64>>,
    ) -> AuthResult<crate::store::SecondaryStorageFuture<()>> {
        assert!(ttl.is_some());
        if self.synchronous_storage {
            self.write(&key, &value, ttl.flatten())?;
            Ok(Box::pin(async { Ok(()) }))
        } else {
            Ok(Box::pin(async move {
                self.set_native(&key, &value, ttl.flatten()).await
            }))
        }
    }

    fn invoke_delete_native(
        self: Arc<Self>,
        key: FieldValue,
    ) -> AuthResult<crate::store::SecondaryStorageFuture<()>> {
        if self.synchronous_storage {
            self.remove(&key.decode::<String>()?)?;
            Ok(Box::pin(async { Ok(()) }))
        } else {
            Ok(Box::pin(async move { self.delete_native(&key).await }))
        }
    }

    async fn get(&self, _: &str) -> AuthResult<Option<Json>> {
        Err(AuthError::internal(
            "Verification must read the native cache value",
        ))
    }

    async fn get_native(&self, key: &FieldValue) -> AuthResult<Option<FieldValue>> {
        if self.synchronous_storage {
            return Err(AuthError::internal(
                "Synchronous storage must use the invocation interface",
            ));
        }
        self.read(key)
    }

    async fn set_native(
        &self,
        key: &FieldValue,
        value: &FieldValue,
        ttl: Option<f64>,
    ) -> AuthResult<()> {
        if self.synchronous_storage {
            return Err(AuthError::internal(
                "Synchronous storage must use the invocation interface",
            ));
        }
        self.write(key, value, ttl)
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        if self.synchronous_storage {
            return Err(AuthError::internal(
                "Synchronous storage must use the invocation interface",
            ));
        }
        self.remove(key)
    }

    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<Json>> {
        Err(AuthError::internal(
            "Read and update must not consume verification values",
        ))
    }
}

struct ParseLogger {
    observer: Observer,
    original: FieldValue,
}

impl LogSink for ParseLogger {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> crate::AuthResult<()> {
        assert_eq!(level, LogLevel::Error);
        let values = arguments
            .iter()
            .map(|argument| match argument {
                LogArgument::Native(value) => Ok((*value).clone()),
                _ => Err(AuthError::internal(
                    "Native JSON parsing must log the original native value",
                )),
            })
            .collect::<AuthResult<Vec<_>>>()
            .unwrap();
        let same = values
            .first()
            .unwrap()
            .model_property("error")
            .unwrap()
            .strict_equals(&self.original);
        let mut observer = self.observer.lock().unwrap();
        let arguments = observer.observe(&values.into()).unwrap();
        observer.record(
            "logger:error",
            [
                ("message".into(), message.to_string().into()),
                ("arguments".into(), arguments),
                ("sameOriginal".into(), same.into()),
            ],
        );
        Ok(())
    }
}

async fn capture(
    scenario: &Json,
    in_transaction: bool,
    synchronous_storage: bool,
) -> AuthResult<Json> {
    let name = scenario["name"].as_str().unwrap();
    let observer = Observer::default();
    let input = inputs::Input::new(name, scenario["input"].as_str().unwrap(), observer.clone())?;
    let entries = Entries::default();
    entries.lock().unwrap().extend([
        (TARGET.into(), input.value.clone()),
        ("unrelated".into(), "retained".into()),
    ]);
    let cache = Arc::new(Cache {
        synchronous_storage,
        entries,
        observer: observer.clone(),
        set_error: (scenario["input"] == "set-error").then(|| input.original.clone()),
    });
    let mut config = AuthConfig::default();
    config.verification.store_in_database = false;
    config.logger = crate::LoggerConfig {
        level: Some(LogLevel::Debug),
        log: Some(Arc::new(ParseLogger {
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
        EphemeralStore::new(config.clone())
            .with_hooks(vec![Arc::new(UpdateHooks(observer.clone()))]),
    );
    let store = crate::store::secondary::SecondaryStore::new(
        inner.clone(),
        cache.clone(),
        config.clone(),
        Default::default(),
    )?
    .with_clock(|| chrono::DateTime::from_timestamp_millis(NOW).unwrap());
    let context = AuthContext::new(config, inner.clone()).expect("fixture context initializes");
    let before = observer.lock().unwrap().observe(&cache.state(&inner)?)?;
    let update = input.patch();
    let find = scenario["operation"] == "find";
    let result = context
        .with_endpoint_context(|_| async {
            if in_transaction {
                crate::store::transaction(&store, move |transaction| {
                    Box::pin(async move {
                        if find {
                            transaction.find_verification_value("subject").await
                        } else {
                            transaction
                                .update_verification_value("subject", update)
                                .await
                        }
                    })
                })
                .await
            } else if find {
                store.find_verification_value("subject").await
            } else {
                store.update_verification_value("subject", update).await
            }
        })
        .await
        .map(|value| value.unwrap_or(FieldValue::Null));
    let returned = result
        .as_ref()
        .ok()
        .cloned()
        .unwrap_or(FieldValue::Undefined);
    let outcome = observer.lock().unwrap().outcome(result, &input.original)?;
    let identities = input.identities(&returned)?;
    let after = observer.lock().unwrap().observe(&cache.state(&inner)?)?;
    let observer = observer.lock().unwrap();
    Ok(json!({
        "before":before,"outcome":outcome,"events":observer.events,"identities":identities,
        "after":after,"functionIds":observer.function_ids(),
    }))
}

#[tokio::test]
async fn verification_native_read_and_update_match_complete_upstream_runtime() -> AuthResult<()> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/verification-native-read-write-1.7.6.json");
    let fixture: Json = serde_json::from_str(&std::fs::read_to_string(path).unwrap())?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 27);
    let mut failures = ReplayFailures::default();
    for case in cases {
        let scenario = &case["scenario"];
        let name = scenario["name"].as_str().unwrap();
        for in_transaction in [false, true] {
            for synchronous_storage in [false, true] {
                let actual = capture(scenario, in_transaction, synchronous_storage).await?;
                let label = format!(
                    "{name}/transaction={in_transaction}/synchronous={synchronous_storage}"
                );
                failures.record(&label, || assert_replay(&actual, &case["runtime"], &label));
            }
        }
    }
    failures.finish();
    Ok(())
}
