#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;

pub(super) struct NativeStorage {
    synchronous_storage: bool,
    cache: Mutex<indexmap::IndexMap<String, FieldValue>>,
    observer: Observer,
    original: FieldValue,
    index: FieldValue,
    batch: bool,
    reject: bool,
    reads: Mutex<usize>,
}

impl NativeStorage {
    pub(super) fn new(
        scenario: &Json,
        roots: &FieldMap,
        original: &FieldValue,
        observer: Observer,
        synchronous_storage: bool,
    ) -> AuthResult<Self> {
        let batch = scenario["operation"] == "batch-delete";
        let index = roots.get("index").unwrap().clone();
        let initial = if batch {
            FieldValue::from(vec![
                reference("target", 60_000),
                reference("retained", 90_000),
            ])
            .stringify_native()?
        } else {
            index.clone()
        };
        let mut cache = indexmap::IndexMap::from([(INDEX.into(), initial)]);
        for (token, expiry) in [
            ("target", 60_000),
            ("retained", 90_000),
            ("concurrent", 180_000),
        ] {
            let value: FieldValue = FieldMap::from([
                ("session".into(), session(token, expiry).into()),
                ("user".into(), user().into()),
            ])
            .into();
            let _ = cache.insert(token.into(), value.stringify_native()?);
        }
        Ok(Self {
            synchronous_storage,
            cache: Mutex::new(cache),
            observer,
            original: original.clone(),
            index,
            batch,
            reject: scenario["reject"] == "index",
            reads: Mutex::new(0),
        })
    }

    pub(super) fn value(&self, key: &str) -> FieldValue {
        self.cache
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .unwrap_or(FieldValue::Null)
    }

    pub(super) fn snapshot(
        &self,
        inner: &EphemeralStore,
        roots: &FieldMap,
        initial: Option<&FieldValue>,
    ) -> AuthResult<Json> {
        let cache = self.cache.lock().unwrap();
        let entries: Vec<FieldValue> = cache
            .iter()
            .map(|(key, value)| vec![key.clone().into(), value.clone()].into())
            .collect();
        let present: Vec<FieldValue> = [INDEX, "target", "retained", "concurrent"]
            .into_iter()
            .map(|key| vec![key.into(), cache.contains_key(key).into()].into())
            .collect();
        let mut state = FieldMap::from([
            ("database".into(), database_rows(inner)?),
            ("cache".into(), entries.into()),
            ("roots".into(), roots.clone().into()),
            ("storageHas".into(), present.into()),
        ]);
        if let Some(initial) = initial {
            let _ = state.insert("indexReads".into(), (*self.reads.lock().unwrap()).into());
            let _ = state.insert(
                "indexSameOriginal".into(),
                cache
                    .get(INDEX)
                    .is_some_and(|value| value.strict_equals(initial))
                    .into(),
            );
        }
        self.observer.lock().unwrap().observe(&state.into())
    }
}

impl NativeStorage {
    fn read(&self, key: &FieldValue) -> AuthResult<Option<FieldValue>> {
        let key: String = key.decode()?;
        if key == INDEX {
            let mut reads = self.reads.lock().unwrap();
            *reads += 1;
            if *reads == 2 && self.batch {
                let _ = self
                    .cache
                    .lock()
                    .unwrap()
                    .insert(key.clone(), self.index.clone());
                let mut observer = self.observer.lock().unwrap();
                let value = observer.observe(&self.index)?;
                observer.record("concurrent:index-replacement", [("value".into(), value)]);
            }
        }
        let value = match self.value(&key) {
            FieldValue::Undefined | FieldValue::Null => FieldValue::Null,
            value => value,
        };
        let mut observer = self.observer.lock().unwrap();
        let observed = observer.observe(&value)?;
        observer.record(
            "storage.get",
            [("key".into(), key.into()), ("value".into(), observed)],
        );
        Ok(Some(value))
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
        if self.reject && key == INDEX && value.is_undefined() {
            let error = observer.observe(&self.original)?;
            observer.record(
                "storage.reject",
                [("key".into(), key.into()), ("error".into(), error)],
            );
            return Err(AuthError::from_thrown(self.original.clone()));
        }
        let _ = self.cache.lock().unwrap().insert(key, value.clone());
        Ok(())
    }

    fn remove(&self, key: &str) -> AuthResult<()> {
        self.observer
            .lock()
            .unwrap()
            .record("storage.delete", [("key".into(), key.into())]);
        let _ = self.cache.lock().unwrap().shift_remove(key);
        Ok(())
    }
}

#[async_trait]
impl SecondaryStorage for NativeStorage {
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

    async fn get(&self, key: &str) -> AuthResult<Option<Json>> {
        self.get_native(&key.into())
            .await?
            .map(|value| value.decode())
            .transpose()
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
            "Session write contract does not consume verification values",
        ))
    }
}
