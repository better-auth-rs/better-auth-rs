#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;

pub(super) struct Storage {
    synchronous_storage: bool,
    cache: Mutex<indexmap::IndexMap<String, FieldValue>>,
    observer: Observer,
    references: Vec<FieldValue>,
    concurrent: FieldValue,
    batch: bool,
    reads: Mutex<usize>,
}

impl Storage {
    pub(super) fn new(
        scenario: &Json,
        values: &values::Values,
        observer: Observer,
        synchronous_storage: bool,
    ) -> AuthResult<Self> {
        let mut cache =
            indexmap::IndexMap::from([(INDEX.into(), values.initial_index.clone().into())]);
        for (token, expiration) in [
            ("target", 60_000),
            ("retained", 90_000),
            ("expired", -1_000),
            ("concurrent", 180_000),
        ] {
            let mut envelope = FieldMap::from([
                ("session".into(), session(token, expiration).into()),
                ("user".into(), user().into()),
            ]);
            if token == "target" {
                let _ = envelope.insert("discardedEnvelopeField".into(), "before".into());
            }
            let _ = cache.insert(
                token.into(),
                FieldValue::from(envelope).stringify()?.unwrap().into(),
            );
        }
        if let Some(root) = values.roots.get("root") {
            let _ = cache.insert(INDEX.into(), root.clone());
        }
        if let Some(envelope) = values.roots.get("envelope") {
            let _ = cache.insert("target".into(), envelope.clone());
        }
        if let Some(reference) = values.roots.get("reference") {
            let _ = cache.insert(INDEX.into(), vec![reference.clone()].into());
        }
        Ok(Self {
            synchronous_storage,
            cache: Mutex::new(cache),
            observer,
            references: values.references.clone(),
            concurrent: values.concurrent.clone(),
            batch: scenario["operation"] == "batch-delete",
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

    pub(super) fn snapshot(&self) -> FieldValue {
        self.cache
            .lock()
            .unwrap()
            .iter()
            .map(|(key, value)| FieldValue::from(vec![key.clone().into(), value.clone()]))
            .collect::<Vec<_>>()
            .into()
    }
}

impl Storage {
    fn read(&self, key: &FieldValue) -> AuthResult<Option<FieldValue>> {
        let key = key.display_utf16()?.to_utf8().unwrap();
        if key == INDEX {
            let mut reads = self.reads.lock().unwrap();
            *reads += 1;
            if *reads == 2 && self.batch {
                let mut references = self.references.clone();
                references.push(self.concurrent.clone());
                let value: FieldValue = FieldValue::from(references).stringify()?.unwrap().into();
                let _ = self
                    .cache
                    .lock()
                    .unwrap()
                    .insert(key.clone(), value.clone());
                let mut observer = self.observer.lock().unwrap();
                let value = observer.observe(&value)?;
                observer.record("concurrent:index-replacement", [("value".into(), value)]);
            }
        }
        let value = self.value(&key);
        let mut observer = self.observer.lock().unwrap();
        let observed = observer.observe(&value)?;
        observer.record(
            "cache.get",
            [("key".into(), key.into()), ("value".into(), observed)],
        );
        Ok(Some(value))
    }

    fn write(&self, key: &FieldValue, value: &FieldValue, ttl: Option<f64>) -> AuthResult<()> {
        let key = key.display_utf16()?.to_utf8().unwrap();
        let mut observer = self.observer.lock().unwrap();
        let observed = observer.observe(value)?;
        let ttl = observer.observe(&ttl.map_or(FieldValue::Undefined, FieldValue::from))?;
        observer.record(
            "cache.set",
            [
                ("key".into(), key.clone().into()),
                ("value".into(), observed),
                ("ttl".into(), ttl),
            ],
        );
        let _ = self.cache.lock().unwrap().insert(key, value.clone());
        Ok(())
    }

    fn remove(&self, key: &str) -> AuthResult<()> {
        self.observer
            .lock()
            .unwrap()
            .record("cache.delete", [("key".into(), key.into())]);
        let _ = self.cache.lock().unwrap().shift_remove(key);
        Ok(())
    }
}

#[async_trait]
impl SecondaryStorage for Storage {
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
            .map(|value| value.json())
            .transpose()
            .map(Option::flatten)
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

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Json>> {
        let value = self.get(key).await?;
        self.delete(key).await?;
        Ok(value)
    }
}
