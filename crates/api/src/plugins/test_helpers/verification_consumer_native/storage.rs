use super::*;
use async_trait::async_trait;
use better_auth_core::store::SecondaryStorage;

pub(crate) struct Storage {
    entries: Mutex<indexmap::IndexMap<String, FieldValue>>,
    state: Arc<State>,
}

impl Storage {
    pub(super) fn new(state: Arc<State>) -> Self {
        Self {
            entries: Mutex::default(),
            state,
        }
    }

    pub(crate) fn insert(&self, key: &str, value: FieldValue) -> AuthResult<()> {
        let _ = self.entries.lock().unwrap().insert(key.into(), value);
        Ok(())
    }

    pub(crate) fn get(&self, key: &str) -> AuthResult<Option<FieldValue>> {
        Ok(self.entries.lock().unwrap().get(key).cloned())
    }

    pub(crate) fn contains(&self, key: &str) -> AuthResult<bool> {
        Ok(self.entries.lock().unwrap().contains_key(key))
    }

    pub(super) fn snapshot(&self) -> AuthResult<FieldValue> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|(key, value)| vec![key.clone().into(), value.clone()].into())
            .collect::<Vec<FieldValue>>()
            .into())
    }
}

#[async_trait]
impl SecondaryStorage for Storage {
    async fn get(&self, _: &str) -> AuthResult<Option<Json>> {
        Err(AuthError::internal(
            "Consumer reads must preserve the native secondary value",
        ))
    }

    async fn get_native(&self, key: &FieldValue) -> AuthResult<Option<FieldValue>> {
        let key: String = key.decode()?;
        let result = self.get(&key)?;
        let observed = self
            .state
            .observe(result.as_ref().unwrap_or(&FieldValue::Null))?;
        self.state.record(
            "storage.get",
            [
                ("key".into(), key.into()),
                ("present".into(), result.is_some().into()),
                (
                    "sameRoot".into(),
                    result
                        .as_ref()
                        .is_some_and(|value| value.strict_equals(self.state.root.get().unwrap()))
                        .into(),
                ),
                ("value".into(), observed),
            ],
        );
        Ok(result)
    }

    async fn set_native(
        &self,
        key: &FieldValue,
        value: &FieldValue,
        ttl: Option<f64>,
    ) -> AuthResult<()> {
        let key: String = key.decode()?;
        self.state.record(
            "storage.set",
            [
                ("key".into(), key.clone().into()),
                ("value".into(), self.state.observe(value)?),
                (
                    "ttl".into(),
                    self.state
                        .observe(&ttl.map_or(FieldValue::Undefined, FieldValue::from))?,
                ),
            ],
        );
        self.insert(&key, value.clone())?;
        if self.state.scenario["fail"] == "set:after" {
            return self.state.fail("throw:storage.set:after");
        }
        Ok(())
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.state.record(
            "storage.delete",
            [
                ("key".into(), key.into()),
                ("present".into(), self.contains(key)?.into()),
            ],
        );
        let _ = self.entries.lock().unwrap().shift_remove(key);
        if self.state.scenario["fail"] == "delete:after"
            || self.state.scenario["fail"] == "session-delete:after" && key == "new-session"
        {
            return self.state.fail("throw:storage.delete:after");
        }
        Ok(())
    }

    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<Json>> {
        Err(AuthError::internal(
            "Consumer consumption must preserve the native secondary value",
        ))
    }

    async fn get_and_delete_native(&self, key: &FieldValue) -> AuthResult<Option<FieldValue>> {
        let key: String = key.decode()?;
        let (result, remaining) = {
            let mut entries = self.entries.lock().unwrap();
            let result = entries.shift_remove(&key);
            (result, entries.keys().cloned().collect::<Vec<_>>())
        };
        self.state.record(
            "storage.getAndDelete",
            [
                ("key".into(), key.into()),
                ("present".into(), result.is_some().into()),
                (
                    "sameRoot".into(),
                    result
                        .as_ref()
                        .is_some_and(|value| value.strict_equals(self.state.root.get().unwrap()))
                        .into(),
                ),
                ("remainingKeys".into(), json!(remaining)),
            ],
        );
        Ok(result)
    }
}
