use super::trace::Trace;
use better_auth_core::{AuthResult, FieldValue, store::SecondaryStorage};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Mutex;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub(super) key: String,
    pub(super) value: String,
    pub(super) ttl: Option<f64>,
}

pub(super) struct Cache {
    trace: Trace,
    entries: Mutex<Vec<Entry>>,
}

impl Cache {
    pub(super) fn new(trace: Trace) -> Self {
        Self {
            trace,
            entries: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn entries(&self) -> Vec<Entry> {
        self.entries.lock().expect("lifecycle cache").clone()
    }
}

#[async_trait::async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        let value = self
            .entries
            .lock()
            .expect("lifecycle cache")
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| Value::String(entry.value.clone()));
        self.trace
            .callback(json!({"phase": "cache:get", "key": key, "value": value}));
        Ok(value)
    }

    async fn set_native(&self, key: &FieldValue, value: &str, ttl: Option<f64>) -> AuthResult<()> {
        let entry = Entry {
            key: key.decode()?,
            value: value.to_owned(),
            ttl,
        };
        self.trace.cache_set(entry.clone());
        // The upstream fixture retains insertion order and records TTLs without expiring entries.
        let mut entries = self.entries.lock().expect("lifecycle cache");
        if let Some(existing) = entries
            .iter_mut()
            .find(|existing| existing.key == entry.key)
        {
            *existing = entry;
        } else {
            entries.push(entry);
        }
        Ok(())
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.trace
            .callback(json!({"phase": "cache:delete", "key": key}));
        self.entries
            .lock()
            .expect("lifecycle cache")
            .retain(|entry| entry.key != key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        let mut entries = self.entries.lock().expect("lifecycle cache");
        let value = entries
            .iter()
            .position(|entry| entry.key == key)
            .map(|index| Value::String(entries.remove(index).value));
        self.trace
            .callback(json!({"phase": "cache:get-and-delete", "key": key, "value": value}));
        Ok(value)
    }
}
