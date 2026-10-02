use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{Json, Router, routing::post};
use better_auth::{
    AuthError, AuthResult, AuthSchema, BetterAuth,
    plugins::api_key::{ApiKeyConfig, ApiKeyPlugin, ApiKeyStorage, KeyExpirationConfig},
    store::SecondaryStorage,
};
use serde_json::{Value, json};

struct Entry {
    value: String,
    ttl: Option<u64>,
    expires: Option<Instant>,
}
struct State {
    entries: BTreeMap<String, Entry>,
    failure: Option<String>,
}
struct Storage {
    state: Mutex<State>,
    blocked: tokio::sync::watch::Sender<bool>,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                entries: BTreeMap::new(),
                failure: None,
            }),
            blocked: tokio::sync::watch::channel(false).0,
        }
    }
}

impl Storage {
    fn check(state: &State, operation: &str, key: &str) -> AuthResult<()> {
        if key.starts_with("api-key:") && state.failure.as_deref() == Some(operation) {
            Err(AuthError::internal("compat secondary storage failure"))
        } else {
            Ok(())
        }
    }
    fn control(&self, body: &Value) -> Vec<Value> {
        let mut state = self.state.lock().unwrap();
        match body["action"].as_str() {
            Some("failure") => state.failure = body["operation"].as_str().map(str::to_owned),
            Some("evict") => state.entries.retain(|key, _| !key.starts_with("api-key:")),
            Some("delete") => {
                let _ = state.entries.remove(body["key"].as_str().unwrap());
            }
            Some("put") => {
                let _ = state.entries.insert(
                    body["key"].as_str().unwrap().into(),
                    Entry {
                        value: body["value"].as_str().unwrap().into(),
                        ttl: None,
                        expires: None,
                    },
                );
            }
            Some("block") => {
                let _ = self
                    .blocked
                    .send_replace(body["blocked"].as_bool().unwrap());
            }
            _ => {}
        }
        state
            .entries
            .iter()
            .filter(|(key, entry)| {
                key.starts_with("api-key:")
                    && entry.expires.is_none_or(|expiry| expiry > Instant::now())
            })
            .map(|(key, entry)| json!({"key":key,"value":entry.value,"ttl":entry.ttl}))
            .collect()
    }
    fn reset(&self) {
        let mut state = self.state.lock().unwrap();
        state.entries.clear();
        state.failure = None;
        let _ = self.blocked.send_replace(false);
    }
}

#[async_trait::async_trait]
impl SecondaryStorage for Storage {
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        let mut state = self.state.lock().unwrap();
        Self::check(&state, "get", key)?;
        Ok(state
            .entries
            .remove(key)
            .filter(|entry| entry.expires.is_none_or(|expiry| expiry > Instant::now()))
            .map(|entry| Value::String(entry.value)))
    }

    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        let state = self.state.lock().unwrap();
        Self::check(&state, "get", key)?;
        Ok(state
            .entries
            .get(key)
            .filter(|entry| entry.expires.is_none_or(|expiry| expiry > Instant::now()))
            .map(|entry| Value::String(entry.value.clone())))
    }
    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> AuthResult<()> {
        Self::check(&self.state.lock().unwrap(), "set", key)?;
        if key.starts_with("api-key:") {
            let mut blocked = self.blocked.subscribe();
            while *blocked.borrow_and_update() {
                blocked
                    .changed()
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
            }
        }
        let _ = self.state.lock().unwrap().entries.insert(
            key.into(),
            Entry {
                value: value.into(),
                ttl,
                expires: ttl.map(|ttl| Instant::now() + Duration::from_secs(ttl)),
            },
        );
        Ok(())
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        let mut state = self.state.lock().unwrap();
        Self::check(&state, "delete", key)?;
        let _ = state.entries.remove(key);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub(super) struct ApiKeyStorageFixture {
    global: Arc<Storage>,
    custom: Arc<Storage>,
}

impl ApiKeyStorageFixture {
    pub(super) fn secondary_storage(&self) -> Arc<dyn SecondaryStorage> {
        self.global.clone()
    }
    pub(super) fn plugin(&self, plugin: ApiKeyPlugin) -> ApiKeyPlugin {
        [
            ApiKeyConfig {
                config_id: "cache".into(),
                storage: ApiKeyStorage::SecondaryStorage,
                enable_metadata: true,
                key_expiration: KeyExpirationConfig {
                    min_expires_in: 0.0,
                    ..Default::default()
                },
                ..Default::default()
            },
            ApiKeyConfig {
                config_id: "fallback".into(),
                storage: ApiKeyStorage::SecondaryStorage,
                fallback_to_database: true,
                enable_metadata: true,
                ..Default::default()
            },
            ApiKeyConfig {
                config_id: "custom".into(),
                storage: ApiKeyStorage::SecondaryStorage,
                custom_storage: Some(self.custom.clone()),
                enable_metadata: true,
                ..Default::default()
            },
            ApiKeyConfig {
                config_id: "custom-fallback".into(),
                storage: ApiKeyStorage::SecondaryStorage,
                custom_storage: Some(self.custom.clone()),
                fallback_to_database: true,
                ..Default::default()
            },
            ApiKeyConfig {
                config_id: "deferred".into(),
                storage: ApiKeyStorage::SecondaryStorage,
                defer_updates: true,
                ..Default::default()
            },
            ApiKeyConfig {
                config_id: "database-custom".into(),
                storage: ApiKeyStorage::Database,
                custom_storage: Some(self.custom.clone()),
                ..Default::default()
            },
        ]
        .into_iter()
        .fold(plugin, |plugin, config| plugin.configuration(config))
    }
    pub(super) fn reset(&self) {
        self.global.reset();
        self.custom.reset();
    }
    pub(super) fn router<S: AuthSchema>(&self, auth: Arc<BetterAuth<S>>) -> Router {
        let fixture = self.clone();
        Router::new().route(
            "/__test/api-key-storage",
            post(move |Json(body): Json<Value>| {
                let fixture = fixture.clone();
                let auth = auth.clone();
                async move {
                    let storage = if body["backend"] == "custom" {
                        &fixture.custom
                    } else {
                        &fixture.global
                    };
                    if body["action"] == "delete-database" {
                        auth.store()
                            .delete_api_key(&body["id"].as_str().unwrap().into())
                            .await
                            .unwrap();
                    }
                    let entries = storage.control(&body);
                    let rows = if let Some(reference) = body["referenceId"].as_str() {
                        auth.store()
                            .list_api_keys_by_reference(reference)
                            .await
                            .unwrap()
                    } else {
                        Vec::new()
                    };
                    #[derive(serde::Serialize)]
                    struct Snapshot<T> {
                        entries: Vec<Value>,
                        rows: T,
                    }
                    Json(Snapshot { entries, rows })
                }
            }),
        )
    }
}
