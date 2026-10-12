#![expect(
    clippy::panic_in_result_fn,
    reason = "The regression compares complete verification results and retained error identities while setup failures propagate."
)]

use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthResult, FieldFunction, FieldMap, FieldObject,
    FieldValue,
    background::{BackgroundTask, BackgroundTasks},
    store::{EphemeralStore, SecondaryStorage, schema::EntityRole},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
    task::Poll,
    time::Duration,
};
use tokio::sync::Notify;

use crate::plugins::api_key::{
    ApiKeyConfig, ApiKeyPlugin, ApiKeyStorage, ApiKeyVerificationError, VerifyApiKey,
};

const HASH: &str = "api-key:usage-secret";
const BY_ID: &str = "api-key:by-id:usage-key";
const OLD_REF: &str = "api-key:by-ref:owner";
const FRESH_REF: &str = "api-key:by-ref:fresh-owner";

use crate::plugins::test_helpers::native_observation::{NativeObservation, assert_replay};
use crate::plugins::test_helpers::native_source as source;
use source::source_value;

#[path = "usage_tests/rate_limit.rs"]
mod rate_limit;
#[path = "usage_tests/rate_limit_contract.rs"]
mod rate_limit_contract;
#[path = "usage_tests/success.rs"]
mod success;

fn lock<T>(mutex: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| AuthError::internal("Usage cache observation lock poisoned"))
}

fn seed() -> Value {
    json!({
        "id":"usage-key", "name":"Before eviction", "start":null, "prefix":null,
        "key":"usage-secret", "referenceId":"owner", "configId":"default",
        "refillInterval":null, "refillAmount":null, "lastRefillAt":null,
        "enabled":true, "rateLimitEnabled":false, "rateLimitTimeWindow":60000,
        "rateLimitMax":3, "requestCount":0, "remaining":5, "lastRequest":null,
        "expiresAt":null, "createdAt":"2030-01-02T03:04:05.000Z",
        "updatedAt":"2030-01-02T03:04:05.000Z", "permissions":null, "metadata":null,
    })
}

struct Cache {
    pending: bool,
    fresh: Option<String>,
    values: Mutex<BTreeMap<String, String>>,
    reads: Mutex<Vec<String>>,
    events: Mutex<Vec<Value>>,
    started: Notify,
    release: Notify,
}

impl Cache {
    fn new(pending: bool) -> Self {
        Self {
            pending,
            fresh: None,
            values: Mutex::new(BTreeMap::from([
                (HASH.into(), seed().to_string()),
                ("api-key:by-id:usage-key".into(), seed().to_string()),
                ("api-key:by-ref:owner".into(), "[\"usage-key\"]".into()),
            ])),
            reads: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            started: Notify::new(),
            release: Notify::new(),
        }
    }

    fn successful(pending: bool, fresh: &Value) -> AuthResult<Self> {
        let mut cache = Self::new(pending);
        cache.fresh = Some(serde_json::to_string(fresh)?);
        let _ = lock(&cache.values)?.insert(FRESH_REF.into(), "[\"peer\"]".into());
        Ok(cache)
    }

    fn entries(&self) -> AuthResult<Value> {
        let values = lock(&self.values)?;
        assert_eq!(values.len(), 4);
        [HASH, BY_ID, OLD_REF, FRESH_REF]
            .into_iter()
            .map(|key| {
                let value = values
                    .get(key)
                    .ok_or_else(|| AuthError::internal("Expected complete cache key"))?;
                Ok(json!([key, value]))
            })
            .collect::<AuthResult<Vec<_>>>()
            .map(Into::into)
    }
}

#[async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        if self.fresh.is_none() {
            assert_eq!(key, HASH);
        }
        lock(&self.events)?.push(json!(["get", key]));
        let read = {
            let mut reads = lock(&self.reads)?;
            reads.push(key.into());
            reads.len()
        };
        if key == HASH && read == 2 {
            if self.fresh.is_none() {
                let _ = lock(&self.values)?.remove(HASH);
            }
            self.started.notify_one();
            if self.pending {
                self.release.notified().await;
            }
            if let Some(fresh) = &self.fresh {
                return Ok(Some(fresh.clone().into()));
            }
        }
        Ok(lock(&self.values)?.get(key).cloned().map(Value::String))
    }

    async fn set_native(
        &self,
        key: &FieldValue,
        value: &FieldValue,
        ttl: Option<f64>,
    ) -> AuthResult<()> {
        if self.fresh.is_none() {
            return Err(AuthError::internal(
                "A missing fresh key must not be recreated",
            ));
        }
        let (FieldValue::String(key), FieldValue::String(value)) = (key, value) else {
            return Err(AuthError::internal(
                "Usage cache writes must retain string keys and serialized records",
            ));
        };
        let ttl =
            NativeObservation::default().observe(&ttl.map_or(FieldValue::Undefined, Into::into))?;
        lock(&self.events)?.push(json!(["set", key, value, ttl]));
        let _ = lock(&self.values)?.insert(key.clone(), value.clone());
        Ok(())
    }

    async fn delete(&self, _: &str) -> AuthResult<()> {
        Err(AuthError::internal(
            "A missing fresh key must not delete its other indexes",
        ))
    }

    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<Value>> {
        Err(AuthError::internal(
            "Usage must not consume verification storage",
        ))
    }
}

#[derive(Default)]
struct Observation {
    logs: Mutex<Vec<Vec<FieldValue>>>,
    tasks: Mutex<Vec<BackgroundTask>>,
}

impl Observation {
    fn config(self: &Arc<Self>) -> AuthConfig {
        let mut config = AuthConfig::default();
        config.logger = FieldObject::from(FieldMap::from([
            ("level".into(), "error".into()),
            (
                "log".into(),
                FieldFunction::contextual({
                    let state = self.clone();
                    move |_, arguments| {
                        lock(&state.logs)?.push(arguments.to_vec());
                        Ok(FieldValue::Undefined)
                    }
                })
                .into(),
            ),
        ]))
        .into();
        config.advanced.background_tasks = Some(BackgroundTasks::new({
            let state = self.clone();
            move |task| {
                lock(&state.tasks)?.push(task);
                Ok(())
            }
        }));
        config
    }

    async fn settle(&self, deferred: bool) -> AuthResult<()> {
        let tasks = std::mem::take(&mut *lock(&self.tasks)?);
        assert_eq!(tasks.len(), if deferred { 2 } else { 0 });
        for (index, task) in tasks.into_iter().enumerate() {
            let completion = tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .map_err(|_| AuthError::internal("Deferred cache miss did not settle"))?
                .map_err(|error| {
                    AuthError::internal(format!("Unexpected task failure: {error}"))
                })??;
            assert!(completion.strict_equals(&if index == 0 {
                FieldValue::Null
            } else {
                FieldValue::Undefined
            }));
        }
        Ok(())
    }
}

// Source assertions live in contracts/api-key-usage-miss.test.ts; existing cache and Logger contracts cover storage failures.
#[tokio::test]
async fn fresh_cache_miss_rejects_sync_verification_and_resolves_deferred_usage() -> AuthResult<()>
{
    for deferred in [false, true] {
        for pending in [false, true] {
            let cache = Arc::new(Cache::new(pending));
            let before = lock(&cache.values)?.clone();
            let state = Arc::new(Observation::default());
            let config = Arc::new(state.config());
            let store = Arc::new(EphemeralStore::from_storage(
                config.clone(),
                ["user", "session", "account", "verification", "apikey"]
                    .map(|name| (name.into(), Vec::new())),
            )?);
            let context = AuthContext::new(config, store.clone())?;
            let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
                storage: ApiKeyStorage::SecondaryStorage,
                custom_storage: Some(cache.clone()),
                disable_key_hashing: true,
                defer_updates: deferred,
                ..Default::default()
            });
            let input = VerifyApiKey {
                key: "usage-secret",
                config_id: None,
                permissions: None,
            };
            let earliest = chrono::Utc::now().timestamp_millis();
            let mut verify = Box::pin(plugin.verify_api_key(&input, &context));
            let first = std::future::poll_fn(|cx| Poll::Ready(verify.as_mut().poll(cx))).await;
            tokio::time::timeout(Duration::from_secs(5), cache.started.notified())
                .await
                .map_err(|_| AuthError::internal("Verification did not reread the hashed key"))?;
            if pending && !deferred {
                assert!(first.is_pending());
            }
            if pending {
                assert!(lock(&state.logs)?.is_empty());
            }
            if !deferred {
                cache.release.notify_one();
            }
            let result = match first {
                Poll::Ready(result) => result,
                Poll::Pending => tokio::time::timeout(Duration::from_secs(5), verify)
                    .await
                    .map_err(|_| {
                        AuthError::internal("Deferred verification waited for its cache reread")
                    })?,
            };
            let latest = chrono::Utc::now().timestamp_millis();
            cache.release.notify_one();
            state.settle(deferred).await?;
            if deferred {
                let key = result.map_err(|error| AuthError::internal(error.to_string()))?;
                for value in [key.last_request.field_value(), key.updated_at.field_value()] {
                    let milliseconds = better_auth_core::query::field_date(&value)?.milliseconds();
                    assert!((earliest as f64..=latest as f64).contains(&milliseconds));
                }
                let actual = serde_json::to_value(&key)?;
                let mut expected = seed();
                let object = expected
                    .as_object_mut()
                    .ok_or_else(|| AuthError::internal("Expected seeded object"))?;
                let _ = object.remove("key");
                let _ = object.insert("remaining".into(), 4.into());
                let _ = object.insert(
                    "lastRequest".into(),
                    serde_json::to_value(&key.last_request)?,
                );
                let _ = object.insert("updatedAt".into(), serde_json::to_value(&key.updated_at)?);
                assert_eq!(actual, expected);
                assert!(lock(&state.logs)?.is_empty());
            } else {
                let error = match result {
                    Err(ApiKeyVerificationError::Rejected(error)) => error,
                    other => {
                        return Err(AuthError::internal(format!(
                            "Expected source API error, got {other:?}"
                        )));
                    }
                };
                assert_eq!(error.status_code()?.json()?, Some(500.into()));
                let cause = error
                    .raw_value()
                    .ok_or_else(|| AuthError::internal("Expected native API error"))?;
                let logs = lock(&state.logs)?;
                let [arguments] = logs.as_slice() else {
                    return Err(AuthError::internal("Expected one validation error log"));
                };
                let [level, message, logged] = arguments.as_slice() else {
                    return Err(AuthError::internal(
                        "Expected complete validation log arguments",
                    ));
                };
                assert!(level.strict_equals(&"error".into()));
                assert!(message.strict_equals(&"Failed to validate API key:".into()));
                assert!(logged.strict_equals(cause));
                assert_eq!(
                    ApiKeyVerificationError::Rejected(error)
                        .into_response()?
                        .body
                        .json()?,
                    Some(json!({
                        "valid":false,"key":null,"error":{"message":"Failed to update API key","code":"FAILED_TO_UPDATE_API_KEY"}
                    }))
                );
            }
            let mut expected_storage = before;
            let _ = expected_storage.remove(HASH);
            assert_eq!(*lock(&cache.values)?, expected_storage);
            assert_eq!(*lock(&cache.reads)?, vec![HASH, HASH]);
            for role in [
                EntityRole::User,
                EntityRole::Session,
                EntityRole::Account,
                EntityRole::Verification,
                EntityRole::ApiKey,
            ] {
                assert!(store.storage_rows(role)?.is_empty());
            }
        }
    }
    Ok(())
}
