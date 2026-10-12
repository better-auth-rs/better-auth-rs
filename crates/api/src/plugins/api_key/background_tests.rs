#![expect(
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    reason = "The contract asserts callback lengths before comparing original failures, catch ownership, and persistent records."
)]

use super::*;
use async_trait::async_trait;
use better_auth_core::{
    ApiKey, AuthConfig, FieldDate, FieldFunction, FieldMap, FieldObject, FromFieldMap,
    background::{BackgroundTask, BackgroundTasks},
    store::{ConsumeApiKeyResult, EphemeralStore, SecondaryStorage, schema::EntityRole},
};
use std::sync::{
    MutexGuard,
    atomic::{AtomicUsize, Ordering},
};

fn lock<T>(mutex: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| AuthError::internal("API Key background observation lock poisoned"))
}

struct Observation {
    producer: FieldValue,
    first_logger: FieldValue,
    second_logger: FieldValue,
    handler: FieldValue,
    events: Mutex<Vec<String>>,
    tasks: Mutex<Vec<BackgroundTask>>,
    logged: tokio::sync::Notify,
}

impl Observation {
    fn new() -> Arc<Self> {
        let marker = |owner: &str| FieldMap::from([("owner".into(), owner.into())]).into();
        Arc::new(Self {
            producer: marker("producer"),
            first_logger: marker("first logger"),
            second_logger: marker("second logger"),
            handler: marker("handler"),
            events: Mutex::new(Vec::new()),
            tasks: Mutex::new(Vec::new()),
            logged: tokio::sync::Notify::new(),
        })
    }

    fn config(
        self: &Arc<Self>,
        message: &'static str,
        handler: Option<bool>,
    ) -> AuthResult<AuthConfig> {
        let mut config = AuthConfig::default();
        let owner: FieldObject = FieldMap::from([("level".into(), "error".into())]).into();
        let expected: FieldValue = owner.clone().into();
        owner.set(
            "log",
            FieldFunction::contextual({
                let state = self.clone();
                move |receiver, arguments| {
                    assert!(receiver.strict_equals(&expected));
                    assert_eq!(arguments.len(), 3);
                    assert!(arguments[0].strict_equals(&"error".into()));
                    assert!(arguments[1].strict_equals(&message.into()));
                    let mut events = lock(&state.events)?;
                    let second = events.iter().any(|event| event == "logger:first");
                    let (input, output, event) = if second {
                        (&state.first_logger, &state.second_logger, "logger:second")
                    } else {
                        (&state.producer, &state.first_logger, "logger:first")
                    };
                    assert!(arguments[2].strict_equals(input));
                    events.push(event.into());
                    state.logged.notify_one();
                    Err(AuthError::from_thrown(output.clone()))
                }
            })
            .into(),
        )?;
        config.logger = owner.into();
        if let Some(throws) = handler {
            config.advanced.background_tasks = Some(BackgroundTasks::new({
                let state = self.clone();
                move |task| {
                    lock(&state.events)?.push("handler".into());
                    lock(&state.tasks)?.push(task);
                    if throws {
                        Err(AuthError::from_thrown(state.handler.clone()))
                    } else {
                        Ok(())
                    }
                }
            }));
        }
        Ok(config)
    }

    async fn task_error(&self, expected: &FieldValue) -> AuthResult<()> {
        let task = lock(&self.tasks)?
            .pop()
            .ok_or_else(|| AuthError::internal("Background handler did not retain its task"))?;
        let result = task
            .await
            .map_err(|error| AuthError::internal(format!("Unexpected join failure: {error}")))?;
        assert_failure(result, expected)
    }
}

fn assert_failure<T>(result: AuthResult<T>, expected: &FieldValue) -> AuthResult<()> {
    match result {
        Err(error) => assert!(error.into_thrown_value()?.strict_equals(expected)),
        Ok(_) => return Err(AuthError::internal("Expected the original native failure")),
    }
    Ok(())
}

#[test]
fn expired_cleanup_keeps_source_catch_layers_and_unowned_crud_behavior()
-> Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "plugins::api_key::background_tests::expired_cleanup_catch_child",
            "--ignored",
        ])
        .output()?;
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[tokio::test]
#[ignore = "The parent starts a fresh process because upstream cleanup state is module-global"]
async fn expired_cleanup_catch_child() -> AuthResult<()> {
    for (index, (defer, outer, retained)) in [
        (false, false, true),
        (false, true, true),
        (true, true, false),
        (true, true, true),
    ]
    .into_iter()
    .enumerate()
    {
        let state = Observation::new();
        let config = Arc::new(state.config(
            "Failed to delete expired API keys:",
            retained.then_some(false),
        )?);
        let expiration: FieldValue = FieldMap::from([(
            "valueOf".into(),
            FieldFunction::contextual({
                let state = state.clone();
                move |_, _| Err(AuthError::from_thrown(state.producer.clone()))
            })
            .into(),
        )])
        .into();
        let row = FieldMap::from([
            ("id".into(), "retained".into()),
            ("expiresAt".into(), expiration),
        ]);
        let store = Arc::new(EphemeralStore::from_storage(
            config.clone(),
            [("apikey".into(), vec![row.clone()])],
        )?);
        let clock =
            chrono::DateTime::from_timestamp_millis(2_000_000_000_000 + index as i64 * 10_000)
                .ok_or_else(|| {
                    AuthError::internal("Cleanup test clock is outside Chrono's range")
                })?;
        let ctx = AuthContext::new(config, store.clone())?.with_clock(move || clock);
        ApiKeyPlugin::with_config(ApiKeyConfig::default())
            .start_expired_cleanup(&ctx, defer, outer)
            .await?;
        if defer && retained {
            state.task_error(&state.second_logger).await?;
        } else {
            tokio::time::timeout(std::time::Duration::from_secs(5), state.logged.notified())
                .await
                .map_err(|_| {
                    AuthError::internal("API Key cleanup did not report its adapter error")
                })?;
            assert!(
                lock(&state.tasks)?.is_empty(),
                "CRUD and nondeferred hooks do not use the configured handler"
            );
        }
        let mut expected = Vec::new();
        if defer && retained {
            expected.push("handler".to_owned());
        }
        expected.push("logger:first".to_owned());
        if outer {
            expected.push("logger:second".to_owned());
        }
        assert_eq!(*lock(&state.events)?, expected);
        assert_eq!(
            store.plugin_storage_rows(EntityRole::ApiKey)?,
            [row.clone()]
        );
        let other = ctx
            .clone()
            .with_clock(move || clock + chrono::Duration::milliseconds(1));
        ApiKeyPlugin::with_config(ApiKeyConfig::default())
            .maybe_delete_expired(&other, false)
            .await?;
        assert_eq!(*lock(&state.events)?, expected);
        assert_eq!(store.plugin_storage_rows(EntityRole::ApiKey)?, [row]);
    }
    Ok(())
}

struct FailingCache {
    state: Arc<Observation>,
    reads: AtomicUsize,
    deletes: Mutex<Vec<String>>,
}

#[async_trait]
impl SecondaryStorage for FailingCache {
    async fn get(&self, key: &str) -> AuthResult<Option<serde_json::Value>> {
        assert_eq!(key, "api-key:hash");
        let _ = self.reads.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::from_thrown(self.state.producer.clone()))
    }
    async fn set_native(&self, _: &FieldValue, _: &FieldValue, _: Option<f64>) -> AuthResult<()> {
        Err(AuthError::internal(
            "The failed cache read must prevent a cache write",
        ))
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        lock(&self.deletes)?.push(key.to_owned());
        Err(AuthError::from_thrown(self.state.producer.clone()))
    }
    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<serde_json::Value>> {
        Err(AuthError::internal(
            "API Key cleanup must not consume verification storage",
        ))
    }
}

fn key_fields() -> FieldMap {
    let date = FieldDate::from_milliseconds(1_893_456_000_000.0);
    FieldMap::from([
        ("id".into(), "retained".into()),
        ("key".into(), "hash".into()),
        ("referenceId".into(), "owner".into()),
        ("remaining".into(), 5.into()),
        ("requestCount".into(), 0.into()),
        ("refillAmount".into(), FieldValue::Null),
        ("refillInterval".into(), FieldValue::Null),
        ("lastRefillAt".into(), FieldValue::Null),
        ("lastRequest".into(), FieldValue::Null),
        ("rateLimitEnabled".into(), false.into()),
        ("expiresAt".into(), FieldValue::Null),
        ("createdAt".into(), date.clone().into()),
        ("updatedAt".into(), date.into()),
    ])
}

#[tokio::test]
async fn deferred_usage_keeps_the_snapshot_and_gives_logger_failure_to_the_handler_task()
-> AuthResult<()> {
    for handler in [None, Some(false), Some(true)] {
        let state = Observation::new();
        let config = Arc::new(state.config("Failed to update API key:", handler)?);
        let store = Arc::new(EphemeralStore::new(config.clone()));
        let context = AuthContext::new(config, store)?;
        let cache = Arc::new(FailingCache {
            state: state.clone(),
            reads: AtomicUsize::new(0),
            deletes: Mutex::new(Vec::new()),
        });
        let mut config = ApiKeyConfig {
            storage: ApiKeyStorage::SecondaryStorage,
            custom_storage: Some(cache.clone()),
            defer_updates: true,
            ..Default::default()
        };
        config.rate_limit.enabled = false;
        let original = key_fields();
        let key = ApiKey::from_field_values(original.clone())?;
        let result = storage::consume(&config, &context, &key, "hash").await;
        if handler == Some(true) {
            assert_failure(result, &state.handler)?;
        } else {
            let ConsumeApiKeyResult::Allowed(snapshot) = result? else {
                return Err(AuthError::internal(
                    "Deferred usage must return the claimed snapshot",
                ));
            };
            assert!(snapshot.remaining.field_value().strict_equals(&4.into()));
            assert!(snapshot.last_request.field_value().is_truthy());
        }
        if handler.is_some() {
            state.task_error(&state.first_logger).await?;
        } else {
            tokio::time::timeout(std::time::Duration::from_secs(5), state.logged.notified())
                .await
                .map_err(|_| AuthError::internal("Deferred usage did not settle"))?;
        }
        assert_eq!(cache.reads.load(Ordering::SeqCst), 1);
        assert!(lock(&cache.deletes)?.is_empty());
        assert!(key.remaining.field_value().strict_equals(&5.into()));
        assert_eq!(
            *lock(&state.events)?,
            if handler.is_some() {
                vec!["handler", "logger:first"]
            } else {
                vec!["logger:first"]
            }
        );
    }
    Ok(())
}

#[tokio::test]
async fn deferred_deletion_keeps_committed_peers_and_stops_before_the_database_delete()
-> AuthResult<()> {
    let state = Observation::new();
    let config = Arc::new(state.config("Deferred update failed:", Some(false))?);
    let row = key_fields();
    let store = Arc::new(EphemeralStore::from_storage(
        config.clone(),
        [("apikey".into(), vec![row.clone()])],
    )?);
    let context = AuthContext::new(config, store.clone())?;
    let cache = Arc::new(FailingCache {
        state: state.clone(),
        reads: AtomicUsize::new(0),
        deletes: Mutex::new(Vec::new()),
    });
    let config = ApiKeyConfig {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(cache.clone()),
        fallback_to_database: true,
        defer_updates: true,
        ..Default::default()
    };
    storage::delete_for_verification(&config, &context, &ApiKey::from_field_values(row.clone())?)
        .await?;
    state.task_error(&state.first_logger).await?;
    assert_eq!(*lock(&state.events)?, ["handler", "logger:first"]);
    assert_eq!(
        *lock(&cache.deletes)?,
        [
            "api-key:hash",
            "api-key:by-id:retained",
            "api-key:by-ref:owner"
        ]
    );
    assert_eq!(store.plugin_storage_rows(EntityRole::ApiKey)?, [row]);
    Ok(())
}
