#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Barrier contract fixtures fail immediately on invalid setup or a closed test channel."
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, AuthStore, CreateUser,
    HttpMethod,
    hooks::{RequestHookContext, current_request_hook_context, with_request_hook_context_value},
    store::EphemeralStore,
};
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};

use super::{ApiKeyConfig, ApiKeyStorage, SecondaryStorage};
use crate::plugins::api_key::{ApiKeyPlugin, CreateKeyRequest};

const COUNT: usize = 12;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Get,
    Refill,
    Remove,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rejection {
    None,
    Single,
    Multiple,
}

struct Call {
    row: usize,
    by_id: bool,
    release: oneshot::Sender<AuthResult<()>>,
    finished: oneshot::Receiver<()>,
}

impl Call {
    async fn finish(self, result: AuthResult<()>) {
        self.release.send(result).unwrap();
        self.finished.await.unwrap();
    }
}

#[derive(Default)]
struct State {
    values: HashMap<String, String>,
    rows: HashMap<String, usize>,
    mode: Option<Mode>,
    sender: Option<mpsc::UnboundedSender<Call>>,
    starts: Vec<usize>,
    completed: usize,
    active: usize,
    maximum: usize,
    index_writes: Vec<(Value, usize, usize)>,
    removal_changes: Vec<(String, Option<String>)>,
}

#[derive(Default)]
struct Storage(Mutex<State>);

impl Storage {
    fn arm(&self, mode: Mode) -> mpsc::UnboundedReceiver<Call> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut state = self.0.lock().unwrap();
        state.mode = Some(mode);
        state.sender = Some(sender);
        if mode == Mode::Refill {
            state.values.clear();
        }
        receiver
    }

    async fn run<T>(
        &self,
        key: &str,
        mode: Mode,
        value: Option<&str>,
        action: impl FnOnce(&mut State) -> T,
    ) -> AuthResult<T> {
        let barrier = {
            let mut state = self.0.lock().unwrap();
            let row = if mode == Mode::Remove {
                state.rows.get(key).copied()
            } else if mode == Mode::Get {
                key.strip_prefix("api-key:by-id:")
                    .and_then(|id| state.rows.get(id).copied())
            } else if key.starts_with("api-key:by-ref:") {
                None
            } else {
                value.and_then(|text| {
                    let object: Value = serde_json::from_str(text).unwrap();
                    object
                        .get("id")
                        .and_then(Value::as_str)
                        .and_then(|id| state.rows.get(id).copied())
                })
            };
            if state.mode == Some(mode)
                && let Some(row) = row
            {
                assert_eq!(
                    current_request_hook_context().unwrap().path.as_deref(),
                    Some(if mode == Mode::Remove {
                        "/api-key/delete"
                    } else {
                        "/api-key/list"
                    })
                );
                let (release, permit) = oneshot::channel();
                let (finished, completion) = oneshot::channel();
                state
                    .sender
                    .as_ref()
                    .unwrap()
                    .send(Call {
                        row,
                        by_id: key.starts_with("api-key:by-id:"),
                        release,
                        finished: completion,
                    })
                    .unwrap();
                state.starts.push(row);
                state.active += 1;
                state.maximum = state.maximum.max(state.active);
                Some((permit, finished))
            } else {
                None
            }
        };
        let Some((permit, finished)) = barrier else {
            return Ok(action(&mut self.0.lock().unwrap()));
        };
        let result = permit.await.unwrap();
        let mut state = self.0.lock().unwrap();
        let result = result.map(|()| action(&mut state));
        state.completed += 1;
        state.active -= 1;
        let _ = finished.send(());
        result
    }
}

#[async_trait]
impl SecondaryStorage for Storage {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        self.run(key, Mode::Get, None, |state| {
            state.values.get(key).cloned().map(Value::String)
        })
        .await
    }

    async fn set_native(
        &self,
        key: &better_auth_core::FieldValue,
        value: &str,
        _: Option<f64>,
    ) -> AuthResult<()> {
        let key = key
            .as_str()
            .expect("API-key batch storage receives string-formatted index keys");
        let mode = if self.0.lock().unwrap().mode == Some(Mode::Remove) {
            Mode::Remove
        } else {
            Mode::Refill
        };
        self.run(key, mode, Some(value), |state| {
            if state.mode == Some(Mode::Refill) && key.starts_with("api-key:by-ref:") {
                state.index_writes.push((
                    serde_json::from_str(value).unwrap(),
                    state.completed,
                    state.active,
                ));
            }
            if state.mode == Some(Mode::Remove) {
                state
                    .removal_changes
                    .push((key.to_owned(), Some(value.to_owned())));
            }
            let _ = state.values.insert(key.to_owned(), value.to_owned());
        })
        .await
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.run(key, Mode::Remove, None, |state| {
            if state.mode == Some(Mode::Remove) {
                state.removal_changes.push((key.to_owned(), None));
            }
            let _ = state.values.remove(key);
        })
        .await
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        Ok(self.0.lock().unwrap().values.remove(key).map(Value::String))
    }
}

async fn exercise<S: AuthSchema>(
    database: Arc<dyn AuthStore<S>>,
    mode: Mode,
    fallback: bool,
    reject: Rejection,
) {
    // The deadline reports a stalled barrier if a regression serializes the batch.
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        exercise_batch(database, mode, fallback, reject),
    )
    .await
    .unwrap();
}

async fn exercise_batch<S: AuthSchema>(
    database: Arc<dyn AuthStore<S>>,
    mode: Mode,
    fallback: bool,
    reject: Rejection,
) {
    let owner = database
        .create_user(
            CreateUser::new()
                .with_name("Cache Owner")
                .with_email("owner@api-key-cache-batch.test"),
        )
        .await
        .unwrap();
    let storage = Arc::new(Storage::default());
    let config = ApiKeyConfig {
        storage: ApiKeyStorage::SecondaryStorage,
        fallback_to_database: fallback,
        custom_storage: Some(storage.clone()),
        defer_updates: false,
        ..Default::default()
    };
    let plugin = ApiKeyPlugin::with_config(config.clone());
    let context = AuthContext::new(
        Arc::new(
            AuthConfig::new("api-key-cache-batch-contract-secret-at-least-32-characters")
                .base_url("http://api-key-cache-batch.test"),
        ),
        database,
    );
    let mut ids = Vec::new();
    let mut names = Vec::new();
    for row in 0..COUNT {
        let name = format!("Ordinary key {row:02}");
        let key = plugin
            .create_key(
                &context,
                &CreateKeyRequest {
                    user_id: Some(owner.id.typed().unwrap().clone()),
                    name: Some(name.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let id = key.api_key.id.typed().unwrap().clone();
        let _ = storage.0.lock().unwrap().rows.insert(id.clone(), row);
        ids.push(id);
        names.push(name);
    }
    if mode == Mode::Get && fallback {
        let _ = super::list(&config, &context, owner.id.typed().unwrap(), None)
            .await
            .unwrap();
    }
    let mut calls = storage.arm(mode);
    let mut task = tokio::spawn(with_request_hook_context_value(
        RequestHookContext::from_request(&AuthRequest::new(HttpMethod::Get, "/api-key/list"))
            .unwrap(),
        async move { super::list(&config, &context, owner.id.typed().unwrap(), None).await },
    ));
    let width = if mode == Mode::Get { 1 } else { 2 };
    let mut pending: Vec<Call> = Vec::new();
    for _ in 0..10 * width {
        pending.push(calls.recv().await.unwrap());
    }
    assert!(calls.try_recv().is_err());
    assert_eq!(storage.0.lock().unwrap().maximum, 10 * width);
    assert!(storage.0.lock().unwrap().index_writes.is_empty());

    if reject != Rejection::None {
        let position = pending
            .iter()
            .position(|call| call.row == 0 && call.by_id)
            .unwrap();
        pending
            .remove(position)
            .finish(Err(AuthError::validation("ordinary storage rejection")))
            .await;
        // This adapter drains already-started callbacks; the original error is retained.
        assert!(!task.is_finished());
        if mode == Mode::Refill {
            // Another key completes while the failed key's other write is still pending.
            // A failure must stop new keys before all writes for that key finish.
            for _ in 0..width {
                let position = pending.iter().position(|call| call.row == 1).unwrap();
                pending.remove(position).finish(Ok(())).await;
            }
        }
        if reject == Rejection::Multiple {
            assert!(mode == Mode::Refill);
            let position = pending
                .iter()
                .position(|call| call.row == 2 && call.by_id)
                .unwrap();
            pending
                .remove(position)
                .finish(Err(AuthError::Forbidden("later peer failure".into())))
                .await;
            let position = pending.iter().position(|call| call.row == 2).unwrap();
            pending.remove(position).finish(Ok(())).await;
            let position = pending.iter().position(|call| call.row == 0).unwrap();
            pending
                .remove(position)
                .finish(Err(AuthError::internal("later hashed-key failure")))
                .await;
        }
        for call in pending {
            call.finish(Ok(())).await;
        }
        let result = loop {
            tokio::select! {
                result = &mut task => break result,
                call = calls.recv() => call.unwrap().finish(Ok(())).await,
            }
        };
        let error = result.unwrap().unwrap_err();
        assert!(
            matches!(error, AuthError::Validation(message) if message == "ordinary storage rejection")
        );
        let state = storage.0.lock().unwrap();
        assert_eq!(state.starts.len(), 10 * width);
        assert!(state.starts.iter().all(|row| *row < 10));
        assert_eq!(state.completed, 10 * width);
        assert_eq!(state.active, 0);
        assert!(state.index_writes.is_empty());
        if mode == Mode::Refill {
            assert!(
                state
                    .values
                    .contains_key(&format!("api-key:by-id:{}", ids.get(1).unwrap()))
            );
            assert!(
                !state
                    .values
                    .keys()
                    .any(|key| key.starts_with("api-key:by-ref:"))
            );
        }
        return;
    }

    for row in (0..10).rev().chain([11, 10]) {
        while pending.iter().filter(|call| call.row == row).count() < width {
            pending.push(calls.recv().await.unwrap());
        }
        for _ in 0..width {
            let position = pending.iter().position(|call| call.row == row).unwrap();
            pending.remove(position).finish(Ok(())).await;
        }
        while let Ok(call) = calls.try_recv() {
            pending.push(call);
        }
    }
    let result = task.await.unwrap().unwrap();
    assert_eq!(
        result
            .iter()
            .map(|key| super::list_field(key, "id").unwrap())
            .collect::<Vec<_>>(),
        ids.iter()
            .cloned()
            .map(better_auth_core::FieldValue::from)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        result
            .iter()
            .map(|key| super::list_field(key, "name").unwrap())
            .collect::<Vec<_>>(),
        names
            .iter()
            .cloned()
            .map(better_auth_core::FieldValue::from)
            .collect::<Vec<_>>()
    );
    let state = storage.0.lock().unwrap();
    assert_eq!(state.maximum, 10 * width);
    assert_eq!(state.completed, COUNT * width);
    assert_eq!(state.active, 0);
    if mode == Mode::Refill {
        assert_eq!(state.index_writes, vec![(json!(ids), COUNT * width, 0)]);
    }
}

#[tokio::test]
async fn cached_lists_and_database_refills_preserve_order_with_ten_concurrent_keys() {
    for (mode, fallback) in [(Mode::Get, false), (Mode::Get, true), (Mode::Refill, true)] {
        exercise(
            Arc::new(EphemeralStore::default()),
            mode,
            fallback,
            Rejection::None,
        )
        .await;
        exercise(
            crate::plugins::test_helpers::create_test_database().await,
            mode,
            fallback,
            Rejection::None,
        )
        .await;
    }
}

#[tokio::test]
async fn failed_cache_batches_drain_started_keys_and_skip_queued_keys_and_index_publish() {
    for (mode, fallback) in [(Mode::Get, false), (Mode::Get, true), (Mode::Refill, true)] {
        exercise(
            Arc::new(EphemeralStore::default()),
            mode,
            fallback,
            Rejection::Single,
        )
        .await;
        exercise(
            crate::plugins::test_helpers::create_test_database().await,
            mode,
            fallback,
            Rejection::Single,
        )
        .await;
    }
}

#[tokio::test]
async fn failed_refill_preserves_first_error_across_writes_and_keys_while_draining() {
    exercise(
        Arc::new(EphemeralStore::default()),
        Mode::Refill,
        true,
        Rejection::Multiple,
    )
    .await;
    exercise(
        crate::plugins::test_helpers::create_test_database().await,
        Mode::Refill,
        true,
        Rejection::Multiple,
    )
    .await;
}

#[tokio::test]
async fn failed_groups_preserve_first_error_without_stopping_independent_workers() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let storages = (0..3).map(|group| {
            let storage = Arc::new(Storage::default());
            let mut state = storage.0.lock().unwrap();
            let ids = (0..COUNT).map(|row| format!("group-{group}-key-{row}")).collect::<Vec<_>>();
            for (row, id) in ids.iter().enumerate() {
                let _ = state.rows.insert(id.clone(), row);
                let _ = state.values.insert(format!("api-key:by-id:{id}"), json!({
                    "id":id,"referenceId":"owner","configId":format!("group-{group}"),"key":"secret",
                    "createdAt":"2030-01-02T03:04:05.000Z","updatedAt":"2030-01-02T03:04:05.000Z"
                }).to_string());
            }
            let _ = state.values.insert("api-key:by-ref:owner".into(), json!(ids).to_string());
            drop(state);
            storage
        }).collect::<Vec<_>>();
        let before = storages.iter().map(|storage| storage.0.lock().unwrap().values.clone()).collect::<Vec<_>>();
        let configurations = storages.iter().enumerate().map(|(group, storage)| ApiKeyConfig {
            config_id: format!("group-{group}"),
            storage: ApiKeyStorage::SecondaryStorage,
            custom_storage: Some(storage.clone()),
            ..Default::default()
        }).collect::<Vec<_>>();
        let mut plugin = ApiKeyPlugin::with_config(configurations.first().unwrap().clone());
        for config in configurations.into_iter().skip(1) {
            plugin = plugin.configuration(config);
        }
        let context = AuthContext::new(
            Arc::new(AuthConfig::new("group-cache-list-contract-at-least-32-characters")),
            Arc::new(EphemeralStore::default()),
        );
        let mut calls = storages.iter().map(|storage| storage.arm(Mode::Get)).collect::<Vec<_>>();
        let task = tokio::spawn(with_request_hook_context_value(
            RequestHookContext::from_request(&AuthRequest::new(HttpMethod::Get, "/api-key/list")).unwrap(),
            async move {
                crate::plugins::api_key::handlers::list_keys_core(
                    "owner", &crate::plugins::api_key::types::ListKeysQuery::default(), &plugin, &context,
                ).await
            },
        ));
        let mut pending = Vec::new();
        for receiver in &mut calls {
            let mut group = Vec::new();
            for _ in 0..10 {
                group.push(receiver.recv().await.unwrap());
            }
            assert!(receiver.try_recv().is_err());
            pending.push(group);
        }
        pending.get_mut(1).unwrap().remove(0).finish(Err(AuthError::validation("first group failure"))).await;
        assert!(!task.is_finished());
        pending.get_mut(0).unwrap().remove(0).finish(Err(AuthError::Forbidden("later group failure".into()))).await;
        for group in pending.iter_mut().take(2) {
            for call in group.drain(..) {
                call.finish(Ok(())).await;
            }
        }
        let successful = pending.get_mut(2).unwrap();
        for row in 0..COUNT {
            let call = if let Some(position) = successful.iter().position(|call| call.row == row) {
                successful.remove(position)
            } else {
                calls.get_mut(2).unwrap().recv().await.unwrap()
            };
            assert_eq!(call.row, row);
            call.finish(Ok(())).await;
        }
        assert!(matches!(task.await.unwrap().unwrap_err(), AuthError::Validation(message) if message == "first group failure"));
        for (group, (storage, before)) in storages.iter().zip(before).enumerate() {
            let state = storage.0.lock().unwrap();
            let count = if group == 2 { COUNT } else { 10 };
            assert_eq!(state.starts, (0..count).collect::<Vec<_>>());
            assert_eq!((state.completed, state.active, state.maximum), (count, 0, 10));
            assert_eq!(state.values, before);
            assert!(state.index_writes.is_empty());
        }
    }).await.unwrap();
}

#[tokio::test]
async fn cache_removal_preserves_first_error_and_drains_reference_and_record_changes() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for fallback in [false, true] {
            for first_row in [1, 2] {
                let storage = Arc::new(Storage::default());
                let key = super::deserialize(Some(r#"{"id":"removed","key":"hash","referenceId":"owner","createdAt":"2030-01-02T03:04:05.000Z","updatedAt":"2030-01-02T03:04:05.000Z"}"#.into())).unwrap();
                let encoded = super::serialize(&key).unwrap();
                let cache_keys = ["api-key:hash", "api-key:by-id:removed", "api-key:by-ref:owner"];
                {
                    let mut state = storage.0.lock().unwrap();
                    for (row, cache_key) in cache_keys.iter().enumerate() {
                        let _ = state.rows.insert((*cache_key).into(), row);
                        let _ = state.values.insert((*cache_key).into(), if row == 2 {
                            r#"["removed","kept"]"#.into()
                        } else { encoded.clone() });
                    }
                    let _ = state.values.insert("unrelated".into(), "preserved".into());
                }
                let mut expected = storage.0.lock().unwrap().values.clone();
                let mut calls = storage.arm(Mode::Remove);
                let current_storage = storage.clone();
                let task = tokio::spawn(with_request_hook_context_value(
                    RequestHookContext::from_request(&AuthRequest::new(HttpMethod::Post, "/api-key/delete")).unwrap(),
                    async move { super::remove_cached(current_storage.as_ref(), &key, fallback).await },
                ));
                let mut pending = Vec::new();
                for _ in 0..3 {
                    pending.push(calls.recv().await.unwrap());
                }
                assert!(calls.try_recv().is_err());
                let position = pending.iter().position(|call| call.row == first_row).unwrap();
                pending.remove(position).finish(Err(AuthError::validation("first removal failure"))).await;
                assert!(!task.is_finished());
                let position = pending.iter().position(|call| call.row == 0).unwrap();
                pending.remove(position).finish(Err(AuthError::Forbidden("later removal failure".into()))).await;
                let successful = pending.pop().unwrap();
                let changed_key = cache_keys.get(successful.row).unwrap().to_string();
                let changed_value = if successful.row == 2 && !fallback {
                    Some(r#"["kept"]"#.to_owned())
                } else { None };
                successful.finish(Ok(())).await;
                assert!(matches!(task.await.unwrap().unwrap_err(), AuthError::Validation(message) if message == "first removal failure"));
                if let Some(value) = &changed_value {
                    let _ = expected.insert(changed_key.clone(), value.clone());
                } else {
                    let _ = expected.remove(&changed_key);
                }
                let state = storage.0.lock().unwrap();
                let mut starts = state.starts.clone();
                starts.sort_unstable();
                assert_eq!(starts, [0, 1, 2]);
                assert_eq!((state.completed, state.active, state.maximum), (3, 0, 3));
                assert_eq!(state.values, expected);
                assert_eq!(state.removal_changes, [(changed_key, changed_value)]);
                assert!(state.index_writes.is_empty());
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn fractional_string_length_starts_one_worker_then_reads_both_indices() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let storage = Arc::new(Storage::default());
        {
            let mut state = storage.0.lock().unwrap();
            for (index, id) in ["first", "second"].into_iter().enumerate() {
                let _ = state.rows.insert(id.into(), index);
                let _ = state.values.insert(format!("api-key:by-id:{id}"), json!({
                    "id":id,"referenceId":"owner","key":"secret",
                    "createdAt":"2030-01-02T03:04:05.000Z","updatedAt":"2030-01-02T03:04:05.000Z"
                }).to_string());
            }
            let _ = state.values.insert(
                "api-key:by-ref:owner".into(),
                r#"{"length":"1.5","0":"first","1":"second"}"#.into(),
            );
        }
        let before = storage.0.lock().unwrap().values.clone();
        let config = ApiKeyConfig {
            storage: ApiKeyStorage::SecondaryStorage,
            custom_storage: Some(storage.clone()),
            ..Default::default()
        };
        let ctx = AuthContext::new(
            Arc::new(AuthConfig::new(
                "fractional-cache-list-contract-at-least-32-characters",
            )),
            Arc::new(EphemeralStore::default()),
        );
        let mut calls = storage.arm(Mode::Get);
        let task = tokio::spawn(with_request_hook_context_value(
            RequestHookContext::from_request(&AuthRequest::new(HttpMethod::Get, "/api-key/list"))
                .unwrap(),
            async move { super::list(&config, &ctx, "owner", None).await },
        ));
        for index in 0..2 {
            let call = calls.recv().await.unwrap();
            assert_eq!(call.row, index);
            assert!(calls.try_recv().is_err());
            assert_eq!(storage.0.lock().unwrap().maximum, 1);
            call.finish(Ok(())).await;
        }
        let result = task.await.unwrap().unwrap();
        assert_eq!(
            result
                .into_iter()
                .map(|key| key.json().unwrap().unwrap())
                .collect::<Vec<_>>(),
            ["first", "second"].map(|id| json!({
                "id":id,"referenceId":"owner","key":"secret",
                "createdAt":"2030-01-02T03:04:05.000Z","updatedAt":"2030-01-02T03:04:05.000Z",
                "expiresAt":null,"lastRefillAt":null,"lastRequest":null
            }))
        );
        let state = storage.0.lock().unwrap();
        assert_eq!(state.values, before);
        assert_eq!(state.starts, [0, 1]);
        assert_eq!((state.completed, state.active, state.maximum), (2, 0, 1));
        assert!(state.index_writes.is_empty());
    })
    .await
    .unwrap();
}
