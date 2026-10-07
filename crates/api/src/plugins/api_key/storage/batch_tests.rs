#![expect(
    clippy::unwrap_used,
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
}

struct Call {
    row: usize,
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
            let row = if mode == Mode::Get {
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
                    Some("/api-key/list")
                );
                let (release, permit) = oneshot::channel();
                let (finished, completion) = oneshot::channel();
                state
                    .sender
                    .as_ref()
                    .unwrap()
                    .send(Call {
                        row,
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

    async fn set(&self, key: &str, value: &str, _: Option<u64>) -> AuthResult<()> {
        self.run(key, Mode::Refill, Some(value), |state| {
            if state.mode == Some(Mode::Refill) && key.starts_with("api-key:by-ref:") {
                state.index_writes.push((
                    serde_json::from_str(value).unwrap(),
                    state.completed,
                    state.active,
                ));
            }
            let _ = state.values.insert(key.to_owned(), value.to_owned());
        })
        .await
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        let _ = self.0.lock().unwrap().values.remove(key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        Ok(self.0.lock().unwrap().values.remove(key).map(Value::String))
    }
}

async fn exercise<S: AuthSchema>(
    database: Arc<dyn AuthStore<S>>,
    mode: Mode,
    fallback: bool,
    reject: bool,
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
    reject: bool,
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

    if reject {
        let position = pending.iter().position(|call| call.row == 0).unwrap();
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
            .map(|key| key.id.typed().unwrap())
            .collect::<Vec<_>>(),
        ids.iter().collect::<Vec<_>>()
    );
    assert_eq!(
        result
            .iter()
            .map(|key| key.name.typed().unwrap().as_deref().unwrap())
            .collect::<Vec<_>>(),
        names.iter().map(String::as_str).collect::<Vec<_>>()
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
        exercise(Arc::new(EphemeralStore::default()), mode, fallback, false).await;
        exercise(
            crate::plugins::test_helpers::create_test_database().await,
            mode,
            fallback,
            false,
        )
        .await;
    }
}

#[tokio::test]
async fn failed_cache_batches_drain_started_keys_and_skip_queued_keys_and_index_publish() {
    for (mode, fallback) in [(Mode::Get, false), (Mode::Get, true), (Mode::Refill, true)] {
        exercise(Arc::new(EphemeralStore::default()), mode, fallback, true).await;
        exercise(
            crate::plugins::test_helpers::create_test_database().await,
            mode,
            fallback,
            true,
        )
        .await;
    }
}
