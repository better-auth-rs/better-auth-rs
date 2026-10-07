use super::*;
use async_trait::async_trait;
use better_auth_core::{
    UpdateUser,
    observability::{LogArgument, LogLevel, LogSink},
    store::{
        SecondaryStorage,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    },
};
use std::sync::Mutex;
use tokio::sync::Semaphore;

#[derive(Clone, Default)]
pub(super) struct Recorder(Arc<Mutex<Vec<Value>>>);

impl Recorder {
    #[expect(
        clippy::expect_used,
        reason = "The synchronous logger callback cannot propagate mutex poisoning."
    )]
    pub(super) fn push(&self, event: Value) {
        self.0
            .lock()
            .expect("Recorder mutex is not poisoned")
            .push(event);
    }

    #[expect(
        clippy::expect_used,
        reason = "A poisoned recorder means a callback already failed the test."
    )]
    pub(super) fn snapshot(&self) -> Vec<Value> {
        self.0
            .lock()
            .expect("Recorder mutex is not poisoned")
            .clone()
    }
}

pub(super) fn error(error: &AuthError) -> Value {
    assert!(
        matches!(error, AuthError::Internal(_)),
        "Unexpected typed error: {error:?}"
    );
    json!({"type": "rust-error", "debug": format!("{error:?}"), "display": error.to_string()})
}

impl LogSink for Recorder {
    fn log(&self, level: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]) {
        self.push(json!({
            "kind": "logger", "level": level.as_str(), "message": log_value(&message),
            "args": arguments.iter().map(log_value).collect::<Vec<_>>(),
        }));
    }
}

fn log_value(argument: &LogArgument<'_>) -> Value {
    match argument {
        LogArgument::Text(text) => Value::String((*text).into()),
        LogArgument::Value(value) => (*value).clone(),
        LogArgument::Error(value) => {
            json!({"type": "rust-error", "debug": format!("{value:?}"), "display": value.to_string()})
        }
    }
}

pub(super) struct Hooks {
    pub(super) recorder: Recorder,
    pub(super) scenario: String,
}

#[better_auth::database_hooks]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn before_update_user(
        &self,
        data: &UpdateUser,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        assert!(context.request.is_none());
        assert_eq!(
            serde_json::to_value(data)?,
            serde_json::to_value(super::super::update("Updated"))?
        );
        self.recorder
            .push(json!({"kind": "hook.before", "data": {"name": data.name}, "context": null}));
        Ok(if self.scenario == "cancel-committed" {
            DatabaseHookUpdate::Cancel
        } else {
            DatabaseHookUpdate::Continue
        })
    }

    async fn after_update_user(
        &self,
        user: Option<&UserView>,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        assert!(context.request.is_none());
        assert!(context.transaction.is_none());
        self.recorder.push(json!({"kind": "hook.after", "data": observed_user(user, context.config).await?, "context": null}));
        if self.scenario.starts_with("after-error-") {
            Err(AuthError::internal("refresh-after-hook-failure"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Deserialize, serde::Serialize)]
struct Entry {
    key: String,
    value: String,
}

pub(super) struct Cache {
    values: Mutex<Vec<Entry>>,
    recorder: Recorder,
    scenario: String,
    entered: Semaphore,
    completed: Semaphore,
    pub(super) release_a: Semaphore,
    pub(super) release_b: Semaphore,
}

impl Cache {
    pub(super) fn new(case: &Case, recorder: Recorder) -> TestResult<Self> {
        Ok(Self {
            values: Mutex::new(serde_json::from_value(case.before["cache"].clone())?),
            recorder,
            scenario: case.scenario.clone(),
            entered: Semaphore::new(0),
            completed: Semaphore::new(0),
            release_a: Semaphore::new(0),
            release_b: Semaphore::new(0),
        })
    }

    pub(super) fn snapshot(&self) -> AuthResult<Value> {
        let values = self
            .values
            .lock()
            .map_err(|_| AuthError::internal("Cache mutex is poisoned"))?;
        Ok(serde_json::to_value(&*values)?)
    }

    pub(super) async fn both_entered(&self) -> TestResult {
        self.entered.acquire_many(2).await?.forget();
        Ok(())
    }

    pub(super) async fn sibling_finished(&self) -> TestResult {
        self.completed.acquire().await?.forget();
        Ok(())
    }
}

#[async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        self.recorder
            .push(json!({"kind": "cache.get.start", "key": key}));
        if self.scenario == "parallel-partial" && matches!(key, "token-a" | "token-b") {
            self.entered.add_permits(1);
            let gate = if key == "token-a" {
                &self.release_a
            } else {
                &self.release_b
            };
            gate.acquire()
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?
                .forget();
        }
        if (self.scenario.ends_with("refresh-error") && key == "active-sessions-owner")
            || (self.scenario == "parallel-partial" && key == "token-a")
        {
            let failure = AuthError::internal("refresh-cache-failure");
            self.recorder
                .push(json!({"kind": "cache.get.throw", "key": key, "error": error(&failure)}));
            return Err(failure);
        }
        let value = self
            .values
            .lock()
            .map_err(|_| AuthError::internal("Cache mutex is poisoned"))?
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| Value::String(entry.value.clone()));
        self.recorder
            .push(json!({"kind": "cache.get.return", "key": key, "value": value}));
        Ok(value)
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> AuthResult<()> {
        self.recorder
            .push(json!({"kind": "cache.set.start", "key": key, "value": value, "ttl": ttl}));
        {
            let mut values = self
                .values
                .lock()
                .map_err(|_| AuthError::internal("Cache mutex is poisoned"))?;
            if let Some(entry) = values.iter_mut().find(|entry| entry.key == key) {
                entry.value = value.into();
            } else {
                values.push(Entry {
                    key: key.into(),
                    value: value.into(),
                });
            }
        }
        self.recorder
            .push(json!({"kind": "cache.set.return", "key": key, "value": {"type": "undefined"}}));
        if key == "token-b" {
            self.completed.add_permits(1);
        }
        Ok(())
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.recorder
            .push(json!({"kind": "cache.delete.start", "key": key}));
        self.values
            .lock()
            .map_err(|_| AuthError::internal("Cache mutex is poisoned"))?
            .retain(|entry| entry.key != key);
        self.recorder.push(
            json!({"kind": "cache.delete.return", "key": key, "value": {"type": "undefined"}}),
        );
        Ok(())
    }

    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<Value>> {
        Err(AuthError::internal(
            "User refresh must not call get_and_delete",
        ))
    }
}

pub(super) fn project_reference(value: &mut Value, scenario: &str) -> TestResult {
    match value {
        Value::Object(fields) if fields.get("type").and_then(Value::as_str) == Some("error") => {
            let message = match fields.get("injected").and_then(Value::as_str) {
                Some(source @ ("cache" | "after" | "rollback")) => {
                    assert_eq!(fields.get("name"), Some(&json!("Error")));
                    let message = fields
                        .get("message")
                        .and_then(Value::as_str)
                        .ok_or("Expected injected error message")?;
                    assert_eq!(
                        message,
                        match source {
                            "cache" => "refresh-cache-failure",
                            "after" => "refresh-after-hook-failure",
                            _ => "refresh-transaction-rollback",
                        }
                    );
                    message.to_owned()
                }
                None => {
                    assert_eq!(fields.get("name"), Some(&json!("TypeError")));
                    assert!(
                        fields
                            .get("message")
                            .and_then(Value::as_str)
                            .is_some_and(|text| !text.is_empty())
                    );
                    match scenario {
                        "missing-immediate" | "cancel-committed" => {
                            "Cannot refresh sessions for a missing user"
                        }
                        "malformed-cache-envelope" => {
                            "Cached user session refresh requires a session object"
                        }
                        "non-array-active-index" => "Cached user session index must be an array",
                        _ => return Err(format!("Unexpected native error in {scenario}").into()),
                    }
                    .to_owned()
                }
                Some(source) => {
                    return Err(format!("Unknown injected error source: {source}").into());
                }
            };
            // Rust retains its typed diagnostic; JavaScript error object details stay in the source fixture.
            *value = error(&AuthError::internal(message));
        }
        Value::Object(fields) => {
            if fields
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.starts_with("hook."))
            {
                let context = fields.get_mut("context").ok_or("Expected hook context")?;
                assert!(*context == Value::Null || *context == json!({"type": "undefined"}));
                *context = Value::Null;
            }
            for child in fields.values_mut() {
                project_reference(child, scenario)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                project_reference(child, scenario)?;
            }
        }
        _ => {}
    }
    Ok(())
}
