#![expect(
    clippy::indexing_slicing,
    reason = "Fixture indexing must fail when an expected record or property is missing."
)]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic_in_result_fn,
    reason = "Frozen source scenarios and barrier channels must remain valid throughout each replay."
)]

use super::*;
use crate::plugins::test_helpers::native_observation::{NativeObservation, assert_replay};
use better_auth_core::{FieldDate, FieldFunction, FieldObject};
use serde_json::json;
use std::sync::{Mutex, OnceLock, Weak};
use tokio::sync::{Notify, oneshot};
use tracing::instrument::WithSubscriber;

mod host;
mod storage;
mod values;

type Shared = Arc<Mutex<State>>;

struct Call {
    slot: String,
    method: &'static str,
    plan: String,
    state: &'static str,
    returned_promise: bool,
    reason: FieldValue,
    release: Option<oneshot::Sender<()>>,
    done: Arc<Notify>,
}

struct State {
    scenario: Value,
    observer: NativeObservation,
    trace: Vec<String>,
    counts: Value,
    entries: Vec<(FieldValue, FieldValue)>,
    calls: Vec<Call>,
    errors: FieldMap,
    settled: bool,
}

impl State {
    fn error(&self, name: &str) -> FieldValue {
        self.errors.get(name).unwrap().clone()
    }

    fn identity(&self, error: &FieldValue) -> Value {
        self.errors
            .iter()
            .map(|(name, original)| (name.clone(), error.strict_equals(original).into()))
            .collect::<serde_json::Map<_, _>>()
            .into()
    }

    fn snapshot(&mut self, key: &ApiKey) -> AuthResult<Value> {
        let entries = self
            .entries
            .iter()
            .map(|(key, value)| vec![key.clone(), value.clone()].into())
            .collect::<Vec<FieldValue>>();
        let calls = self
            .calls
            .iter()
            .map(|call| {
                Ok(json!({
                    "slot":call.slot,"method":call.method,"plan":call.plan,
                    "state":call.state,"returnedPromise":call.returned_promise,
                    "reason":self.observer.observe(&call.reason)?,
                }))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(json!({
            "record":self.observer.observe(&key.field_values()?.into())?,
            "cache":self.observer.observe(&entries.into())?,"counts":self.counts,
            "settled":self.settled,"calls":calls,
        }))
    }
}

fn names() -> Vec<String> {
    let mut names = Vec::new();
    for operation in ["put", "remove"] {
        for fallback in [false, true] {
            let prefix = format!("{operation}/{fallback}");
            names.push(format!("{prefix}/success"));
            for slot in ["reference", "hash", "id"] {
                for phase in ["primitive-get", "primitive-call"] {
                    names.push(format!("{prefix}/key-error/{slot}/{phase}"));
                }
            }
            for slot in ["hash", "id"] {
                for failure in ["throw", "reject"] {
                    names.push(format!("{prefix}/storage-error/{slot}/{failure}"));
                }
            }
            for timing in ["ready", "pending"] {
                for completion in ["resolve", "reject"] {
                    names.push(format!(
                        "{prefix}/orphan/id/primitive-call/{timing}/{completion}"
                    ));
                }
            }
            for completion in ["resolve", "reject"] {
                names.push(format!("{prefix}/retained/{completion}"));
            }
        }
    }
    names
}

async fn run_case(case: &Value, host: Arc<host::Host>) -> AuthResult<()> {
    let scenario = &case["scenario"];
    let name = scenario["name"].as_str().unwrap();
    let state = Arc::new(Mutex::new(State {
        scenario: scenario.clone(),
        observer: NativeObservation::default(),
        trace: Vec::new(),
        counts: json!({
            "reference":{"getter":0,"method":0},
            "hash":{"getter":0,"method":0},
            "id":{"getter":0,"method":0},
        }),
        entries: Vec::new(),
        calls: Vec::new(),
        errors: values::errors(name),
        settled: false,
    }));
    let (key, _roots) = values::key(&state)?;
    let storage = Arc::new(storage::Storage::new(state.clone()));
    let original = state.lock().unwrap().error(
        if matches!(
            scenario["kind"].as_str().unwrap(),
            "storage-error" | "retained"
        ) {
            "storage"
        } else {
            "key"
        },
    );
    let errors_before = state
        .lock()
        .unwrap()
        .errors
        .values()
        .map(|value| value.enumerable_fields())
        .collect::<AuthResult<Vec<_>>>()?;
    let before = state.lock().unwrap().snapshot(&key)?;
    let fallback = scenario["fallback"].as_bool().unwrap();
    let put_operation = scenario["operation"] == "put";
    let observed = state.clone();
    let operated = key.clone();
    let mut pending = Box::pin(async move {
        let result = if put_operation {
            put(storage, &operated, fallback).await
        } else {
            remove_cached(storage, &operated, fallback).await
        };
        // The source runtime.capture awaits the helper's promise before publishing its outcome.
        let result = concurrent::adapter_result(result).await;
        let mut state = observed.lock().unwrap();
        let outcome = state
            .observer
            .outcome(result.map(|()| FieldValue::Undefined), &original)?;
        state.settled = true;
        let mut fields = vec![("returned".into(), outcome["returned"].clone())];
        if let Some(same) = outcome.get("sameOriginal") {
            fields.push(("sameOriginal".into(), same.clone()));
        }
        state.observer.record("operation:settled", fields);
        Ok::<_, AuthError>(outcome)
    });
    assert!(futures_util::poll!(pending.as_mut()).is_pending());
    let prefix = state.lock().unwrap().trace.clone();
    assert_replay(&json!(prefix), &case["prefix"], name);
    state
        .lock()
        .unwrap()
        .observer
        .record("operation:returned-to-caller", []);
    let outcome = pending.await?;
    let unowned_rejection = scenario["kind"] == "orphan" && scenario["completion"] == "reject";
    if unowned_rejection && scenario["timing"] == "ready" {
        host.reported.notified().await;
    }
    let before_release = {
        let mut state = state.lock().unwrap();
        state.observer.record(
            "host:checkpoint",
            [("checkpoint".into(), "before-release".into())],
        );
        state.snapshot(&key)?
    };
    let pending = {
        let mut state = state.lock().unwrap();
        let pending = state
            .calls
            .iter_mut()
            .filter_map(|call| {
                call.release
                    .take()
                    .map(|release| (call.slot.clone(), release, call.done.clone()))
            })
            .collect::<Vec<_>>();
        for (slot, _, _) in &pending {
            state
                .observer
                .record("gate:release", [("slot".into(), slot.clone().into())]);
        }
        pending
    };
    for (_, release, done) in pending {
        release.send(()).unwrap();
        done.notified().await;
    }
    if unowned_rejection && scenario["timing"] == "pending" {
        host.reported.notified().await;
    }
    let mut state = state.lock().unwrap();
    for checkpoint in [1, 2] {
        state.observer.record(
            "host:checkpoint",
            [("checkpoint".into(), checkpoint.into())],
        );
    }
    let after = state.snapshot(&key)?;
    let actual = json!({
        "before":before,"beforeRelease":before_release,"outcome":outcome,
        "events":state.observer.events,"after":after,
        "functionIds":state.observer.function_ids(),
    });
    let mut runtime = case["runtime"].clone();
    // Bun host rejection events remain raw fixture evidence. Rust reports unowned failures
    // through the shared terminal reporter; the two host lifecycles are separate contracts.
    runtime["events"]
        .as_array_mut()
        .unwrap()
        .retain(|event| event["phase"] != "host:event");
    assert_replay(&actual, &runtime, name);
    assert_replay(&json!(state.trace), &case["trace"], name);
    for (before, error) in errors_before.iter().zip(state.errors.values()) {
        assert_eq!(before, &error.enumerable_fields()?);
    }
    let host_events = case["hostEvents"].as_array().unwrap();
    assert_eq!(host_events.len(), usize::from(unowned_rejection));
    if unowned_rejection {
        let event = host_events.first().unwrap();
        assert_eq!(event["phase"], "unhandledRejection");
        assert_eq!(event["task"], 0);
        assert_eq!(event["identity"], state.identity(&state.error("storage")));
    }
    assert_eq!(
        *host.events.lock().unwrap(),
        if unowned_rejection {
            vec![json!({
                "target":"better-auth::runtime",
                "fields":{
                    "message":"Authentication runtime failed",
                    "boundary":if put_operation { "API key unowned cache write" } else { "API key unowned cache removal" },
                    "error":AuthError::from_thrown(state.error("storage")).to_string(),
                },
            })]
        } else {
            Vec::new()
        },
        "{name}: Rust owns terminal failures without invoking the application logger"
    );
    Ok(())
}

#[tokio::test]
async fn cache_call_order_matches_all_upstream_runtime_observations() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/api-key-cache-key-order-1.7.6.json"
    )))?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"].as_array().unwrap();
    let names = names();
    assert_eq!(cases.len(), 68);
    assert_eq!(cases.len(), names.len());
    for (case, name) in cases.iter().zip(names) {
        assert_eq!(case["scenario"]["name"], name);
        let host = Arc::new(host::Host::default());
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run_case(case, host.clone()).with_subscriber(host),
        )
        .await
        .expect("Cache call-order replay must settle before its gate is released")?;
    }
    Ok(())
}
