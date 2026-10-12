#![expect(
    clippy::indexing_slicing,
    reason = "Fixture indexing must fail when an expected record or property is missing."
)]

use super::*;
use async_trait::async_trait;
use better_auth_core::store::SecondaryStorageFuture;

pub(super) struct Storage {
    state: Shared,
    receiver: FieldValue,
}

fn plan(scenario: &Value, slot: &str) -> String {
    match scenario["kind"].as_str().unwrap() {
        "storage-error" if scenario["slot"] == slot => if scenario["failure"] == "throw" {
            "throw"
        } else {
            "ready-reject"
        }
        .into(),
        "orphan" if slot == "hash" => format!(
            "{}-{}",
            scenario["timing"].as_str().unwrap(),
            scenario["completion"].as_str().unwrap()
        ),
        "retained" if slot == "hash" => "ready-reject".into(),
        "retained" if slot == "id" => {
            format!("pending-{}", scenario["completion"].as_str().unwrap())
        }
        _ => "ready-resolve".into(),
    }
}

#[expect(
    clippy::panic,
    reason = "Any unrecorded cache key invalidates the paired source contract."
)]
fn slot(key: &FieldValue) -> &'static str {
    match key.as_str().unwrap() {
        "api-key:hash" => "hash",
        "api-key:by-id:key" => "id",
        "api-key:by-ref:owner" => "reference",
        key => panic!("Unexpected cache key {key}"),
    }
}

impl Storage {
    pub(super) fn new(state: Shared) -> Self {
        Self {
            state,
            receiver: FieldMap::new().into(),
        }
    }

    fn call(&self, method: &'static str, arguments: &[FieldValue]) -> AuthResult<()> {
        let slot = slot(arguments.first().unwrap());
        let mut state = self.state.lock().unwrap();
        state.trace.push(format!("storage:{method}:{slot}"));
        state.observer.call(
            &format!("storage.{method}:{slot}"),
            &self.receiver,
            &self.receiver,
            arguments,
        )
    }

    fn complete(&self, index: usize, key: &FieldValue, value: &FieldValue) -> AuthResult<()> {
        let mut state = self.state.lock().unwrap();
        let call = state.calls.get(index).unwrap();
        let slot = call.slot.clone();
        let method = call.method;
        let rejects = call.plan == "throw" || call.plan.ends_with("reject");
        let result = if rejects {
            let kind = if state.scenario["kind"] == "retained" && slot == "id" {
                "peer"
            } else {
                "storage"
            };
            let error = state.error(kind);
            let identity = state.identity(&error);
            let observed = state.observer.observe(&error)?;
            state.observer.record(
                "storage:rejected",
                [
                    ("slot".into(), slot.into()),
                    ("identity".into(), identity),
                    ("error".into(), observed),
                ],
            );
            let call = state.calls.get_mut(index).unwrap();
            call.state = "rejected";
            call.reason = error.clone();
            Err(AuthError::from_thrown(error))
        } else {
            if method == "set" {
                if let Some((_, stored)) = state
                    .entries
                    .iter_mut()
                    .find(|(stored, _)| stored.same_value_zero(key))
                {
                    *stored = value.clone();
                } else {
                    state.entries.push((key.clone(), value.clone()));
                }
            } else {
                state
                    .entries
                    .retain(|(stored, _)| !stored.same_value_zero(key));
            }
            let observed_key = state.observer.observe(key)?;
            let observed_value = state.observer.observe(value)?;
            state.observer.record(
                "storage:mutated",
                [
                    ("method".into(), method.into()),
                    ("key".into(), observed_key),
                    ("value".into(), observed_value),
                ],
            );
            state.observer.record(
                "storage:fulfilled",
                [
                    ("slot".into(), slot.into()),
                    ("result".into(), json!({"type":"undefined"})),
                ],
            );
            state.calls.get_mut(index).unwrap().state = "fulfilled";
            Ok(())
        };
        state.calls.get(index).unwrap().done.notify_one();
        result
    }

    fn invoke(
        self: Arc<Self>,
        method: &'static str,
        arguments: Vec<FieldValue>,
    ) -> AuthResult<SecondaryStorageFuture<()>> {
        self.call(method, &arguments)?;
        let key = arguments.first().unwrap().clone();
        let value = arguments.get(1).cloned().unwrap_or_default();
        let (index, plan, gate) = {
            let mut state = self.state.lock().unwrap();
            let slot = slot(&key);
            let plan = plan(&state.scenario, slot);
            let (release, gate) = oneshot::channel();
            let index = state.calls.len();
            state.calls.push(Call {
                slot: slot.into(),
                method,
                plan: plan.clone(),
                state: "pending",
                returned_promise: false,
                reason: FieldValue::Undefined,
                release: plan.starts_with("pending").then_some(release),
                done: Arc::new(Notify::new()),
            });
            (index, plan, gate)
        };
        let future: SecondaryStorageFuture<()> = if plan.starts_with("pending") {
            let storage = self.clone();
            Box::pin(async move {
                gate.await.unwrap();
                storage.complete(index, &key, &value)
            })
        } else {
            let result = self.complete(index, &key, &value);
            if plan == "throw" {
                return Err(result.unwrap_err());
            }
            Box::pin(std::future::ready(result))
        };
        self.state
            .lock()
            .unwrap()
            .calls
            .get_mut(index)
            .unwrap()
            .returned_promise = true;
        Ok(future)
    }
}

#[async_trait]
impl SecondaryStorage for Storage {
    fn invoke_get_native(
        self: Arc<Self>,
        key: FieldValue,
    ) -> AuthResult<SecondaryStorageFuture<Option<FieldValue>>> {
        self.call("get", std::slice::from_ref(&key))?;
        let mut state = self.state.lock().unwrap();
        let result = state
            .entries
            .iter()
            .find(|(stored, _)| stored.same_value_zero(&key))
            .map(|(_, value)| value.clone());
        let observed = state
            .observer
            .observe(&result.clone().unwrap_or(FieldValue::Null))?;
        state.observer.record(
            "storage:get:fulfilled",
            [
                ("slot".into(), slot(&key).into()),
                ("result".into(), observed),
            ],
        );
        Ok(Box::pin(std::future::ready(Ok(result))))
    }

    fn invoke_set_native(
        self: Arc<Self>,
        key: FieldValue,
        value: FieldValue,
        ttl: Option<Option<f64>>,
    ) -> AuthResult<SecondaryStorageFuture<()>> {
        let mut arguments = vec![key, value];
        if let Some(ttl) = ttl {
            arguments.push(ttl.map(FieldValue::from).unwrap_or_default());
        }
        self.invoke("set", arguments)
    }

    fn invoke_delete_native(
        self: Arc<Self>,
        key: FieldValue,
    ) -> AuthResult<SecondaryStorageFuture<()>> {
        self.invoke("delete", vec![key])
    }

    async fn get(&self, _: &str) -> AuthResult<Option<Value>> {
        Err(AuthError::internal(
            "The contract must use the native invocation boundary",
        ))
    }

    async fn set_native(&self, _: &FieldValue, _: &FieldValue, _: Option<f64>) -> AuthResult<()> {
        Err(AuthError::internal(
            "The contract must use the native invocation boundary",
        ))
    }

    async fn delete(&self, _: &str) -> AuthResult<()> {
        Err(AuthError::internal(
            "The contract must use the native invocation boundary",
        ))
    }

    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<Value>> {
        Err(AuthError::internal(
            "API Key cache helpers must not consume atomic verification values",
        ))
    }
}
