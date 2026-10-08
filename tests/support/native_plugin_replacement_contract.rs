#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "The paired contract requires complete recorded operations and fails on invalid fixture shapes"
)]

use better_auth::__private_core::{
    __private_async_trait::async_trait, AuthError, AuthResult, FieldMap, FieldValue,
};
use serde_json::{Value, json};
use std::future::Future;

#[path = "native_plugin_replacement_observation.rs"]
mod observation;
#[path = "native_plugin_replacement_policies.rs"]
mod policies;
pub(crate) use policies::{Policy, config};
#[path = "native_plugin_replacement_target.rs"]
mod target;
pub(crate) use target::Target;
#[path = "native_plugin_replacement_store.rs"]
mod store;
pub(crate) use store::with_store;

mod values {
    use better_auth::__private_core as better_auth_core;
    use better_auth::seaorm::__private_chrono as chrono;
    include!("device_where_values.rs");
}

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(crate) const ID: &str = "native-replacement-row";
pub(crate) const OWNER: &str = "native-replacement-owner";
pub(crate) const TARGETS: [&str; 9] = [
    "api-key-remaining-number",
    "api-key-remaining-string",
    "api-key-enabled-boolean",
    "api-key-enabled-number",
    "api-key-expiry-date",
    "passkey-counter-string",
    "passkey-backup-boolean",
    "device-polling-number",
    "two-factor-verified-boolean",
];

pub(crate) fn observe(value: &FieldValue) -> AuthResult<Value> {
    values::observe(value)
}

pub(crate) fn fixture(path: &std::path::Path, backend: &str, name: &str) -> TestResult<Value> {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["backend"], backend);
    let targets = fixture["targets"]
        .as_array()
        .ok_or("Missing replacement targets")?;
    assert_eq!(
        targets
            .iter()
            .map(|target| target["name"].as_str())
            .collect::<Vec<_>>(),
        [
            "api-key-remaining-number",
            "api-key-remaining-string",
            "api-key-enabled-boolean",
            "api-key-enabled-number",
            "api-key-expiry-date",
            "passkey-counter-string",
            "passkey-backup-boolean",
            "device-polling-number",
            "two-factor-verified-boolean",
            "jwk-algorithm-array",
            "wallet-owner-number",
            "wallet-chain-number",
        ]
        .map(Some)
    );
    for value in targets {
        let _ = Target::from_fixture(value)?;
    }
    targets
        .iter()
        .find(|target| target["name"] == name)
        .cloned()
        .ok_or_else(|| "Missing native replacement target".into())
}

#[async_trait]
pub(crate) trait Adapter: Send + Sync {
    async fn create(&self, fields: FieldMap) -> AuthResult<Option<FieldMap>>;
    async fn read(&self, id: FieldValue) -> AuthResult<Option<FieldMap>>;
    async fn update(&self, id: FieldValue, fields: FieldMap) -> AuthResult<Option<FieldMap>>;
    async fn delete(&self, id: FieldValue) -> AuthResult<Option<FieldMap>>;
    async fn stored(&self) -> TestResult<Value>;
}

fn record(value: &Value) -> AuthResult<FieldMap> {
    values::revive(value)?
        .as_object()
        .cloned()
        .ok_or_else(|| AuthError::internal("Expected an observed record"))
}

async fn operate(
    adapter: &impl Adapter,
    target: &Target,
    expected: &Value,
) -> AuthResult<Option<FieldMap>> {
    assert_eq!(expected["input"]["model"], target.model);
    if expected["method"] != "create" {
        assert_eq!(
            expected["input"]["where"],
            json!([{"field":"id", "value":ID}])
        );
    }
    match expected["method"].as_str() {
        Some("create") => {
            assert_eq!(expected["input"]["forceAllowId"], true);
            adapter.create(record(&expected["input"]["data"])?).await
        }
        Some("update") => {
            adapter
                .update(ID.into(), record(&expected["input"]["update"])?)
                .await
        }
        Some("findOne") => adapter.read(ID.into()).await,
        _ => Err(AuthError::internal("Unknown native replacement operation")),
    }
}

struct Check {
    target: Target,
    state: policies::Shared,
}

impl Check {
    async fn observe(&self, adapter: &impl Adapter, expected: &Value) -> TestResult {
        let before = adapter.stored().await?;
        let result = operate(adapter, &self.target, expected).await;
        let stored = adapter.stored().await?;
        observation::compare(
            &before,
            &stored,
            &result,
            &mut self.state.lock().expect("replacement observation state"),
            expected,
        )
    }

    async fn reset(&self, adapter: &impl Adapter) -> TestResult {
        {
            let mut state = self.state.lock().expect("replacement reset state");
            assert!(state.events.is_empty());
            *state = Default::default();
        }
        let _ = adapter.delete(ID.into()).await?;
        assert_eq!(adapter.stored().await?, json!([]));
        Ok(())
    }
}

pub(crate) async fn contract<A, F, Fut>(backend: &str, expected: Value, build: F) -> TestResult
where
    A: Adapter,
    F: Fn(Policy) -> Fut,
    Fut: Future<Output = TestResult<A>>,
{
    let target = Target::from_fixture(&expected)?;
    let state = policies::Shared::default();
    let policy = |defaults| Policy {
        target: target.clone(),
        defaults,
        state: state.clone(),
    };
    let adapter = build(policy(false)).await?;
    let defaults = build(policy(true)).await?;
    let check = Check {
        target: target.clone(),
        state: state.clone(),
    };
    let cases = expected["cases"]
        .as_array()
        .ok_or("Missing replacement cases")?;
    assert_eq!(
        cases
            .iter()
            .map(|case| case["name"].as_str())
            .collect::<Vec<_>>(),
        ["provided", "omitted", "undefined", "null"].map(Some)
    );
    let mut count = 0;
    for case in cases {
        check.reset(&adapter).await?;
        let operations = case["operations"]
            .as_array()
            .ok_or("Missing replacement operations")?;
        assert_eq!(
            operations
                .iter()
                .map(|op| op["name"].as_str())
                .collect::<Vec<_>>(),
            ["create", "read-created", "update", "read-updated"].map(Some)
        );
        for operation in operations {
            check.observe(&adapter, operation).await?;
            count += 1;
        }
    }
    check.reset(&adapter).await?;
    let operations = expected["defaults"]
        .as_array()
        .ok_or("Missing replacement default operations")?;
    assert_eq!(
        operations
            .iter()
            .map(|op| op["name"].as_str())
            .collect::<Vec<_>>(),
        ["create-default", "update-default", "read-default"].map(Some)
    );
    for operation in operations {
        check.observe(&defaults, operation).await?;
        count += 1;
    }
    check.reset(&adapter).await?;
    state
        .lock()
        .expect("replacement transformation state")
        .replace_input = true;
    check.observe(&adapter, &expected["transformed"]).await?;
    count += 1;
    state
        .lock()
        .expect("replacement transformation state")
        .replace_input = false;
    let projections = expected["projections"]
        .as_array()
        .ok_or("Missing replacement projections")?;
    assert_eq!(
        projections
            .iter()
            .map(|op| op["name"].as_str())
            .collect::<Vec<_>>(),
        ["object", "null", "undefined"].map(Some)
    );
    for operation in projections {
        state
            .lock()
            .expect("replacement projection state")
            .projection = Some(match operation["name"].as_str() {
            Some("object") => {
                FieldValue::from_json(json!({"source":"output","field":target.field}))?
            }
            Some("null") => FieldValue::Null,
            Some("undefined") => FieldValue::Undefined,
            _ => return Err("Unknown replacement projection".into()),
        });
        check.observe(&adapter, operation).await?;
        count += 1;
    }
    let failures = expected["failures"]
        .as_array()
        .ok_or("Missing replacement failures")?;
    assert_eq!(
        failures
            .iter()
            .map(|op| op["name"].as_str())
            .collect::<Vec<_>>(),
        [
            "create-default",
            "create-input",
            "create-output",
            "update-onUpdate",
            "update-input",
            "update-output",
            "read-output"
        ]
        .map(Some)
    );
    for failure in failures {
        check.reset(&adapter).await?;
        if !failure["seed"].is_null() {
            check.observe(&adapter, &failure["seed"]).await?;
            count += 1;
        }
        observation::storage(&adapter.stored().await?, &failure["before"])?;
        let (_, phase) = failure["name"]
            .as_str()
            .ok_or("Missing failure name")?
            .split_once('-')
            .ok_or("Invalid failure name")?;
        state.lock().expect("replacement failure state").fail(phase);
        check.observe(&defaults, &failure["result"]).await?;
        count += 1;
    }
    assert_eq!(count, 34);
    eprintln!(
        "native replacement boundaries: backend={backend}; target={}; all values, timestamps, field presence, and field order are paired",
        target.name
    );
    Ok(())
}
