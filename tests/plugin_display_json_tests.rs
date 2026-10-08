#![cfg(feature = "seaorm2")]

#[path = "support/plugin_display_json_contract.rs"]
mod contract;

use better_auth::__private_core::{
    AuthStore, FieldValue,
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
};
use contract::{Target, TestResult};
use serde_json::{Value, json};
use std::sync::Arc;

async fn stored(store: &EphemeralStore, target: Target) -> TestResult<Value> {
    let role = if target == Target::ApiKeyName {
        EntityRole::ApiKey
    } else {
        EntityRole::Passkey
    };
    let rows = store.plugin_storage_rows(role)?;
    assert!(rows.len() <= 1);
    let Some(record) = rows.into_iter().next() else {
        return Ok(json!([]));
    };
    let record = FieldValue::from(record)
        .json()?
        .ok_or("Missing Memory record")?;
    let fields = record.as_object().ok_or("Expected a Memory record")?;
    let keys = fields.keys().cloned().collect::<Vec<_>>();
    Ok(json!([{"row": record, "keys": keys}]))
}

#[tokio::test]
async fn memory_plugin_display_json_matches_pinned_adapter_observations() -> TestResult {
    for target in Target::ALL {
        let raw = Arc::new(EphemeralStore::new(Arc::new(contract::config())));
        let observer = raw.clone();
        let store: Arc<dyn AuthStore<StatelessSchema>> = raw;
        let expected = contract::fixture(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/plugin-display-json-memory-1.7.6.json"),
            "memory",
            target,
        )?;
        contract::contract(store, "memory", target, expected, move || {
            let observer = observer.clone();
            async move { stored(&observer, target).await }
        })
        .await?;
    }
    Ok(())
}
