#![cfg(feature = "seaorm2")]

#[path = "support/plugin_display_json_contract.rs"]
mod contract;

use better_auth::__private_core::{
    AuthStore, FieldValue,
    store::{ApiKeyStore, EphemeralStore, PasskeyStore, StatelessSchema},
};
use contract::{Target, TestResult};
use serde_json::{Value, json};
use std::sync::Arc;

async fn stored(store: &EphemeralStore, target: Target) -> TestResult<Value> {
    let record = if target == Target::ApiKeyName {
        store
            .get_api_key_by_id(contract::ID)
            .await?
            .map(|row| FieldValue::from_json(serde_json::to_value(row)?)?.json())
            .transpose()?
            .flatten()
    } else {
        store
            .get_passkey_by_id(contract::ID)
            .await?
            .map(|row| {
                let mut value = serde_json::to_value(&row)?;
                let credential = row
                    .credential
                    .field_value()
                    .json()?
                    .ok_or("Missing Memory credential")?;
                let _ = value
                    .as_object_mut()
                    .ok_or("Expected a Memory Passkey record")?
                    .insert("credential".into(), credential);
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(value)
            })
            .transpose()?
    };
    let Some(mut record) = record else {
        return Ok(json!([]));
    };
    let fields = record.as_object_mut().ok_or("Expected a Memory record")?;
    // Preserve omission from the stored record; the output observer tags Undefined separately.
    if let Some(display) = fields.remove(target.field()) {
        let _ = fields.insert("stored_display".into(), display);
    }
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
