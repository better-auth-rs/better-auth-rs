#![cfg(all(feature = "seaorm2", feature = "axum"))]

#[path = "support/api_key_number_name_contract.rs"]
mod contract;

use better_auth::__private_core::{
    FieldValue,
    store::{EphemeralStore, schema::EntityRole},
};
use contract::{Scenario, TestResult};
use serde_json::{Value, json};
use std::sync::Arc;

async fn stored(store: &EphemeralStore) -> TestResult<Value> {
    let mut result = Vec::new();
    for row in store.plugin_storage_rows(EntityRole::ApiKey)? {
        let mut value = FieldValue::from(row)
            .json()?
            .ok_or("API Key must serialize")?;
        let fields = value.as_object_mut().ok_or("Expected an API Key object")?;
        assert!(!fields.contains_key("permissions"));
        for field in ["createdAt", "updatedAt"] {
            let date = fields.get_mut(field).ok_or("Missing API Key date")?;
            *date = json!({"type":"date", "value": date});
        }
        result.push(value);
    }
    Ok(Value::Array(result))
}

async fn run(scenario: Scenario) -> TestResult {
    for required in [true, false] {
        let raw = Arc::new(EphemeralStore::new(Arc::new(contract::config())));
        let observer = raw.clone();
        contract::contract(
            raw,
            contract::fixture("memory", required, scenario)?,
            scenario,
            move || {
                let observer = observer.clone();
                async move { stored(&observer).await }
            },
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_api_key_number_name_matches_pinned_http_and_storage() -> TestResult {
    run(Scenario::Defaults).await
}

#[tokio::test]
async fn memory_api_key_number_name_order_matches_pinned_http_and_storage() -> TestResult {
    run(Scenario::Ordering).await
}
