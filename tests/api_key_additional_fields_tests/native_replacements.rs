#[path = "../support/native_plugin_replacement_contract.rs"]
mod contract;

use better_auth::__private_core::{FieldValue, store::EphemeralStore};
use contract::TestResult;
use serde_json::{Value, json};
use std::sync::Arc;

#[tokio::test]
async fn memory_native_plugin_replacements_match_complete_operations() -> TestResult {
    for name in contract::TARGETS {
        let raw = Arc::new(EphemeralStore::new(Arc::new(contract::config())));
        let expected = contract::fixture(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/native-plugin-replacements-memory-1.7.6.json"),
            "memory",
            name,
        )?;
        let role = contract::Target::from_fixture(&expected)?.role;
        contract::with_store(raw.clone(), "memory", expected, move || {
            let raw = raw.clone();
            async move {
                let rows = raw.plugin_storage_rows(role)?;
                Ok(Value::Array(
                    rows.into_iter()
                        .map(|row| {
                            let keys = row.keys().cloned().collect::<Vec<_>>();
                            let row = contract::observe(&FieldValue::from(row))?;
                            Ok(json!({"row": row, "keys": keys}))
                        })
                        .collect::<TestResult<_>>()?,
                ))
            }
        })
        .await?;
    }
    Ok(())
}
