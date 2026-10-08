#[path = "../support/native_plugin_replacement_contract.rs"]
mod contract;

use better_auth::__private_core::{FieldValue, store::EphemeralStore};
use contract::TestResult;
use serde_json::{Value, json};
use std::sync::Arc;

async fn check(name: &str) -> TestResult {
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
    .await
}

macro_rules! target {
    ($module:ident, $name:literal) => {
        mod $module {
            #[tokio::test]
            async fn memory_native_plugin_replacements_match_complete_operations()
            -> super::TestResult {
                super::check($name).await
            }
        }
    };
}

target!(api_key_remaining_number, "api-key-remaining-number");
target!(api_key_remaining_string, "api-key-remaining-string");
target!(api_key_enabled_boolean, "api-key-enabled-boolean");
target!(api_key_enabled_number, "api-key-enabled-number");
target!(api_key_expiry_date, "api-key-expiry-date");
target!(passkey_counter_string, "passkey-counter-string");
target!(passkey_backup_boolean, "passkey-backup-boolean");
target!(device_polling_number, "device-polling-number");
target!(two_factor_verified_boolean, "two-factor-verified-boolean");
target!(jwk_algorithm_array, "jwk-algorithm-array");
target!(wallet_owner_number, "wallet-owner-number");
target!(wallet_chain_number, "wallet-chain-number");
