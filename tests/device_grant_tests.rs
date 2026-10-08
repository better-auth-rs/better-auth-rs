#[path = "support/device_grant_contract.rs"]
mod contract;

use better_auth_core::{AuthError, AuthResult, store::EphemeralStore};
use chrono as contract_chrono;
use serde_json::Value;
use std::sync::Arc;

#[tokio::test]
async fn ordinary_device_grant_http_and_native_lifecycles_match_pinned_upstream() -> AuthResult<()>
{
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/device-grant-1.7.6.json");
    let content = std::fs::read_to_string(path)
        .map_err(|error| AuthError::internal(format!("Read Device grant fixture: {error}")))?;
    let fixture: Value = serde_json::from_str(&content)?;
    for expected in contract::cases(&fixture)? {
        contract::check(
            Arc::new(EphemeralStore::new(Arc::new(contract::config()))),
            expected,
        )
        .await?;
    }
    Ok(())
}
