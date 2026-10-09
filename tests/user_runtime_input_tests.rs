#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "The paired input contract fails immediately on missing records or malformed shared cases"
)]

use better_auth_core::{AuthConfig, AuthResult, store::EphemeralStore};
use std::sync::Arc;

#[path = "support/user_runtime_output_contract.rs"]
#[expect(
    dead_code,
    reason = "The shared contract also supplies output callback helpers"
)]
mod contract;

#[path = "support/username_native_input.rs"]
mod username_native_input;

use contract::write;

async fn raw(config: &AuthConfig, create: bool) -> AuthResult<Arc<EphemeralStore>> {
    if create {
        Ok(Arc::new(EphemeralStore::new(Arc::new(config.clone()))))
    } else {
        Ok(contract::seed(config).await?.0)
    }
}
