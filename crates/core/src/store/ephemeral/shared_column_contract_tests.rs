//! Exercise the production record engine without adding business Store lifecycle behavior.

use super::EphemeralStore;
use crate as auth_core;
use crate::native_test_observation::assert_replay;
use crate::native_test_replay_failures::ReplayFailures;
use crate::{AuthConfig, AuthError, AuthResult, FieldMap, FieldValue, store::schema::EntityRole};
use std::sync::Arc;

#[path = "../../../../../tests/support/shared_column_contract.rs"]
mod contract;

struct Adapter {
    store: EphemeralStore,
    role: EntityRole,
}

#[crate::__private_async_trait::async_trait]
impl contract::Adapter for Adapter {
    async fn execute(&self, method: &str, input: FieldMap) -> AuthResult<FieldValue> {
        match method {
            "create" => {
                assert_eq!(input.get("forceAllowId"), Some(&true.into()));
                self.store
                    .create_plugin_record(
                        self.role,
                        contract::parameter(&input, "data")?,
                        FieldMap::new(),
                    )
                    .await
                    .map(Into::into)
            }
            "findOne" => self
                .store
                .get_plugin_record(self.role, &contract::identifier(&input)?)
                .await
                .map(|row| row.map_or(FieldValue::Null, Into::into)),
            "update" => self
                .store
                .update_plugin_record(
                    self.role,
                    &contract::identifier(&input)?,
                    contract::parameter(&input, "update")?,
                    FieldMap::new(),
                )
                .await
                .map(|row| row.map_or(FieldValue::Null, Into::into)),
            "delete" => {
                self.store
                    .delete_plugin_records(self.role, &contract::identifier(&input)?)
                    .await?;
                Ok(FieldValue::Undefined)
            }
            _ => Err(AuthError::internal("Unknown captured adapter method")),
        }
    }

    async fn stored(&self) -> AuthResult<Vec<FieldMap>> {
        self.store.storage_rows(self.role)
    }
}

#[tokio::test]
async fn shared_record_crud_matches_all_pinned_memory_column_collisions() -> AuthResult<()> {
    for case in contract::cases("memory")? {
        let (runtime, role, trace) = contract::runtime(&case)?;
        let store = EphemeralStore::from_schema(Arc::new(AuthConfig::default()), &runtime);
        contract::run(&Adapter { store, role }, &case, &trace).await?;
    }
    Ok(())
}
