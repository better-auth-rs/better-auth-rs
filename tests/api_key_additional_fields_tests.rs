#![cfg(feature = "seaorm2")]

#[path = "support/ordinary_field_policies.rs"]
mod ordinary_field_policies;

#[path = "support/api_key_field_contract.rs"]
mod contract;
#[path = "api_key_additional_fields_tests/enabled_boundary.rs"]
mod enabled_boundary;
#[path = "support/api_key_fields.rs"]
mod fixture;
#[path = "support/api_key_live_fields.rs"]
mod live;
#[path = "api_key_additional_fields_tests/name_mapping.rs"]
mod name_mapping;
#[path = "api_key_additional_fields_tests/name_mapping_conflicts.rs"]
mod name_mapping_conflicts;
#[path = "support/api_key_name_mapping_contract.rs"]
mod name_mapping_contract;
#[path = "api_key_additional_fields_tests/native_replacements.rs"]
mod native_replacements;

use better_auth::{
    __private_core::{
        AuthResult,
        store::{EphemeralStore, MemoryCacheAdapter},
        user_fields::{UserConfig, UserFieldConfig},
    },
    BetterAuth,
};
use std::sync::Arc;

#[tokio::test]
async fn memory_api_key_name_callbacks_refresh_later_native_and_additional_fields() -> AuthResult<()>
{
    for fail_output in [false, true] {
        live::contract(
            Arc::new(EphemeralStore::new(Arc::new(contract::config()))),
            "memory",
            fail_output,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_api_key_name_callbacks_keep_the_selected_native_and_additional_snapshot()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for fail_output in [false, true] {
        let (store, database) = fixture::sqlite(contract::config()).await;
        live::contract(Arc::new(store), "sqlite", fail_output).await?;
        database.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_api_key_fields_match_complete_pinned_operations_and_errors() -> AuthResult<()> {
    for scenario in contract::Scenario::all() {
        contract::contract(
            Arc::new(EphemeralStore::new(Arc::new(contract::config()))),
            "memory",
            scenario,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_api_key_fields_match_complete_pinned_operations_and_errors()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for scenario in contract::Scenario::all() {
        let (store, database) = fixture::sqlite(contract::config()).await;
        contract::contract(Arc::new(store), "sqlite", scenario).await?;
        database.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_api_key_usage_dates_match_complete_pinned_operations() -> AuthResult<()> {
    contract::usage_dates::contract(
        Arc::new(EphemeralStore::new(Arc::new(contract::config()))),
        "memory",
    )
    .await
}

#[tokio::test]
async fn sqlite_api_key_usage_dates_match_complete_pinned_operations()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (store, database) = fixture::sqlite(contract::config()).await;
    contract::usage_dates::contract(Arc::new(store), "sqlite").await?;
    database.close().await?;
    Ok(())
}

#[tokio::test]
async fn secondary_api_key_fields_forward_policies_and_extra_values() -> AuthResult<()> {
    let auth = BetterAuth::new(contract::config())
        .store(EphemeralStore::new(Arc::new(contract::config())))
        .secondary_storage(Arc::new(MemoryCacheAdapter::new()))
        .build()
        .await?;
    contract::contract(
        auth.store().clone(),
        "memory",
        contract::Scenario::Operations,
    )
    .await
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The declaration contract asserts successful initialization while propagating database errors"
)]
async fn api_key_additional_fields_accept_complete_native_and_alias_declarations()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for (name, column) in [
        ("key", None),
        ("keyHash", None),
        ("key_hash", None),
        ("referenceId", None),
        ("configId", None),
        ("requestCount", None),
        ("remaining", None),
        ("label", Some("stored_key")),
        ("label", Some("stored_owner")),
        ("label", Some("stored_count")),
    ] {
        let (store, database) = fixture::sqlite(contract::config()).await;
        let fields = UserConfig {
            additional_fields: Some(
                [(
                    name.into(),
                    UserFieldConfig {
                        field_name: column.map(str::to_owned),
                        required: Some(false),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        };
        let result = BetterAuth::new(contract::config())
            .store(store)
            .plugin(contract::Fields(fields))
            .build()
            .await;
        assert!(result.is_ok(), "{name}/{column:?}: {:?}", result.err());
        database.close().await?;
    }
    Ok(())
}
