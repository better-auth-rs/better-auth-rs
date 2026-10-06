#![cfg(feature = "seaorm2")]

#[path = "support/passkey_field_contract.rs"]
mod contract;
#[path = "support/passkey_fields.rs"]
mod fixture;

use better_auth::{
    __private_core::{
        AuthError, AuthResult,
        store::{EphemeralStore, MemoryCacheAdapter},
        user_fields::{UserConfig, UserFieldConfig},
    },
    BetterAuth,
};
use std::sync::Arc;

#[tokio::test]
async fn memory_passkey_fields_match_complete_pinned_operations_and_errors() -> AuthResult<()> {
    for scenario in contract::Scenario::ALL {
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
async fn sqlite_passkey_fields_match_complete_pinned_operations_and_errors()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for scenario in contract::Scenario::ALL {
        let (store, database) = fixture::sqlite(contract::config()).await;
        contract::contract(Arc::new(store), "sqlite", scenario).await?;
        database.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn secondary_passkey_fields_forward_policies_and_extra_values() -> AuthResult<()> {
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
async fn passkey_additional_fields_cannot_replace_native_identity_or_credential_columns() {
    for (name, column) in [
        ("credential", None),
        ("userId", None),
        ("counter", None),
        ("label", Some("credential")),
        ("label", Some("stored_owner")),
        ("label", Some("stored_counter")),
    ] {
        let (store, _) = fixture::sqlite(contract::config()).await;
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
        assert!(
            matches!(result, Err(AuthError::Config(_))),
            "{name}/{column:?}"
        );
    }
}
