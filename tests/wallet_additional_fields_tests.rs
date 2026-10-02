#![cfg(feature = "seaorm2")]

#[path = "support/wallet_field_contract.rs"]
mod contract;
#[path = "support/wallet_fields.rs"]
mod fixture;
#[path = "support/wallet_transaction_contract.rs"]
mod transactions;

use better_auth::{
    __private_core::{
        AuthResult,
        store::{EphemeralStore, MemoryCacheAdapter},
    },
    BetterAuth,
};
use std::sync::Arc;

#[tokio::test]
async fn memory_wallet_display_fields_match_pinned_adapter_phases() -> AuthResult<()> {
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
async fn sqlite_wallet_display_fields_match_pinned_adapter_phases() -> AuthResult<()> {
    for scenario in contract::Scenario::ALL {
        let (store, _) = fixture::sqlite(contract::config()).await;
        contract::contract(Arc::new(store), "sqlite", scenario).await?;
    }
    Ok(())
}

#[tokio::test]
async fn secondary_wallet_display_fields_forward_policies() -> AuthResult<()> {
    let auth = BetterAuth::new(contract::config())
        .store(EphemeralStore::new(Arc::new(contract::config())))
        .secondary_storage(Arc::new(MemoryCacheAdapter::new()))
        .build()
        .await?;
    contract::contract(auth.store().clone(), "memory", contract::Scenario::Success).await
}

#[tokio::test]
async fn memory_wallet_display_transactions_match_pinned_commit_and_rollback() -> AuthResult<()> {
    for secondary in [false, true] {
        for scenario in [contract::Scenario::Success, contract::Scenario::OutputError] {
            transactions::contract(
                Arc::new(EphemeralStore::new(Arc::new(contract::config()))),
                "memory",
                secondary,
                scenario,
            )
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_wallet_display_transactions_match_pinned_commit_and_rollback() -> AuthResult<()> {
    for secondary in [false, true] {
        for scenario in [contract::Scenario::Success, contract::Scenario::OutputError] {
            let (store, _) = fixture::sqlite(contract::config()).await;
            transactions::contract(Arc::new(store), "sqlite", secondary, scenario).await?;
        }
    }
    Ok(())
}
