#![cfg(feature = "seaorm2")]

#[path = "support/jwk_field_contract.rs"]
mod contract;
#[path = "support/jwk_fields.rs"]
mod fixture;

use better_auth::{
    __private_core::{
        AuthError, AuthResult, AuthSchema, AuthStore,
        store::{EphemeralStore, MemoryCacheAdapter, transaction},
    },
    BetterAuth,
};
use contract::{Fields, Scenario, Trace};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn memory_jwk_display_fields_match_pinned_adapter_phases() -> AuthResult<()> {
    for scenario in Scenario::ALL {
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
async fn sqlite_jwk_display_fields_match_pinned_adapter_phases() -> AuthResult<()> {
    for scenario in Scenario::ALL {
        let (store, _) = fixture::sqlite(contract::config()).await;
        contract::contract(Arc::new(store), "sqlite", scenario).await?;
    }
    Ok(())
}

#[tokio::test]
async fn secondary_jwk_display_fields_forward_policies() -> AuthResult<()> {
    let auth = BetterAuth::new(contract::config())
        .store(EphemeralStore::new(Arc::new(contract::config())))
        .secondary_storage(Arc::new(MemoryCacheAdapter::new()))
        .build()
        .await?;
    contract::contract(auth.store().clone(), "memory", Scenario::Success).await
}

#[expect(
    clippy::expect_used,
    reason = "Transaction assertions must fail on missing records or changed callback errors"
)]
async fn transaction_contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    secondary: bool,
) -> AuthResult<()> {
    let events = Trace::default();
    let mut builder = BetterAuth::new(contract::config())
        .store_arc(raw.clone())
        .plugin(Fields(contract::policies(
            Some(events.clone()),
            Scenario::Success,
        )));
    if secondary {
        builder = builder.secondary_storage(Arc::new(MemoryCacheAdapter::new()));
    }
    let auth = builder.build().await?;
    let committed = transaction(auth.store().as_ref(), |tx| {
        Box::pin(async move {
            let created = tx.create_jwk(contract::input()).await?;
            let id = created.id.typed()?.clone();
            let read = tx
                .get_jwk(&id)
                .await?
                .expect("transaction reads its JWK display record");
            let listed: Vec<_> = tx
                .list_jwks()
                .await?
                .into_iter()
                .map(|row| row.additional_fields)
                .collect();
            assert_eq!(read.additional_fields, created.additional_fields);
            assert_eq!(listed, std::slice::from_ref(&created.additional_fields));
            Ok((id, created.additional_fields))
        })
    })
    .await?;
    let expected = json!({
        "label":"Display:out",
        "note":"default-note",
        "settings":{"compact":true,"theme":"dark"},
    });
    assert_eq!(json!(committed.1), expected);
    let read = auth
        .store()
        .get_jwk(&committed.0)
        .await?
        .expect("committed JWK display record exists");
    assert_eq!(json!(read.additional_fields), expected);
    let before: Vec<_> = auth
        .store()
        .list_jwks()
        .await?
        .into_iter()
        .map(|row| row.additional_fields)
        .collect();
    assert_eq!(json!(before), json!([expected]));

    let failed_events = Trace::default();
    let mut failed_builder = BetterAuth::new(contract::config())
        .store_arc(raw)
        .plugin(Fields(contract::policies(
            Some(failed_events.clone()),
            Scenario::OutputError,
        )));
    if secondary {
        failed_builder = failed_builder.secondary_storage(Arc::new(MemoryCacheAdapter::new()));
    }
    let failed_auth = failed_builder.build().await?;
    let result: AuthResult<()> = transaction(failed_auth.store().as_ref(), |tx| {
        Box::pin(async move {
            let _ = tx.create_jwk(contract::input()).await?;
            Ok(())
        })
    })
    .await;
    assert!(
        matches!(result, Err(AuthError::Internal(message)) if message == "ordinary JWK output-error")
    );
    assert_eq!(
        *failed_events.lock().expect("ordinary JWK trace lock"),
        vec![
            json!(["input", "label", " Display "]),
            json!(["input", "note", "default-note"]),
            json!(["input", "settings", {"compact":true,"theme":"dark"}]),
            json!(["output", "label", "Display"]),
        ],
    );
    let after: Vec<_> = auth
        .store()
        .list_jwks()
        .await?
        .into_iter()
        .map(|row| row.additional_fields)
        .collect();
    assert_eq!(after, before);
    Ok(())
}

#[tokio::test]
async fn memory_jwk_display_transaction_commit_and_callback_rollback() -> AuthResult<()> {
    for secondary in [false, true] {
        transaction_contract(
            Arc::new(EphemeralStore::new(Arc::new(contract::config()))),
            secondary,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_jwk_display_transaction_commit_and_callback_rollback() -> AuthResult<()> {
    for secondary in [false, true] {
        let (store, _) = fixture::sqlite(contract::config()).await;
        transaction_contract(Arc::new(store), secondary).await?;
    }
    Ok(())
}
