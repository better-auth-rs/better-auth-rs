use super::contract::{self as fields, ADDRESS, Fields, Scenario, Trace};
use better_auth::{
    __private_core::{
        AuthError, AuthResult, AuthSchema, AuthStore, AuthUser, CreateUser,
        store::{MemoryCacheAdapter, transaction},
    },
    BetterAuth,
};
use serde_json::{Value, json};
use std::sync::Arc;

#[expect(
    clippy::expect_used,
    reason = "Transaction observations must fail on missing rows or changed callback errors"
)]
pub(super) async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    secondary: bool,
    scenario: Scenario,
) -> AuthResult<()> {
    let reader = BetterAuth::new(fields::config())
        .store_arc(raw.clone())
        .plugin(Fields(fields::policies(None, Scenario::Success)))
        .build()
        .await?;
    let user = reader
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Display fixture")
                .with_email("display@wallet-fields.test"),
        )
        .await?;
    let user_id = user.id().typed()?.to_string();
    let events = Trace::default();
    let mut builder = BetterAuth::new(fields::config())
        .store_arc(raw)
        .plugin(Fields(fields::policies(Some(events.clone()), scenario)));
    if secondary {
        builder = builder.secondary_storage(Arc::new(MemoryCacheAdapter::new()));
    }
    let auth = builder.build().await?;
    events
        .lock()
        .expect("ordinary Wallet trace lock")
        .push(json!(["operation", "create"]));
    let result = if scenario == Scenario::Success {
        let transaction_events = events.clone();
        transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                let created = tx.create_wallet_address(fields::input(user_id)).await?;
                transaction_events
                    .lock()
                    .expect("ordinary Wallet trace lock")
                    .push(json!(["operation", "read-exact"]));
                let read = tx
                    .get_wallet_address(ADDRESS, Some(1))
                    .await?
                    .expect("transaction reads its Wallet display record");
                transaction_events
                    .lock()
                    .expect("ordinary Wallet trace lock")
                    .push(json!(["operation", "read-address"]));
                let by_address = tx
                    .get_wallet_address(ADDRESS, None)
                    .await?
                    .expect("transaction reads its Wallet display record");
                Ok(json!({
                    "created":created.additional_fields.json()?,
                    "readExact":read.additional_fields.json()?,
                    "readAddress":by_address.additional_fields.json()?,
                }))
            })
        })
        .await?
    } else {
        let outcome: AuthResult<()> = transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                let _ = tx.create_wallet_address(fields::input(user_id)).await?;
                Ok(())
            })
        })
        .await;
        let message = "ordinary Wallet output-error";
        let same_error = match outcome {
            Err(AuthError::Internal(actual)) if actual == message => true,
            Err(error) => return Err(error),
            Ok(()) => false,
        };
        json!({"sameError":same_error,"message":message})
    };
    let stored = reader
        .store()
        .get_wallet_address(ADDRESS, Some(1))
        .await?
        .map(|row| row.additional_fields.json())
        .transpose()?;
    let scenario_name = if scenario == Scenario::Success {
        "commit"
    } else {
        "output-error"
    };
    let actual = json!({
        "backend":backend,
        "scenario":scenario_name,
        "events":*events.lock().expect("ordinary Wallet trace lock"),
        "result":result,
        "stored":stored,
    });
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/wallet-transaction-fields-1.7.6.json"
    ))?;
    let expected = fixture
        .get("cases")
        .and_then(Value::as_array)
        .expect("captured Wallet transaction cases")
        .iter()
        .find(|case| case["backend"] == backend && case["scenario"] == scenario_name)
        .expect("captured Wallet transaction scenario");
    assert_eq!(&actual, expected);
    Ok(())
}
