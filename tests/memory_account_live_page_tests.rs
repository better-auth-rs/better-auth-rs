#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Captured fixture keys and the locally installed store must exist; setup errors fail the contract immediately."
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, CreateAccount, CreateUser, UpdateAccount,
    store::{AccountStore, EphemeralStore, JoinValue, UserStore},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
struct Trace {
    enabled: AtomicBool,
    nested: AtomicBool,
    store: Mutex<Weak<EphemeralStore>>,
    events: Mutex<Vec<Value>>,
}

#[tokio::test]
async fn account_children_read_the_selected_live_page_sequentially() -> AuthResult<()> {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/memory-account-live-page-1.7.6.json"))?;
    for case in fixture["cases"].as_array().unwrap() {
        let trace = Arc::new(Trace::default());
        let mut config = AuthConfig::default();
        config.advanced.database.joins = case["joins"].as_bool();
        config.advanced.database.default_find_many_limit = Some(2.0);
        let callback = trace.clone();
        let _ = config.account.additional_fields.insert(
            "displayLabel".into(),
            UserFieldConfig {
                required: Some(false),
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new_async(move |value| {
                        let trace = callback.clone();
                        async move {
                            if !trace.enabled.load(Ordering::SeqCst)
                                || trace.nested.load(Ordering::SeqCst)
                            {
                                return Ok(value);
                            }
                            trace
                                .events
                                .lock()
                                .unwrap()
                                .push(json!(["displayLabel", value.json()?]));
                            if value.as_str() == Some("label-a-before") {
                                trace.nested.store(true, Ordering::SeqCst);
                                let store = trace.store.lock().unwrap().upgrade().unwrap();
                                let changed = store
                                    .update_account(
                                        "ordinary-account-b",
                                        UpdateAccount {
                                            additional_fields: [(
                                                "displayLabel".into(),
                                                "label-b-after".into(),
                                            )]
                                            .into_iter()
                                            .collect(),
                                            ..Default::default()
                                        },
                                    )
                                    .await;
                                trace.nested.store(false, Ordering::SeqCst);
                                let _ = changed?;
                                trace
                                    .events
                                    .lock()
                                    .unwrap()
                                    .push(json!(["display-write", "label-b-after"]));
                            }
                            Ok(format!("{}-visible", value.as_str().unwrap()).into())
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let store = Arc::new(EphemeralStore::new(Arc::new(config)));
        *trace.store.lock().unwrap() = Arc::downgrade(&store);
        let _ = store
            .create_user(CreateUser {
                id: Some("ordinary-user".into()),
                name: Some("ordinary-name".into()).into(),
                email: Some("ordinary@account-page.test".into()),
                email_verified: Some(true),
                ..Default::default()
            })
            .await?;
        for suffix in ["a", "b"] {
            let _ = store
                .create_account(CreateAccount {
                    id: format!("ordinary-account-{suffix}").into(),
                    account_id: format!("ordinary-account-{suffix}").into(),
                    provider_id: "ordinary-provider".into(),
                    user_id: "ordinary-user".into(),
                    additional_fields: [(
                        "displayLabel".into(),
                        format!("label-{suffix}-before").into(),
                    )]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                })
                .await?;
        }
        trace.enabled.store(true, Ordering::SeqCst);
        let joined = store
            .get_user_with_accounts("ordinary@account-page.test")
            .await?
            .unwrap();
        let JoinValue::Many(accounts) = joined.accounts else {
            return Err(AuthError::internal(
                "Expected the Account relationship page",
            ));
        };
        trace.enabled.store(false, Ordering::SeqCst);
        let stored = store.get_user_accounts("ordinary-user").await?;
        assert_eq!(
            json!({
                "joins": case["joins"],
                "events": *trace.events.lock().unwrap(),
                "result": accounts.iter().map(|account| account.additional_fields["displayLabel"].json()).collect::<AuthResult<Vec<_>>>()?,
                "stored": stored.iter().map(|account| account.additional_fields["displayLabel"].json()).collect::<AuthResult<Vec<_>>>()?
            }),
            *case
        );
    }
    Ok(())
}
