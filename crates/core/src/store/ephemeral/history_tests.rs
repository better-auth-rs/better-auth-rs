use super::*;
use crate::store::{AccountOwner, RuntimeStore};
use crate::user_fields::{
    FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform,
};
use serde_json::{Value as JsonValue, json};

fn config() -> AuthConfig {
    let mut config = AuthConfig::default();
    for name in ["id", "image"] {
        let _ = config.user.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                references: Some(UserFieldReference {
                    model: "account".into(),
                    field: "id".into(),
                }),
                ..Default::default()
            },
        );
    }
    config
}

fn fixture() -> JsonValue {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/schema-join-reference-history-1.7.6.json"
    ))
    .unwrap()
}

fn owner_schema(store: &EphemeralStore) -> JsonValue {
    match AccountOwner::validate_schema(&store.config, &store.model_fields, |_, _| false) {
        Ok(()) => JsonValue::Null,
        Err(error) => json!({ "error": error.instrumentation_message() }),
    }
}

#[tokio::test]
async fn schema_history_memory_transaction_creation_matches_capture() {
    let fixture = fixture();
    let cases: Vec<_> = fixture["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["backend"] == "memory")
        .collect();
    assert_eq!(cases.len(), 8);
    for case in cases {
        let mut config = config();
        config.advanced.database.joins = case["joins"].as_bool();
        let parent = EphemeralStore::new(Arc::new(config));
        let mut transaction: Option<(State, EphemeralStore, Arc<PendingHookQueue>)> = None;
        let mut nested: Option<(State, EphemeralStore, Arc<PendingHookQueue>)> = None;
        for observation in case["observations"].as_array().unwrap() {
            let scope = observation["scope"].as_str().unwrap();
            let operation = observation["operation"].as_str().unwrap();
            if operation == "transaction-result" {
                let (base, active, queue) = if scope == "nested" {
                    nested.take().unwrap()
                } else {
                    transaction.take().unwrap()
                };
                if observation["result"] == "committed" {
                    let parent = if scope == "nested" {
                        &transaction.as_ref().unwrap().1
                    } else {
                        &parent
                    };
                    parent
                        .commit_transaction(base, active, queue)
                        .await
                        .unwrap();
                } else {
                    assert_eq!(
                        observation["result"],
                        json!({ "error": "join-history-rollback" })
                    );
                }
                continue;
            }
            let fresh;
            let active = match scope {
                "parent" => &parent,
                "transaction" => {
                    &transaction
                        .get_or_insert_with(|| parent.begin_adapter_transaction().unwrap())
                        .1
                }
                "nested" => {
                    &nested
                        .get_or_insert_with(|| {
                            transaction
                                .as_ref()
                                .unwrap()
                                .1
                                .begin_adapter_transaction()
                                .unwrap()
                        })
                        .1
                }
                "fresh" => {
                    fresh = EphemeralStore::new(parent.config.clone());
                    &fresh
                }
                _ => panic!("Unexpected scope: {scope}"),
            };
            match operation {
                "owner" => assert_eq!(owner_schema(active), observation["result"]),
                "read-user" => assert!(active.get_user_by_id("missing").await.unwrap().is_none()),
                _ => panic!("Unexpected operation: {operation}"),
            }
        }
    }
}

#[tokio::test]
async fn schema_history_memory_input_failure_preserves_callback_and_mutation() {
    let fixture = fixture();
    let expected = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            case["backend"] == "boundary"
                && case["name"] == "input-callback-failure"
                && case["joins"] == false
        })
        .unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = events.clone();
    let mut config = config();
    let _ = config.user.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    captured
                        .lock()
                        .unwrap()
                        .push(json!(["input", "user.name", value.json()?]));
                    Err(AuthError::internal("history-input-failure"))
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let store = EphemeralStore::new(Arc::new(config.clone()));
    assert_eq!(owner_schema(&store), expected["observations"][0]["result"]);
    let error = store
        .create_user(CreateUser {
            name: Some("Owner".into()).into(),
            email: Some("owner@join-history.test".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        json!({"error": error.instrumentation_message()}),
        expected["observations"][1]["result"]
    );
    assert_eq!(
        json!(*events.lock().unwrap()),
        expected["observations"][1]["events"]
    );
    assert_eq!(
        owner_schema(&store.clone()),
        expected["observations"][2]["result"]
    );
    assert_eq!(store.lock().unwrap().users.len(), 0);
    let fresh = store
        .with_runtime(Arc::new(config), Vec::new(), Default::default())
        .unwrap();
    let error = fresh
        .get_account_owner("provider", "missing")
        .await
        .unwrap_err();
    assert_eq!(
        json!({"error": error.instrumentation_message()}),
        expected["observations"][3]["result"]
    );
}

#[tokio::test]
async fn schema_history_memory_atomic_verification_keeps_the_adapter_runtime() {
    let store = EphemeralStore::new(Arc::new(config()));
    assert!(owner_schema(&store).get("error").is_some());
    assert!(
        store
            .verify_user_and_revoke_unproven_access("missing")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(owner_schema(&store), JsonValue::Null);
}
