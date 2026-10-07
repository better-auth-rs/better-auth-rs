use super::*;
use better_auth_core::store::{AccountOwner, RuntimeStore, UserStore};
use better_auth_core::user_fields::{
    FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform,
};
use serde_json::{Value, json};

type Transaction = SeaOrmTransaction<
    bundled_schema::BundledSchema,
    crate::OrganizationModels,
    crate::PluginModels,
>;

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

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/schema-join-reference-history-1.7.6.json"
    ))
    .unwrap()
}

fn owner_schema(store: &SeaOrmStore<bundled_schema::BundledSchema>) -> Value {
    match AccountOwner::validate_schema(&store.config, &store.model_fields, |_, _| false) {
        Ok(()) => Value::Null,
        Err(error) => json!({ "error": error.instrumentation_message() }),
    }
}

async fn store(config: AuthConfig) -> SeaOrmStore<bundled_schema::BundledSchema> {
    let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
    SeaOrmStore::new(config, db)
}

#[tokio::test]
async fn schema_history_sqlite_transaction_creation_matches_capture() {
    let fixture = fixture();
    let cases: Vec<_> = fixture["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["backend"] == "sqlite" && case["transaction"] == true)
        .collect();
    assert_eq!(cases.len(), 8);
    for case in cases {
        let mut config = config();
        config.advanced.database.joins = case["joins"].as_bool();
        let parent = store(config).await;
        let effects = Arc::new(Mutex::new(Vec::new()));
        let mut transaction: Option<Transaction> = None;
        for observation in case["observations"].as_array().unwrap() {
            let scope = observation["scope"].as_str().unwrap();
            let operation = observation["operation"].as_str().unwrap();
            if operation == "transaction-result" {
                if scope == "transaction" {
                    let active = transaction.take().unwrap();
                    if observation["result"] == "committed" {
                        active.tx.commit().await.unwrap();
                    } else {
                        active.tx.rollback().await.unwrap();
                    }
                }
                continue;
            }
            if matches!(scope, "transaction" | "nested") && transaction.is_none() {
                transaction = Some(SeaOrmTransaction::begin(&parent, &effects).await.unwrap());
            }
            match operation {
                "owner" => {
                    let fresh;
                    let active = match scope {
                        "parent" => &parent,
                        "transaction" | "nested" => &transaction.as_ref().unwrap().store,
                        "fresh" => {
                            fresh = SeaOrmStore::new(parent.config.clone(), parent.db.clone());
                            &fresh
                        }
                        _ => panic!("Unexpected scope: {scope}"),
                    };
                    assert_eq!(owner_schema(active), observation["result"]);
                }
                "read-user" => {
                    let user = if scope == "parent" {
                        parent.get_user_by_id("missing").await.unwrap()
                    } else {
                        transaction
                            .as_ref()
                            .unwrap()
                            .get_user_by_id("missing")
                            .await
                            .unwrap()
                    };
                    assert!(user.is_none());
                }
                _ => panic!("Unexpected operation: {operation}"),
            }
        }
    }
}

#[tokio::test]
async fn schema_history_sqlite_input_failure_preserves_callback_and_mutation() {
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
                        .push(json!(["input", "user.name", value]));
                    Err(AuthError::internal("history-input-failure"))
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let store = store(config.clone()).await;
    assert_eq!(owner_schema(&store), expected["observations"][0]["result"]);
    let error = store
        .create_user(better_auth_core::CreateUser {
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
async fn schema_history_sqlite_generator_failure_keeps_the_input_mutation() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = calls.clone();
    let mut config = config();
    config.advanced.database.generate_id = Some(better_auth_core::id::IdGeneration::Custom(
        better_auth_core::id::IdGenerator::new(move |request| {
            recorded
                .lock()
                .unwrap()
                .push((request.model.to_owned(), request.size));
            Err(AuthError::internal("history-generator-failure"))
        }),
    ));
    let store = store(config).await;
    assert!(owner_schema(&store).get("error").is_some());
    let error = store
        .create_user(better_auth_core::CreateUser {
            name: Some("Owner".into()).into(),
            email: Some("owner@join-history.test".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.instrumentation_message(), "history-generator-failure");
    assert_eq!(*calls.lock().unwrap(), [("user".to_owned(), None)]);
    assert_eq!(owner_schema(&store), Value::Null);
}

#[tokio::test]
async fn schema_history_sqlite_atomic_verification_keeps_the_adapter_runtime() {
    let store = store(config()).await;
    assert!(owner_schema(&store).get("error").is_some());
    assert!(
        store
            .verify_user_and_revoke_unproven_access("missing")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(owner_schema(&store), Value::Null);
}
