use better_auth::{
    AuthConfig,
    config::{IdGeneration, IdGenerator},
    prelude::{CreateAccount, CreateVerification},
};
use better_auth_core::store::{AccountStore, EphemeralStore, VerificationStore};
use chrono::{Duration, Utc};
use std::sync::Arc;

fn account(subject: &str) -> CreateAccount {
    CreateAccount {
        account_id: subject.into(),
        provider_id: "fixture".into(),
        user_id: "owner".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn omitted_memory_ids_keep_distinct_accounts_and_verifications() {
    for policy in [
        IdGeneration::Database,
        IdGeneration::Custom(IdGenerator::new(|_| Ok(None))),
        IdGeneration::Custom(IdGenerator::new(|_| Ok(Some(String::new())))),
    ] {
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id = Some(policy);
        let store = EphemeralStore::new(Arc::new(config));
        for subject in ["first", "second"] {
            let account = store.create_account(account(subject)).await.unwrap();
            assert!(account.id.is_undefined());
            assert!(serde_json::to_value(account).unwrap().get("id").is_none());
            let verification = store
                .create_verification(CreateVerification {
                    identifier: subject.into(),
                    value: "secret".into(),
                    expires_at: (Utc::now() + Duration::minutes(5)).into(),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert!(verification.id.is_undefined());
            assert!(
                serde_json::to_value(verification)
                    .unwrap()
                    .get("id")
                    .is_none()
            );
        }
        let accounts = store.get_user_accounts("owner").await.unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].account_id, "first");
        assert_eq!(accounts[1].account_id, "second");
        for subject in ["first", "second"] {
            assert!(
                store
                    .get_verification_by_identifier(subject)
                    .await
                    .unwrap()
                    .unwrap()
                    .id
                    .is_undefined()
            );
        }
    }
}

#[tokio::test]
async fn memory_serial_uses_current_length_and_retains_duplicate_ids() {
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(IdGeneration::Serial);
    let store = EphemeralStore::new(Arc::new(config));
    let serial_account = |subject: &str| CreateAccount {
        user_id: "1".into(),
        ..account(subject)
    };
    for (subject, expected) in [("first", "1"), ("second", "2"), ("third", "3")] {
        let created = store.create_account(serial_account(subject)).await.unwrap();
        assert_eq!(created.id, expected);
    }
    store.delete_account("2").await.unwrap();
    let next = store
        .create_account(serial_account("fourth"))
        .await
        .unwrap();
    assert_eq!(next.id, "3");
    let rows = store.get_user_accounts("1").await.unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[1].account_id, "third");
    assert_eq!(rows[2].account_id, "fourth");
    store.delete_account("3").await.unwrap();
    let rows = store.get_user_accounts("1").await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].account_id, "first");
}
