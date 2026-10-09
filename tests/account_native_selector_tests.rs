#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Fixture setup and hook observations must fail immediately on unexpected errors"
)]

use std::sync::{Arc, Mutex};

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateUser,
    FieldValue, Utf16String,
    id::IdGeneration,
    store::{
        AccountStore, EphemeralStore, MemoryCacheAdapter,
        database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks},
        secondary::SecondaryStore,
    },
    user_fields::{UserFieldConfig, UserFieldType},
    wire::AccountView,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};

type Events = Arc<Mutex<Vec<String>>>;

struct ObserveDelete(Events);

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for ObserveDelete {
    async fn before_delete_account(
        &self,
        account: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        let subject = account.account_id.typed()?;
        self.0.lock().unwrap().push(format!("before:{subject}"));
        Ok(if subject == "cancelled" {
            DatabaseHookControl::Cancel
        } else {
            DatabaseHookControl::Continue
        })
    }

    async fn after_delete_account(
        &self,
        account: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let subject = account.account_id.typed()?;
        self.0.lock().unwrap().push(format!("after:{subject}"));
        if subject == "failed" {
            return Err(AuthError::internal("account after hook failed"));
        }
        Ok(())
    }
}

async fn check<S: AuthSchema>(
    inner: Arc<dyn AuthStore<S>>,
    mut config: AuthConfig,
    secondary: bool,
) -> AuthResult<()> {
    let owner = inner
        .create_user(CreateUser::new().with_email("native-account@example.test"))
        .await?;
    for (id, subject) in [("1", "deleted"), ("2", "cancelled"), ("3", "failed")] {
        let created = inner
            .create_account(CreateAccount {
                id: id.into(),
                account_id: subject.into(),
                provider_id: "fixture".into(),
                user_id: owner.id.clone(),
                scope: Some(r#"{"owner":7}"#.to_owned()).into(),
                ..Default::default()
            })
            .await?;
        assert_eq!(created.id, id);
    }
    let _ = config.account.additional_fields.insert(
        "userId".into(),
        UserFieldConfig {
            field_type: UserFieldType::Json,
            field_name: Some("scope".into()),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let events = Events::default();
    let inner = inner.with_runtime(
        config.clone(),
        vec![Arc::new(ObserveDelete(events.clone()))],
        Default::default(),
    )?;
    let store: Arc<dyn AuthStore<S>> = if secondary {
        Arc::new(SecondaryStore::new(
            inner,
            Arc::new(MemoryCacheAdapter::new()),
            config,
            Default::default(),
        )?)
    } else {
        inner
    };
    let selector = FieldValue::from_json(serde_json::json!({"owner":7}))?;
    assert_eq!(store.get_user_accounts_value(&selector).await?.len(), 3);
    assert!(
        store
            .get_user_accounts_value(&FieldValue::from_json(serde_json::json!({"owner":8}))?)
            .await?
            .is_empty()
    );
    for (id, fails) in [("1", false), ("2", false), ("3", true)] {
        let selector =
            FieldValue::Utf16String(Utf16String::from_units(id.encode_utf16().collect()));
        let result = store.delete_account_value(&selector).await;
        if fails {
            assert!(
                matches!(result, Err(AuthError::Internal(message)) if message == "account after hook failed")
            );
        } else {
            result?;
        }
    }
    assert_eq!(
        *events.lock().unwrap(),
        [
            "before:deleted",
            "after:deleted",
            "before:cancelled",
            "before:failed",
            "after:failed"
        ]
    );
    let remaining = store.get_user_accounts_value(&selector).await?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining.first().unwrap().account_id, "cancelled");
    assert!(store.get_account("fixture", "deleted").await?.is_none());
    assert!(store.get_account("fixture", "failed").await?.is_none());
    Ok(())
}

#[tokio::test]
async fn native_account_selectors_preserve_aliases_and_single_delete_lifecycles() -> AuthResult<()>
{
    for secondary in [false, true] {
        let config = AuthConfig::default();
        check(
            Arc::new(EphemeralStore::new(Arc::new(config.clone()))),
            config.clone(),
            secondary,
        )
        .await?;
        let database = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&database).await.unwrap();
        check(
            Arc::new(SeaOrmStore::<BundledSchema>::new(config.clone(), database)),
            config,
            secondary,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn serial_account_selectors_convert_native_values_before_matching() -> AuthResult<()> {
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(IdGeneration::Serial);
    let store = EphemeralStore::new(Arc::new(config));
    let created = store
        .create_account(CreateAccount {
            account_id: "native-serial".into(),
            provider_id: "fixture".into(),
            user_id: "001".into(),
            ..Default::default()
        })
        .await?;
    assert_eq!(created.id, "1");
    assert_eq!(store.get_user_accounts_value(&true.into()).await?.len(), 1);
    store.delete_account_value(&true.into()).await?;
    assert!(store.get_user_accounts_value(&1.into()).await?.is_empty());
    Ok(())
}
