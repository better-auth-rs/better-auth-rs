#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Native deletion regressions require exact persisted records and hook order"
)]

use std::sync::{Arc, Mutex};

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateSession,
    CreateUser, FieldValue, Utf16String,
    id::IdGeneration,
    store::{
        EphemeralStore, MemoryCacheAdapter, UserStore,
        database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks},
        secondary::SecondaryStore,
    },
    wire::{AccountView, UserView},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::{Duration, Utc};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Continue,
    Cancel,
    AfterError,
}

struct Hooks(Outcome, Arc<Mutex<Vec<&'static str>>>);

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn before_delete_account(
        &self,
        _: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.1.lock().unwrap().push("account:before");
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_delete_account(
        &self,
        _: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.1.lock().unwrap().push("account:after");
        Ok(())
    }
    async fn before_delete_user(
        &self,
        _: &UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.1.lock().unwrap().push("user:before");
        Ok(if self.0 == Outcome::Cancel {
            DatabaseHookControl::Cancel
        } else {
            DatabaseHookControl::Continue
        })
    }
    async fn after_delete_user(
        &self,
        _: &UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.1.lock().unwrap().push("user:after");
        if self.0 == Outcome::AfterError {
            return Err(AuthError::internal("native user after failed"));
        }
        Ok(())
    }
}

fn session(owner: &str) -> CreateSession {
    CreateSession {
        inherited_fields: Default::default(),
        additional_fields: Default::default(),
        user_id: owner.into(),
        expires_at: (Utc::now() + Duration::hours(1)).into(),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
    }
}

async fn check<S: AuthSchema>(
    inner: Arc<dyn AuthStore<S>>,
    secondary: bool,
    outcome: Outcome,
) -> AuthResult<()> {
    let config = Arc::new(AuthConfig::default());
    let events = Arc::new(Mutex::new(Vec::new()));
    let inner = inner.with_runtime(
        config.clone(),
        vec![Arc::new(Hooks(outcome, events.clone()))],
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
    for owner in ["owner", "other"] {
        let _ = store
            .create_user(CreateUser {
                id: Some(owner.into()),
                email: Some(format!("{owner}@native-delete.test")),
                ..Default::default()
            })
            .await?;
        let _ = store
            .create_account(CreateAccount {
                account_id: owner.into(),
                provider_id: "fixture".into(),
                user_id: owner.into(),
                ..Default::default()
            })
            .await?;
    }
    let owner_session = store.create_session(session("owner")).await?;
    let other_session = store.create_session(session("other")).await?;
    let native = FieldValue::Utf16String(Utf16String::from_units("owner".encode_utf16().collect()));
    let result = store.delete_user_value(&native).await;
    if outcome == Outcome::AfterError {
        assert!(
            matches!(result, Err(AuthError::Internal(message)) if message == "native user after failed")
        );
    } else {
        result?;
    }
    let expected = if outcome == Outcome::Cancel {
        vec!["account:before", "account:after", "user:before"]
    } else {
        vec![
            "account:before",
            "account:after",
            "user:before",
            "user:after",
        ]
    };
    assert_eq!(*events.lock().unwrap(), expected);
    assert!(store.get_account("fixture", "owner").await?.is_none());
    assert_eq!(
        store.get_user_by_id("owner").await?.is_some(),
        outcome == Outcome::Cancel
    );
    assert_eq!(
        store
            .get_session(owner_session.token.typed()?)
            .await?
            .is_some(),
        secondary && outcome != Outcome::Continue
    );
    assert!(store.get_account("fixture", "other").await?.is_some());
    assert!(store.get_user_by_id("other").await?.is_some());
    assert_eq!(
        store.get_session(other_session.token.typed()?).await?,
        Some(other_session)
    );
    Ok(())
}

#[tokio::test]
async fn native_user_delete_preserves_hook_order_partial_writes_and_secondary_cleanup()
-> AuthResult<()> {
    for outcome in [Outcome::Continue, Outcome::Cancel, Outcome::AfterError] {
        for secondary in [false, true] {
            check(
                Arc::new(EphemeralStore::new(Arc::new(AuthConfig::default()))),
                secondary,
                outcome,
            )
            .await?;
            let database = Database::connect("sqlite::memory:").await.unwrap();
            migrator::run_migrations(&database).await.unwrap();
            check(
                Arc::new(SeaOrmStore::<BundledSchema>::new(
                    AuthConfig::default(),
                    database,
                )),
                secondary,
                outcome,
            )
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn serial_user_delete_converts_native_boolean_before_selecting_owned_records()
-> AuthResult<()> {
    use better_auth_core::store::{AccountStore, SessionStore};
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(IdGeneration::Serial);
    let store = EphemeralStore::new(Arc::new(config));
    for owner in ["owner", "other"] {
        let _ = store
            .create_user(CreateUser::new().with_email(format!("{owner}@serial-delete.test")))
            .await?;
    }
    let _ = store
        .create_account(CreateAccount {
            account_id: "owner".into(),
            provider_id: "fixture".into(),
            user_id: "1".into(),
            ..Default::default()
        })
        .await?;
    let removed = store.create_session(session("1")).await?;
    let retained = store.create_session(session("2")).await?;
    store.delete_user_value(&FieldValue::Bool(true)).await?;
    assert!(store.get_user_by_id("1").await?.is_none());
    assert!(store.get_user_accounts("1").await?.is_empty());
    assert!(store.get_session(removed.token.typed()?).await?.is_none());
    assert!(store.get_user_by_id("2").await?.is_some());
    assert_eq!(
        store.get_session(retained.token.typed()?).await?,
        Some(retained)
    );
    Ok(())
}

struct UserSnapshots(Arc<Mutex<Vec<(&'static str, UserView)>>>);

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for UserSnapshots {
    async fn before_delete_user(
        &self,
        user: &UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.0.lock().unwrap().push(("before", user.clone()));
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_user(
        &self,
        user: &UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.0.lock().unwrap().push(("after", user.clone()));
        Ok(())
    }
}

#[tokio::test]
async fn native_user_delete_projects_one_hook_snapshot_and_removes_all_matching_rows()
-> AuthResult<()> {
    let config = Arc::new(AuthConfig::default());
    let snapshots = Arc::new(Mutex::new(Vec::new()));
    let base: Arc<dyn AuthStore<better_auth_core::store::StatelessSchema>> =
        Arc::new(EphemeralStore::new(config.clone()));
    let store = base.with_runtime(
        config,
        vec![Arc::new(UserSnapshots(snapshots.clone()))],
        Default::default(),
    )?;
    let mut users = Vec::new();
    for (id, email) in [
        ("owner", "first@duplicate-delete.test"),
        ("owner", "second@duplicate-delete.test"),
        ("other", "other@duplicate-delete.test"),
    ] {
        users.push(
            store
                .create_user(CreateUser {
                    id: Some(id.into()),
                    email: Some(email.into()),
                    ..Default::default()
                })
                .await?,
        );
    }
    let native = FieldValue::Utf16String(Utf16String::from_units("owner".encode_utf16().collect()));
    store.delete_user_value(&native).await?;
    let first = users.first().unwrap();
    assert_eq!(
        *snapshots.lock().unwrap(),
        vec![("before", first.clone()), ("after", first.clone())]
    );
    assert!(
        store
            .get_user_by_email("first@duplicate-delete.test")
            .await?
            .is_none()
    );
    assert!(
        store
            .get_user_by_email("second@duplicate-delete.test")
            .await?
            .is_none()
    );
    assert_eq!(
        store
            .get_user_by_email("other@duplicate-delete.test")
            .await?,
        users.last().cloned()
    );
    Ok(())
}
