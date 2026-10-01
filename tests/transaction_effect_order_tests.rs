#![cfg(feature = "seaorm2")]
#![allow(
    clippy::unwrap_used,
    reason = "Fixtures fail immediately on setup and assertion errors"
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthSession, AuthStore, AuthUser, CreateAccount,
    CreateSession, CreateUser, HttpMethod, UpdateUser,
    hooks::{current_request_hook_context, with_request_hook_context},
    store::{
        AccountStore, EphemeralStore, MemoryCacheAdapter, SecondaryStorage, SessionStore,
        StatelessSchema, UserStore,
        database_hooks::{DatabaseHookContext, DatabaseHooks},
        secondary::SecondaryStore,
        transaction,
    },
    wire::{AccountView, UserView},
};
use better_auth_seaorm::{
    SeaOrmHookContext, SeaOrmHooks, SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::{Duration, Utc};

#[derive(Clone)]
struct OrderedHooks {
    events: Arc<Mutex<Vec<String>>>,
    early_error: bool,
}

impl OrderedHooks {
    fn after_user(&self) -> AuthResult<()> {
        self.events.lock().unwrap().push("user".into());
        if self.early_error {
            return Err(AuthError::internal("early after hook"));
        }
        Ok(())
    }

    fn after_account(&self) -> AuthResult<()> {
        self.events.lock().unwrap().push("account".into());
        Err(AuthError::internal("late after hook"))
    }
}

#[async_trait]
impl SeaOrmHooks<BundledSchema> for OrderedHooks {
    async fn after_update_user(
        &self,
        _: Option<&<BundledSchema as AuthSchema>::User>,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        self.after_user()
    }

    async fn after_create_account(
        &self,
        _: &<BundledSchema as AuthSchema>::Account,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        self.after_account()
    }
}

#[async_trait]
impl DatabaseHooks<StatelessSchema> for OrderedHooks {
    async fn after_update_user(
        &self,
        _: Option<&UserView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.after_user()
    }

    async fn after_create_account(
        &self,
        _: &AccountView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.after_account()
    }
}

async fn check_order<S: AuthSchema>(
    inner: Arc<dyn AuthStore<S>>,
    config: Arc<AuthConfig>,
    hooks: OrderedHooks,
    rollback: bool,
) {
    let cache = Arc::new(MemoryCacheAdapter::new());
    let store = SecondaryStore::new(inner, cache.clone(), config, Default::default()).unwrap();
    let user = store
        .create_user(
            CreateUser::new()
                .with_email("order@example.com")
                .with_name("Original"),
        )
        .await
        .unwrap();
    let user_id = user.id().into_owned();
    let session = store
        .create_session(CreateSession {
            user_id: user_id.clone(),
            expires_at: Utc::now() + Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    let events = hooks.events.clone();
    let tx_user_id = user_id.clone();
    let result: AuthResult<()> = transaction(&store, move |tx| {
        Box::pin(async move {
            let _ = tx
                .update_user(
                    &tx_user_id,
                    UpdateUser {
                        name: Some("Updated".into()),
                        ..Default::default()
                    },
                )
                .await?;
            let request =
                better_auth_core::AuthRequest::new(HttpMethod::Post, "/captured-operation");
            let captured_events = events.clone();
            with_request_hook_context(&request, async {
                tx.queue_after_commit(Box::pin(async move {
                    captured_events
                        .lock()
                        .unwrap()
                        .push(current_request_hook_context().unwrap().path);
                    Ok(())
                }))
            })
            .await?;
            let _ = tx
                .create_account(CreateAccount {
                    user_id: tx_user_id,
                    provider_id: "mock".into(),
                    account_id: "mock".into(),
                    password: None,
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                })
                .await?;
            tx.queue_after_commit(Box::pin(async move {
                events.lock().unwrap().push("must-not-run".into());
                Ok(())
            }))?;
            if rollback {
                return Err(AuthError::internal("rollback"));
            }
            Ok(())
        })
    })
    .await;
    let expected_error = if rollback {
        "rollback"
    } else if hooks.early_error {
        "early after hook"
    } else {
        "late after hook"
    };
    assert!(matches!(result, Err(AuthError::Internal(message)) if message == expected_error));
    let stored = store.get_user_by_id(&user_id).await.unwrap().unwrap();
    assert_eq!(
        stored.name(),
        Some(if rollback { "Original" } else { "Updated" })
    );
    assert_eq!(
        store.get_user_accounts(&user_id).await.unwrap().is_empty(),
        rollback
    );
    let encoded = cache.get(session.token()).await.unwrap().unwrap();
    let cached: serde_json::Value = serde_json::from_str(encoded.as_str().unwrap()).unwrap();
    assert_eq!(
        cached
            .pointer("/user/name")
            .and_then(serde_json::Value::as_str),
        Some(if rollback || hooks.early_error {
            "Original"
        } else {
            "Updated"
        })
    );
    let expected: &[&str] = if rollback {
        &[]
    } else if hooks.early_error {
        &["user"]
    } else {
        &["user", "/captured-operation", "account"]
    };
    assert_eq!(*hooks.events.lock().unwrap(), expected);
}

// Pinned internal-adapter.updateUser queues its cache refresh after the user's after hook,
// before hooks queued by the next write. A later failure cannot skip that earlier refresh.
#[tokio::test]
async fn sqlite_secondary_effects_interleave_with_after_hooks_and_stop_at_first_error() {
    for (early_error, rollback) in [(false, false), (true, false), (false, true)] {
        let config = Arc::new(AuthConfig::default());
        let hooks = OrderedHooks {
            events: Default::default(),
            early_error,
        };
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        let store = SeaOrmStore::<BundledSchema>::new((*config).clone(), db).hook(hooks.clone());
        check_order(Arc::new(store), config, hooks, rollback).await;
    }
}

#[tokio::test]
async fn ephemeral_secondary_effects_use_the_same_order_and_rollback_boundary() {
    for (early_error, rollback) in [(false, false), (true, false), (false, true)] {
        let config = Arc::new(AuthConfig::default());
        let hooks = OrderedHooks {
            events: Default::default(),
            early_error,
        };
        let store = EphemeralStore::new(config.clone()).with_hooks(vec![Arc::new(hooks.clone())]);
        check_order(Arc::new(store), config, hooks, rollback).await;
    }
}
