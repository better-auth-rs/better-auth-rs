#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    reason = "Fixtures fail immediately on setup and assertion errors"
)]

use std::sync::{Arc, Mutex};

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

#[better_auth::database_hooks()]
impl SeaOrmHooks<BundledSchema> for OrderedHooks {
    async fn after_update_user(
        &self,
        _: Option<&better_auth_core::wire::UserView>,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        self.after_user()
    }

    async fn after_create_account(
        &self,
        _: &better_auth_core::wire::AccountView,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        self.after_account()
    }
}

#[better_auth::database_hooks()]
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
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            additional_fields: Default::default(),
        })
        .await
        .unwrap();
    let events = hooks.events.clone();
    let tx_user_id = user_id.clone();
    let outer = better_auth_core::AuthRequest::new(HttpMethod::Post, "/flush-operation");
    let result: AuthResult<()> = with_request_hook_context(
        &outer,
        transaction(&store, move |tx| {
            Box::pin(async move {
                let _ = tx
                    .update_user(
                        tx_user_id.typed().unwrap(),
                        UpdateUser {
                            name: Some("Updated".into()).into(),
                            ..Default::default()
                        },
                    )
                    .await?;
                let request =
                    better_auth_core::AuthRequest::new(HttpMethod::Post, "/captured-operation");
                let captured_events = events.clone();
                with_request_hook_context(&request, async {
                    tx.queue_after_commit(Box::pin(async move {
                        captured_events.lock().unwrap().push(
                            current_request_hook_context()
                                .unwrap()
                                .path
                                .expect("HTTP endpoint path"),
                        );
                        Ok(())
                    }))
                })
                .await?;
                let _ = tx
                    .create_account(CreateAccount {
                        user_id: tx_user_id,
                        provider_id: "mock".into(),
                        account_id: "mock".into(),
                        password: Default::default(),
                        access_token: Default::default(),
                        refresh_token: Default::default(),
                        id_token: Default::default(),
                        access_token_expires_at: Default::default(),
                        refresh_token_expires_at: Default::default(),
                        scope: Default::default(),
                        ..Default::default()
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
        }),
    )
    .await;
    let expected_error = if rollback {
        "rollback"
    } else if hooks.early_error {
        "early after hook"
    } else {
        "late after hook"
    };
    assert!(matches!(result, Err(AuthError::Internal(message)) if message == expected_error));
    let stored = store
        .get_user_by_id(user_id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.name.typed().unwrap().as_deref(),
        Some(if rollback { "Original" } else { "Updated" })
    );
    assert_eq!(
        store
            .get_user_accounts(user_id.typed().unwrap())
            .await
            .unwrap()
            .is_empty(),
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
        &["user", "/flush-operation", "account"]
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

async fn check_effects_appended_during_drain<S: AuthSchema>(store: &dyn AuthStore<S>) {
    for fail in [false, true] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = events.clone();
        let result = transaction(store, move |tx| {
            Box::pin(async move {
                let retained = tx.clone_handle();
                let first_events = captured.clone();
                tx.queue_after_commit(Box::pin(async move {
                    first_events.lock().unwrap().push("first");
                    retained.queue_after_commit(Box::pin(async move {
                        first_events.lock().unwrap().push("appended");
                        Ok(())
                    }))?;
                    tokio::task::yield_now().await;
                    if fail {
                        return Err(AuthError::internal("drain failure"));
                    }
                    Ok(())
                }))?;
                tx.queue_after_commit(Box::pin(async move {
                    captured.lock().unwrap().push("second");
                    Ok(())
                }))?;
                Ok(())
            })
        })
        .await;
        if fail {
            assert!(
                matches!(result, Err(AuthError::Internal(message)) if message == "drain failure")
            );
            assert_eq!(*events.lock().unwrap(), ["first"]);
        } else {
            result.unwrap();
            assert_eq!(*events.lock().unwrap(), ["first", "second", "appended"]);
        }
    }
    for rollback in [false, true] {
        let marker = Arc::new(());
        let released = Arc::downgrade(&marker);
        let result = transaction(store, move |tx| {
            Box::pin(async move {
                tx.queue_after_commit(Box::pin(async {
                    Err(AuthError::internal("after failure"))
                }))?;
                let retained = tx.clone_handle();
                tx.queue_after_commit(Box::pin(async move {
                    drop(retained);
                    drop(marker);
                    Ok(())
                }))?;
                if rollback {
                    Err(AuthError::internal("rollback"))
                } else {
                    Ok(())
                }
            })
        })
        .await;
        assert!(result.is_err());
        assert!(
            released.upgrade().is_none(),
            "discarded effects must release retained transaction handles"
        );
    }
    let retained = transaction(store, |tx| Box::pin(async move { Ok(tx.clone_handle()) }))
        .await
        .unwrap();
    let marker = Arc::new(());
    let released = Arc::downgrade(&marker);
    let late = retained.clone_handle();
    retained
        .queue_after_commit(Box::pin(async move {
            drop(late);
            drop(marker);
            Err(AuthError::internal("late effect must not run"))
        }))
        .unwrap();
    assert!(released.upgrade().is_none());
}

#[tokio::test]
async fn retained_sqlite_handle_appends_effects_to_the_running_commit_queue() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), db);
    check_effects_appended_during_drain(&store).await;
}

#[tokio::test]
async fn retained_ephemeral_handle_appends_effects_to_the_running_commit_queue() {
    let store = EphemeralStore::new(Arc::new(AuthConfig::default()));
    check_effects_appended_during_drain(&store).await;
}

#[tokio::test]
async fn retained_memory_transaction_shares_committed_rows_but_not_table_membership() {
    let store = EphemeralStore::new(Arc::new(AuthConfig::default()));
    let unchanged = store
        .create_user(CreateUser::new().with_email("unchanged@example.com"))
        .await
        .unwrap();
    let unchanged_id = unchanged.id.typed().unwrap().clone();
    let (retained, created_id) = transaction(&store, |tx| {
        Box::pin(async move {
            let created = tx
                .create_user(CreateUser::new().with_email("created@example.com"))
                .await?;
            Ok((tx.clone_handle(), created.id.typed()?.clone()))
        })
    })
    .await
    .unwrap();
    for id in [&unchanged_id, &created_id] {
        let _ = retained
            .update_user(
                id,
                UpdateUser {
                    name: Some("Delayed".into()).into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    assert!(
        store
            .get_user_by_id(&unchanged_id)
            .await
            .unwrap()
            .unwrap()
            .name
            .is_undefined()
    );
    assert_eq!(
        store
            .get_user_by_id(&created_id)
            .await
            .unwrap()
            .unwrap()
            .name
            .typed()
            .unwrap()
            .as_deref(),
        Some("Delayed")
    );
    retained.delete_user(&created_id).await.unwrap();
    assert!(store.get_user_by_id(&created_id).await.unwrap().is_some());
    let late = retained
        .create_user(CreateUser::new().with_email("late@example.com"))
        .await
        .unwrap();
    assert!(
        store
            .get_user_by_id(late.id.typed().unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn missing_public_ids_preserve_pinned_commit_and_retained_row_behavior() {
    use better_auth::config::IdGeneration;
    use better_auth_core::{CreateVerification, store::VerificationStore};
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(IdGeneration::Database);
    let store = EphemeralStore::new(Arc::new(config));
    for identifier in ["first", "second"] {
        let _ = store
            .create_verification(CreateVerification {
                identifier: identifier.into(),
                value: "original".into(),
                expires_at: (Utc::now() + Duration::hours(1)).into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    let retained = transaction(&store, |tx| {
        Box::pin(async move {
            let _ = tx
                .update_verification(
                    "first",
                    better_auth_core::store::database_hooks::VerificationUpdate {
                        value: "committed".into(),
                        ..Default::default()
                    },
                )
                .await?;
            for subject in ["first", "second"] {
                let _ = tx
                    .create_account(CreateAccount {
                        account_id: subject.into(),
                        provider_id: "fixture".into(),
                        user_id: "owner".into(),
                        ..Default::default()
                    })
                    .await?;
                let _ = tx
                    .create_session(CreateSession {
                        additional_fields: Default::default(),
                        user_id: "owner".into(),
                        expires_at: (Utc::now() + Duration::hours(1)).into(),
                        ip_address: None,
                        user_agent: None,
                        impersonated_by: None,
                        active_organization_id: None,
                    })
                    .await?;
            }
            Ok(tx.clone_handle())
        })
    })
    .await
    .unwrap();
    // The pinned memory merge loses the first row's update when both public IDs are absent.
    assert_eq!(
        store
            .get_verification_by_identifier("first")
            .await
            .unwrap()
            .unwrap()
            .value,
        "original"
    );
    assert_eq!(
        store
            .get_verification_by_identifier("second")
            .await
            .unwrap()
            .unwrap()
            .value,
        "original"
    );
    let accounts = store.get_user_accounts("owner").await.unwrap();
    assert_eq!(accounts.len(), 2);
    assert!(accounts.iter().all(|row| row.id.is_undefined()));
    let sessions = store.get_user_sessions("owner").await.unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(sessions.iter().all(|row| row.id.is_undefined()));
    let _ = retained
        .update_verification(
            "first",
            better_auth_core::store::database_hooks::VerificationUpdate {
                value: "delayed".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .get_verification_by_identifier("first")
            .await
            .unwrap()
            .unwrap()
            .value,
        "original"
    );
}
