#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "The regression fixture must fail immediately on invalid setup or unexpected callback results"
)]

use std::sync::{Arc, Mutex};

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateUser, FieldMap,
    FieldValue, UpdateAccount,
    store::{
        EphemeralStore, MemoryCacheAdapter,
        database_hooks::{
            DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks, DatabaseUpdateResult,
        },
        secondary::SecondaryStore,
        transaction,
    },
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
    wire::AccountView,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};

type Events = Arc<Mutex<Vec<String>>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Commit,
    NoMatch,
    Cancel,
    InputError,
    AfterError,
    Rollback,
}

struct Hooks {
    first: bool,
    outcome: Outcome,
    transactional: bool,
    events: Events,
}

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn before_update_account(
        &self,
        original: &UpdateAccount,
        ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateAccount>> {
        assert_eq!(original.password.typed()?.as_deref(), Some("requested"));
        assert!(original.refresh_token.is_undefined());
        assert_eq!(ctx.transaction.is_some(), self.transactional);
        self.events
            .lock()
            .unwrap()
            .push(format!("before:{}", self.first));
        if !self.first && self.outcome == Outcome::Cancel {
            return Ok(DatabaseHookUpdate::Cancel);
        }
        Ok(DatabaseHookUpdate::Patch(if self.first {
            UpdateAccount {
                password: Some("first-hook".into()).into(),
                ..Default::default()
            }
        } else {
            UpdateAccount {
                refresh_token: Some("second-hook".into()).into(),
                ..Default::default()
            }
        }))
    }

    async fn after_update_account(
        &self,
        result: DatabaseUpdateResult<&AccountView>,
        ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        assert!(ctx.transaction.is_none());
        let DatabaseUpdateResult::Many(count) = result else {
            return Err(AuthError::internal(
                "Batch updates must pass an affected row count to the update hook",
            ));
        };
        self.events
            .lock()
            .unwrap()
            .push(format!("after:{}:{count}", self.first));
        if self.first && self.outcome == Outcome::AfterError {
            return Err(AuthError::internal("after-update failed"));
        }
        Ok(())
    }
}

async fn check<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    mut config: AuthConfig,
    outcome: Outcome,
    secondary: bool,
    transactional: bool,
) -> AuthResult<()> {
    let user = base
        .create_user(
            CreateUser::new()
                .with_email("batch@example.test")
                .with_name("Batch"),
        )
        .await?;
    for (id, provider, owner) in [
        ("first", "credential", 7),
        ("second", "credential", 7),
        ("different-provider", "other", 7),
        ("different-owner", "credential", 8),
    ] {
        let _ = base
            .create_account(CreateAccount {
                id: id.into(),
                account_id: id.into(),
                provider_id: provider.into(),
                user_id: user.id.clone(),
                scope: Some(format!("{{\"owner\":{owner}}}")).into(),
                password: Some("original-password".into()).into(),
                access_token: Some("original-access".into()).into(),
                refresh_token: Some("original-refresh".into()).into(),
                id_token: Some("original-id-token".into()).into(),
                ..Default::default()
            })
            .await?;
    }
    let events = Events::default();
    let _ = config.account.additional_fields.insert(
        "owner".into(),
        UserFieldConfig {
            field_type: UserFieldType::Json,
            field_name: Some("scope".into()),
            required: Some(false),
            ..Default::default()
        },
    );
    let input_events = events.clone();
    let _ = config.account.additional_fields.insert(
        "password".into(),
        UserFieldConfig {
            field_name: Some("accessToken".into()),
            required: Some(false),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    input_events.lock().unwrap().push("input:password".into());
                    assert_eq!(value, FieldValue::from("first-hook"));
                    if outcome == Outcome::InputError {
                        return Err(AuthError::internal("input failed"));
                    }
                    Ok("stored:first-hook".into())
                })),
                output: Some(UserFieldTransform::new(|_| {
                    Err(AuthError::internal(
                        "Batch updates must not project an Account",
                    ))
                })),
            }),
            ..Default::default()
        },
    );
    let stamp_events = events.clone();
    let _ = config.account.additional_fields.insert(
        "stamp".into(),
        UserFieldConfig {
            field_name: Some("idToken".into()),
            required: Some(false),
            on_update: Some(Arc::new(move || {
                stamp_events.lock().unwrap().push("input:stamp".into());
                Ok("updated-stamp".into())
            })),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let hooks: Vec<Arc<dyn DatabaseHooks<S>>> = [true, false]
        .into_iter()
        .map(|first| {
            Arc::new(Hooks {
                first,
                outcome,
                transactional,
                events: events.clone(),
            }) as Arc<dyn DatabaseHooks<S>>
        })
        .collect();
    let inner = base.with_runtime(config.clone(), hooks, Default::default())?;
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
    let owner = if outcome == Outcome::NoMatch { 9 } else { 7 };
    let selectors = FieldMap::from([
        (
            "owner".into(),
            FieldValue::from_json(serde_json::json!({"owner": owner}))?,
        ),
        ("providerId".into(), "credential".into()),
    ]);
    let update = UpdateAccount {
        password: Some("requested".into()).into(),
        ..Default::default()
    };
    let result = if transactional {
        let events = events.clone();
        transaction(store.as_ref(), move |tx| {
            Box::pin(async move {
                let count = tx.update_accounts(&selectors, update).await?;
                events.lock().unwrap().push("inside-transaction".into());
                if outcome == Outcome::Rollback {
                    return Err(AuthError::internal("rollback requested"));
                }
                Ok(count)
            })
        })
        .await
    } else {
        store.update_accounts(&selectors, update).await
    };
    match outcome {
        Outcome::Commit => assert_eq!(result?, Some(2)),
        Outcome::NoMatch => assert_eq!(result?, Some(0)),
        Outcome::Cancel => assert_eq!(result?, None),
        Outcome::InputError => assert!(
            matches!(result, Err(AuthError::Internal(message)) if message == "input failed")
        ),
        Outcome::AfterError => assert!(
            matches!(result, Err(AuthError::Internal(message)) if message == "after-update failed")
        ),
        Outcome::Rollback => assert!(
            matches!(result, Err(AuthError::Internal(message)) if message == "rollback requested")
        ),
    }
    let mut expected = vec!["before:true".to_owned(), "before:false".to_owned()];
    if outcome != Outcome::Cancel {
        expected.push("input:password".into());
        if outcome != Outcome::InputError {
            expected.push("input:stamp".into());
        }
    }
    if transactional && outcome != Outcome::InputError {
        expected.push("inside-transaction".into());
    }
    if matches!(
        outcome,
        Outcome::Commit | Outcome::NoMatch | Outcome::AfterError
    ) {
        let count = if outcome == Outcome::NoMatch { 0 } else { 2 };
        expected.push(format!("after:true:{count}"));
        if outcome != Outcome::AfterError {
            expected.push(format!("after:false:{count}"));
        }
    }
    assert_eq!(*events.lock().unwrap(), expected);
    for (id, provider) in [
        ("first", "credential"),
        ("second", "credential"),
        ("different-provider", "other"),
        ("different-owner", "credential"),
    ] {
        let row = base.get_account(provider, id).await?.unwrap();
        let changed = matches!(outcome, Outcome::Commit | Outcome::AfterError)
            && matches!(id, "first" | "second");
        assert_eq!(
            row.access_token.typed()?.as_deref(),
            Some(if changed {
                "stored:first-hook"
            } else {
                "original-access"
            })
        );
        assert_eq!(
            row.refresh_token.typed()?.as_deref(),
            Some(if changed {
                "second-hook"
            } else {
                "original-refresh"
            })
        );
        assert_eq!(
            row.id_token.typed()?.as_deref(),
            Some(if changed {
                "updated-stamp"
            } else {
                "original-id-token"
            })
        );
        assert_eq!(row.password.typed()?.as_deref(), Some("original-password"));
    }
    Ok(())
}

#[tokio::test]
async fn account_batches_preserve_native_selection_field_policies_counts_and_failure_effects()
-> AuthResult<()> {
    for secondary in [false, true] {
        for outcome in [
            Outcome::Commit,
            Outcome::NoMatch,
            Outcome::Cancel,
            Outcome::InputError,
            Outcome::AfterError,
        ] {
            let config = AuthConfig::default();
            check(
                Arc::new(EphemeralStore::new(Arc::new(config.clone()))),
                config.clone(),
                outcome,
                secondary,
                false,
            )
            .await?;
            let db = Database::connect("sqlite::memory:").await.unwrap();
            migrator::run_migrations(&db).await.unwrap();
            check(
                Arc::new(SeaOrmStore::<BundledSchema>::new(config.clone(), db)),
                config,
                outcome,
                secondary,
                false,
            )
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn account_batches_queue_after_hooks_until_commit_and_keep_committed_after_errors()
-> AuthResult<()> {
    for secondary in [false, true] {
        for outcome in [
            Outcome::Commit,
            Outcome::Cancel,
            Outcome::AfterError,
            Outcome::Rollback,
        ] {
            let config = AuthConfig::default();
            check(
                Arc::new(EphemeralStore::new(Arc::new(config.clone()))),
                config.clone(),
                outcome,
                secondary,
                true,
            )
            .await?;
            let db = Database::connect("sqlite::memory:").await.unwrap();
            migrator::run_migrations(&db).await.unwrap();
            check(
                Arc::new(SeaOrmStore::<BundledSchema>::new(config.clone(), db)),
                config,
                outcome,
                secondary,
                true,
            )
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_account_batches_bind_serial_primary_ids_before_redeclared_field_policies()
-> AuthResult<()> {
    for redeclare_id in [false, true] {
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id = Some(better_auth_core::id::IdGeneration::Serial);
        let base: Arc<dyn AuthStore<better_auth_core::store::StatelessSchema>> =
            Arc::new(EphemeralStore::new(Arc::new(config.clone())));
        let user = base
            .create_user(CreateUser::new().with_email("serial-batch@example.test"))
            .await?;
        for (account_id, provider_id) in [("first", "credential"), ("second", "001")] {
            let _ = base
                .create_account(CreateAccount {
                    account_id: account_id.into(),
                    provider_id: provider_id.into(),
                    user_id: user.id.clone(),
                    password: Some("original".into()).into(),
                    ..Default::default()
                })
                .await?;
        }
        if redeclare_id {
            let _ = config.account.additional_fields.insert(
                "id".into(),
                UserFieldConfig {
                    field_name: Some("providerId".into()),
                    ..Default::default()
                },
            );
        }
        let store = base.with_runtime(Arc::new(config), Vec::new(), Default::default())?;
        for (selector, password) in [
            (FieldValue::from("001"), "string-selector"),
            (FieldValue::Number(1.0), "native-selector"),
        ] {
            assert_eq!(
                store
                    .update_accounts(
                        &[("id".into(), selector)].into(),
                        UpdateAccount {
                            password: Some(password.into()).into(),
                            ..Default::default()
                        }
                    )
                    .await?,
                Some(1)
            );
            assert_eq!(
                base.get_account("credential", "first")
                    .await?
                    .unwrap()
                    .password
                    .typed()?
                    .as_deref(),
                Some(password)
            );
            assert_eq!(
                base.get_account("001", "second")
                    .await?
                    .unwrap()
                    .password
                    .typed()?
                    .as_deref(),
                Some("original")
            );
        }
    }
    Ok(())
}
