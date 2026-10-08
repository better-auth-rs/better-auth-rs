#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    reason = "Fixtures fail immediately on setup or assertion errors"
)]

use std::sync::{Arc, Mutex};

use better_auth_core::{
    AuthConfig, AuthError, AuthRequest, AuthResult, AuthSchema, AuthStore, CreateAccount,
    CreateSession, CreateUser, CreateVerification, HttpMethod, UpdateUser,
    hooks::{RequestHookContext, current_request_hook_context, with_request_hook_context},
    store::{
        EphemeralStore, MemoryCacheAdapter, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHooks, VerificationUpdate},
        secondary::SecondaryStore,
        transaction,
    },
    wire::{AccountView, SessionView, UserView, VerificationView},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::{Duration, Utc};

type Trace = Arc<Mutex<Vec<(&'static str, Option<String>, Option<String>)>>>;
struct Hooks(Trace);
impl Hooks {
    fn capture(&self, phase: &'static str, supplied: Option<&RequestHookContext>) {
        if let Some(supplied) = supplied {
            let ambient = current_request_hook_context().unwrap();
            self.0
                .lock()
                .unwrap()
                .push((phase, supplied.path.clone(), ambient.path));
        }
    }
}

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn after_create_verification(
        &self,
        _: Option<&VerificationView>,
        ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.capture("create", ctx.request.as_ref());
        Ok(())
    }
    async fn after_update_verification(
        &self,
        _: Option<&VerificationView>,
        ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.capture("update", ctx.request.as_ref());
        Ok(())
    }
    async fn after_delete_verification(
        &self,
        _: &VerificationView,
        ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.capture("delete", ctx.request.as_ref());
        Ok(())
    }
    async fn after_update_user(
        &self,
        _: Option<&UserView>,
        ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.capture("missing-user", ctx.request.as_ref());
        Ok(())
    }
    async fn after_delete_user(
        &self,
        _: &UserView,
        ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.capture("user-delete", ctx.request.as_ref());
        Ok(())
    }
    async fn after_delete_account(
        &self,
        _: &AccountView,
        ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.capture("account-delete", ctx.request.as_ref());
        Ok(())
    }
    async fn after_delete_session(
        &self,
        _: &SessionView,
        ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.capture("session-delete", ctx.request.as_ref());
        Ok(())
    }
    async fn after_create_session(
        &self,
        _: Option<&SessionView>,
        ctx: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.capture("session-create", ctx.request.as_ref());
        Ok(())
    }
}

fn session(user_id: better_auth_core::SchemaValue<String>) -> CreateSession {
    CreateSession {
        inherited_fields: Default::default(),
        user_id,
        expires_at: (Utc::now() + Duration::hours(1)).into(),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
        additional_fields: Default::default(),
    }
}

async fn check<S: AuthSchema>(
    inner: Arc<dyn AuthStore<S>>,
    config: Arc<AuthConfig>,
    pure: bool,
    outcome: &'static str,
) {
    let events: Trace = Default::default();
    let inner = inner
        .with_runtime(
            config.clone(),
            vec![Arc::new(Hooks(events.clone()))],
            Default::default(),
        )
        .unwrap();
    let store: Arc<dyn AuthStore<S>> = if pure {
        Arc::new(
            SecondaryStore::new(
                inner,
                Arc::new(MemoryCacheAdapter::new()),
                config,
                Default::default(),
            )
            .unwrap(),
        )
    } else {
        inner
    };
    let user = store
        .create_user(
            CreateUser::new()
                .with_name("Owner")
                .with_email("owner@example.com"),
        )
        .await
        .unwrap();
    if !pure {
        let _ = store
            .create_account(CreateAccount {
                user_id: user.id.clone(),
                provider_id: "fixture".into(),
                account_id: "owner".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let _ = store
            .create_session(session(user.id.clone()))
            .await
            .unwrap();
    }
    let outer = AuthRequest::new(HttpMethod::Post, "/flush-operation");
    let user_id = user.id.typed().unwrap().clone();
    let captured = events.clone();
    let result: AuthResult<()> = with_request_hook_context(
        &outer,
        transaction(store.as_ref(), move |tx| {
            Box::pin(async move {
                let inner = AuthRequest::new(HttpMethod::Post, "/captured-operation");
                with_request_hook_context(&inner, async move {
                    let _ = tx
                        .create_verification(CreateVerification {
                            identifier: "context".into(),
                            value: "original".into(),
                            expires_at: (Utc::now() + Duration::hours(1)).into(),
                            ..Default::default()
                        })
                        .await?;
                    if pure {
                        let _ = tx.create_session(session(user.id.clone())).await?;
                    } else {
                        let _ = tx
                            .update_verification(
                                "context",
                                VerificationUpdate {
                                    value: "updated".into(),
                                    ..Default::default()
                                },
                            )
                            .await?;
                        tx.delete_verification_by_identifier("context").await?;
                        assert!(
                            tx.update_user_optional(
                                "absent",
                                UpdateUser {
                                    name: Some("unused".into()).into(),
                                    ..Default::default()
                                }
                            )
                            .await?
                            .is_none()
                        );
                        tx.delete_user(user.id.typed()?).await?;
                    }
                    let explicit = current_request_hook_context();
                    let external = captured.clone();
                    tx.queue_after_commit(Box::pin(async move {
                        Hooks(external).capture("external", explicit.as_ref());
                        if outcome == "after-error" {
                            return Err(AuthError::internal("after-error"));
                        }
                        Ok(())
                    }))?;
                    let explicit = current_request_hook_context();
                    tx.queue_after_commit(Box::pin(async move {
                        Hooks(captured).capture("tail", explicit.as_ref());
                        Ok(())
                    }))?;
                    if outcome == "rollback" {
                        return Err(AuthError::internal("rollback"));
                    }
                    Ok(())
                })
                .await
            })
        }),
    )
    .await;
    match outcome {
        "commit" => result.unwrap(),
        expected => {
            assert!(matches!(result, Err(AuthError::Internal(message)) if message == expected))
        }
    }
    let mut expected = if outcome == "rollback" {
        vec![]
    } else if pure {
        vec!["create", "session-create", "external"]
    } else {
        vec![
            "create",
            "update",
            "delete",
            "missing-user",
            "session-delete",
            "account-delete",
            "user-delete",
            "external",
        ]
    };
    if outcome == "commit" {
        expected.push("tail");
    }
    assert_eq!(
        *events.lock().unwrap(),
        expected
            .into_iter()
            .map(|phase| (
                phase,
                Some("/captured-operation".to_owned()),
                Some("/flush-operation".to_owned())
            ))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        store
            .get_verification_including_expired("context")
            .await
            .unwrap()
            .is_some(),
        pure
    );
    if pure {
        assert_eq!(store.get_user_sessions(&user_id).await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn sqlite_captures_explicit_context_without_replacing_commit_scope() {
    for pure in [false, true] {
        for outcome in ["commit", "rollback", "after-error"] {
            let mut config = AuthConfig::default();
            config.session.store_session_in_database = Some(!pure);
            config.verification.store_in_database = !pure;
            let config = Arc::new(config);
            let db = Database::connect("sqlite::memory:").await.unwrap();
            migrator::run_migrations(&db).await.unwrap();
            let store = SeaOrmStore::<BundledSchema>::new((*config).clone(), db);
            check(Arc::new(store), config, pure, outcome).await;
        }
    }
}

#[tokio::test]
async fn ephemeral_captures_explicit_context_without_replacing_commit_scope() {
    for pure in [false, true] {
        for outcome in ["commit", "rollback", "after-error"] {
            let mut config = AuthConfig::default();
            config.session.store_session_in_database = Some(!pure);
            config.verification.store_in_database = !pure;
            let config = Arc::new(config);
            let store = EphemeralStore::new(config.clone());
            check::<StatelessSchema>(Arc::new(store), config, pure, outcome).await;
        }
    }
}
