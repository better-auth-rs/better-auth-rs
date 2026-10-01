#![cfg(feature = "seaorm2")]
#![allow(
    clippy::unwrap_used,
    reason = "integration fixtures fail immediately when setup or assertions fail"
)]

use async_trait::async_trait;
use better_auth::prelude::{
    AuthSession, AuthUser, CreateAccount, CreateSession, CreateUser, CreateVerification,
};
use better_auth::store::{MemoryCacheAdapter, SecondaryStorage, transaction};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_seaorm::sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, EntityTrait, PaginatorTrait,
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{
    HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmSessionModel, SeaOrmStore,
    SeaOrmVerificationModel,
};
use chrono::{Duration, Utc};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

type Session = <BundledSchema as better_auth::AuthSchema>::Session;
type Verification = <BundledSchema as better_auth::AuthSchema>::Verification;
type SessionEntity = <Session as SeaOrmSessionModel>::Entity;
type VerificationEntity = <Verification as SeaOrmVerificationModel>::Entity;

#[derive(Clone)]
struct Hooks {
    cache: Arc<MemoryCacheAdapter>,
    events: Arc<Mutex<Vec<&'static str>>>,
    cancel: Arc<AtomicBool>,
    deferred_session: Arc<AtomicBool>,
    pure: bool,
}

#[better_auth::database_hooks()]
impl SeaOrmHooks<BundledSchema> for Hooks {
    async fn before_create_session(
        &self,
        input: &mut CreateSession,
        ctx: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<HookControl> {
        self.events.lock().unwrap().push(if ctx.tx.is_some() {
            "before-session-tx"
        } else {
            "before-session"
        });
        input.user_agent = Some("hook-agent".into());
        Ok(if self.cancel.load(Ordering::SeqCst) {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }
    async fn after_create_session(
        &self,
        session: &better_auth_core::wire::SessionView,
        ctx: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        if self.pure {
            assert!(ctx.tx.is_none());
            // Deferred upstream creates enqueue the after hook before the cache mirror.
            assert_eq!(
                self.cache.get(session.token()).await?.is_some(),
                !self.deferred_session.load(Ordering::SeqCst)
            );
        }
        self.events.lock().unwrap().push("after-session");
        Ok(())
    }
    async fn before_create_verification(
        &self,
        input: &mut CreateVerification,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<HookControl> {
        self.events.lock().unwrap().push("before-verification");
        input.value = "hook-value".into();
        Ok(if self.cancel.load(Ordering::SeqCst) {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }
    async fn after_create_verification(
        &self,
        verification: &better_auth_core::wire::VerificationView,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert!(
            self.cache
                .get(&format!(
                    "verification:{}",
                    verification.identifier.typed()?
                ))
                .await?
                .is_some()
        );
        self.events.lock().unwrap().push("after-verification");
        Ok(())
    }
    async fn before_delete_session(
        &self,
        _: &better_auth_core::wire::SessionView,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<HookControl> {
        self.events.lock().unwrap().push("before-delete");
        Ok(HookControl::Continue)
    }
    async fn after_delete_session(
        &self,
        _: &better_auth_core::wire::SessionView,
        _: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        self.events.lock().unwrap().push("after-delete");
        Ok(())
    }
}

async fn setup(preserve: bool) -> (BetterAuth<BundledSchema>, DatabaseConnection, Hooks) {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let mut config = AuthConfig::new("secondary-hook-test-secret-at-least-32-characters");
    config.session.store_session_in_database = preserve;
    config.session.preserve_session_in_database = preserve;
    let hooks = Hooks {
        cache: Arc::new(MemoryCacheAdapter::new()),
        events: Default::default(),
        cancel: Default::default(),
        deferred_session: Default::default(),
        pure: !preserve,
    };
    let auth = AuthBuilder::<BundledSchema>::new(config.clone())
        .store(SeaOrmStore::<BundledSchema>::new(config, database.clone()).hook(hooks.clone()))
        .secondary_storage(hooks.cache.clone())
        .build()
        .await
        .unwrap();
    (auth, database, hooks)
}

fn input(user_id: String) -> CreateSession {
    CreateSession {
        user_id: user_id.into(),
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
    }
}

#[tokio::test]
async fn pure_secondary_creation_runs_hooks_and_cancellation_prevents_cache_writes() {
    let (auth, database, hooks) = setup(false).await;
    let user = auth
        .store()
        .create_user(CreateUser::new().with_email("hooks@example.com"))
        .await
        .unwrap();
    let session = auth
        .store()
        .create_session(input(user.id.typed().unwrap().clone()))
        .await
        .unwrap();
    assert_eq!(session.user_agent(), Some("hook-agent"));
    let verification = auth
        .store()
        .create_verification(CreateVerification {
            identifier: "first".into(),
            value: "original".into(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(verification.value, "hook-value");
    assert_eq!(
        *hooks.events.lock().unwrap(),
        [
            "before-session",
            "after-session",
            "before-verification",
            "after-verification"
        ]
    );
    assert_eq!(SessionEntity::find().count(&database).await.unwrap(), 0);
    assert_eq!(
        VerificationEntity::find().count(&database).await.unwrap(),
        0
    );
    hooks.events.lock().unwrap().clear();
    hooks.cancel.store(true, Ordering::SeqCst);
    let other = auth
        .store()
        .create_user(CreateUser::new().with_email("cancelled@example.com"))
        .await
        .unwrap();
    assert!(
        auth.store()
            .create_session(input(other.id.typed().unwrap().clone()))
            .await
            .is_err()
    );
    assert!(
        hooks
            .cache
            .get(&format!("active-sessions-{}", other.id.typed().unwrap()))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        auth.store()
            .create_verification(CreateVerification {
                identifier: "cancelled".into(),
                value: "original".into(),
                expires_at: (Utc::now() + Duration::hours(1)).into(),
                ..Default::default()
            })
            .await
            .is_err()
    );
    assert!(
        hooks
            .cache
            .get("verification:cancelled")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        *hooks.events.lock().unwrap(),
        ["before-session", "before-verification"]
    );
}

#[tokio::test]
async fn transaction_publishes_session_and_after_hook_only_after_commit() {
    let (auth, database, hooks) = setup(false).await;
    hooks.deferred_session.store(true, Ordering::SeqCst);
    for commit in [false, true] {
        hooks.events.lock().unwrap().clear();
        let token = Arc::new(Mutex::new(String::new()));
        let captured = token.clone();
        let cache = hooks.cache.clone();
        let email = format!("tx-{commit}@example.com");
        let tx_email = email.clone();
        let result: AuthResult<String> = transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                let user = tx
                    .create_user(CreateUser::new().with_email(tx_email))
                    .await?;
                let session = tx
                    .create_session_with_deferred_secondary(input(user.id.typed().unwrap().clone()))
                    .await?;
                *captured.lock().unwrap() = session.token().to_owned();
                assert!(cache.get(session.token()).await?.is_none());
                if commit {
                    Ok(session.token().to_owned())
                } else {
                    Err(AuthError::internal("rollback"))
                }
            })
        })
        .await;
        let token = token.lock().unwrap().clone();
        assert_eq!(result.is_ok(), commit);
        assert_eq!(hooks.cache.get(&token).await.unwrap().is_some(), commit);
        assert_eq!(
            auth.store()
                .get_user_by_email(&email)
                .await
                .unwrap()
                .is_some(),
            commit
        );
        assert_eq!(
            *hooks.events.lock().unwrap(),
            if commit {
                vec!["before-session-tx", "after-session"]
            } else {
                vec!["before-session-tx"]
            }
        );
    }
    assert_eq!(SessionEntity::find().count(&database).await.unwrap(), 0);
}

#[tokio::test]
async fn default_transaction_session_mirrors_the_uncommitted_user_without_deferral() {
    for database_sessions in [false, true] {
        for commit in [false, true] {
            let (auth, database, hooks) = setup(database_sessions).await;
            let token = Arc::new(Mutex::new(String::new()));
            let captured = token.clone();
            let cache = hooks.cache.clone();
            let email = "immediate@example.com";
            let result: AuthResult<()> = transaction(auth.store().as_ref(), move |tx| {
                Box::pin(async move {
                    let user = tx.create_user(CreateUser::new().with_email(email)).await?;
                    let session = tx
                        .create_session(input(user.id.typed().unwrap().clone()))
                        .await?;
                    *captured.lock().unwrap() = session.token().to_owned();
                    let encoded = cache.get(session.token()).await?.unwrap();
                    let cached: serde_json::Value =
                        serde_json::from_str(encoded.as_str().unwrap())?;
                    assert_eq!(cached["user"]["id"], user.id.typed().unwrap().as_str());
                    assert_eq!(cached["user"]["email"], email);
                    if commit {
                        Ok(())
                    } else {
                        Err(AuthError::internal("rollback after immediate cache write"))
                    }
                })
            })
            .await;
            assert_eq!(result.is_ok(), commit);
            let token = token.lock().unwrap().clone();
            assert!(hooks.cache.get(&token).await.unwrap().is_some());
            assert_eq!(
                auth.store()
                    .get_user_by_email(email)
                    .await
                    .unwrap()
                    .is_some(),
                commit
            );
            assert_eq!(
                SessionEntity::find().count(&database).await.unwrap(),
                u64::from(database_sessions && commit)
            );
            assert_eq!(
                *hooks.events.lock().unwrap(),
                if commit {
                    vec!["before-session-tx", "after-session"]
                } else {
                    vec!["before-session-tx"]
                }
            );
        }
    }
}

#[tokio::test]
async fn preserved_session_revoke_ends_the_row_and_runs_delete_hooks_once() {
    let (auth, database, hooks) = setup(true).await;
    let user = auth
        .store()
        .create_user(CreateUser::new().with_email("preserve@example.com"))
        .await
        .unwrap();
    let session = auth
        .store()
        .create_session(input(user.id.typed().unwrap().clone()))
        .await
        .unwrap();
    hooks.events.lock().unwrap().clear();
    auth.store().delete_session(session.token()).await.unwrap();
    auth.store().delete_session(session.token()).await.unwrap();
    assert!(
        auth.store()
            .get_session(session.token())
            .await
            .unwrap()
            .is_none()
    );
    assert!(hooks.cache.get(session.token()).await.unwrap().is_none());
    let preserved = SessionEntity::find_by_id(session.id.typed().unwrap())
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert!(preserved.expires_at <= Utc::now());
    // Upstream preserved revocation runs adapter.updateMany, including updatedAt.onUpdate.
    assert!(preserved.updated_at > session.updated_at);
    assert!(
        (preserved.updated_at - preserved.expires_at)
            .num_milliseconds()
            .abs()
            < 1000
    );
    assert_eq!(
        *hooks.events.lock().unwrap(),
        ["before-delete", "after-delete"]
    );
}

#[tokio::test]
async fn pure_secondary_email_verification_does_not_require_a_session_table() {
    let (auth, database, hooks) = setup(false).await;
    let _ = database
        .execute_unprepared("DROP TABLE sessions")
        .await
        .unwrap();
    let user = auth
        .store()
        .create_user(CreateUser::new().with_email("proof@example.com"))
        .await
        .unwrap();
    for verified in [false, true] {
        let _ = auth
            .store()
            .create_account(CreateAccount {
                user_id: (user.id.clone()).into(),
                account_id: (user.id.clone()).into(),
                provider_id: "credential".into(),
                password: (Some("unproven".into())).into(),
                access_token: Default::default(),
                refresh_token: Default::default(),
                id_token: Default::default(),
                access_token_expires_at: Default::default(),
                refresh_token_expires_at: Default::default(),
                scope: Default::default(),
                ..Default::default()
            })
            .await
            .unwrap();
        let session = auth
            .store()
            .create_session(input(user.id.typed().unwrap().clone()))
            .await
            .unwrap();
        let result = auth
            .store()
            .verify_user_and_revoke_unproven_access(user.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(result.email_verified());
        assert_eq!(
            auth.store()
                .get_user_accounts(user.id.typed().unwrap())
                .await
                .unwrap()
                .len(),
            usize::from(verified)
        );
        assert_eq!(
            auth.store()
                .get_session(session.token())
                .await
                .unwrap()
                .is_some(),
            verified
        );
        assert_eq!(
            hooks.cache.get(session.token()).await.unwrap().is_some(),
            verified
        );
    }
}

#[derive(Default)]
struct ControlledSecondaryStorage {
    cache: MemoryCacheAdapter,
    pause_next: AtomicBool,
    fail_delete_next: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl SecondaryStorage for ControlledSecondaryStorage {
    async fn get(&self, key: &str) -> AuthResult<Option<serde_json::Value>> {
        if key.starts_with("active-sessions-") && self.pause_next.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        SecondaryStorage::get(&self.cache, key).await
    }
    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> AuthResult<()> {
        SecondaryStorage::set(&self.cache, key, value, ttl).await
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        if self.fail_delete_next.swap(false, Ordering::SeqCst) {
            return Err(AuthError::internal("secondary deletion failed"));
        }
        SecondaryStorage::delete(&self.cache, key).await
    }
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<serde_json::Value>> {
        SecondaryStorage::get_and_delete(&self.cache, key).await
    }
}

#[tokio::test]
async fn late_email_proof_does_not_revoke_the_verified_owners_new_cached_session() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let _ = database
        .execute_unprepared("DROP TABLE sessions")
        .await
        .unwrap();
    let cache = Arc::new(ControlledSecondaryStorage::default());
    let config = AuthConfig::new("secondary-verification-race-test-secret-at-least-32-characters");
    let auth = Arc::new(
        AuthBuilder::<BundledSchema>::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, database))
            .secondary_storage(cache.clone())
            .build()
            .await
            .unwrap(),
    );
    let user = auth
        .store()
        .create_user(CreateUser::new().with_email("proof-race@example.com"))
        .await
        .unwrap();
    let unproven = auth
        .store()
        .create_session(input(user.id.typed().unwrap().clone()))
        .await
        .unwrap();

    cache.pause_next.store(true, Ordering::SeqCst);
    let late = {
        let auth = auth.clone();
        let id = user.id.clone();
        tokio::spawn(async move {
            auth.store()
                .verify_user_and_revoke_unproven_access(id.typed().unwrap())
                .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), cache.entered.notified())
        .await
        .unwrap();
    let winner = auth
        .store()
        .verify_user_and_revoke_unproven_access(user.id.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(winner.email_verified());
    assert!(
        auth.store()
            .get_session(unproven.token())
            .await
            .unwrap()
            .is_none()
    );
    let proven = auth
        .store()
        .create_session(input(user.id.typed().unwrap().clone()))
        .await
        .unwrap();
    cache.release.notify_one();
    assert!(late.await.unwrap().unwrap().unwrap().email_verified());

    assert!(
        auth.store()
            .get_session(proven.token())
            .await
            .unwrap()
            .is_some()
    );
    let active = auth
        .store()
        .get_user_sessions(user.id.typed().unwrap())
        .await
        .unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active.first().unwrap().token(), proven.token());
}

struct FailAfterVerification;

#[better_auth::database_hooks()]
impl SeaOrmHooks<BundledSchema> for FailAfterVerification {
    async fn after_update_user(
        &self,
        _: Option<&better_auth_core::wire::UserView>,
        ctx: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert!(ctx.tx.is_none());
        Err(AuthError::internal("verification after hook failed"))
    }
}

#[tokio::test]
async fn committed_verification_revokes_cache_when_after_hook_fails() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let _ = database
        .execute_unprepared("DROP TABLE sessions")
        .await
        .unwrap();
    let cache = Arc::new(MemoryCacheAdapter::new());
    let config =
        AuthConfig::new("secondary-verification-hook-failure-secret-at-least-32-characters");
    let auth = AuthBuilder::<BundledSchema>::new(config.clone())
        .store(SeaOrmStore::<BundledSchema>::new(config, database).hook(FailAfterVerification))
        .secondary_storage(cache.clone())
        .build()
        .await
        .unwrap();
    let user = auth
        .store()
        .create_user(CreateUser::new().with_email("after-hook@example.com"))
        .await
        .unwrap();
    let old = auth
        .store()
        .create_session(input(user.id.typed().unwrap().clone()))
        .await
        .unwrap();
    let error = auth
        .store()
        .verify_user_and_revoke_unproven_access(user.id.typed().unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuthError::Internal(message) if message == "verification after hook failed")
    );
    assert!(
        auth.store()
            .get_user_by_id(user.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .email_verified()
    );
    assert!(cache.get(old.token()).await.unwrap().is_none());
    assert!(
        auth.store()
            .get_session(old.token())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        auth.store()
            .get_user_sessions(user.id.typed().unwrap())
            .await
            .unwrap()
            .is_empty()
    );

    let owner = auth
        .store()
        .create_session(input(user.id.typed().unwrap().clone()))
        .await
        .unwrap();
    assert!(
        auth.store()
            .verify_user_and_revoke_unproven_access(user.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .email_verified()
    );
    assert!(
        auth.store()
            .get_session(owner.token())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn cache_revocation_failure_rolls_back_verification_and_next_proof_finishes_cleanup() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let _ = database
        .execute_unprepared("DROP TABLE sessions")
        .await
        .unwrap();
    let cache = Arc::new(ControlledSecondaryStorage::default());
    let config =
        AuthConfig::new("secondary-verification-revocation-failure-secret-at-least-32-characters");
    let auth = AuthBuilder::<BundledSchema>::new(config.clone())
        .store(SeaOrmStore::<BundledSchema>::new(config, database))
        .secondary_storage(cache.clone())
        .build()
        .await
        .unwrap();
    let user = auth
        .store()
        .create_user(CreateUser::new().with_email("revocation-failure@example.com"))
        .await
        .unwrap();
    let _ = auth
        .store()
        .create_account(CreateAccount {
            user_id: (user.id.clone()).into(),
            account_id: (user.id.clone()).into(),
            provider_id: "credential".into(),
            password: (Some("unproven".into())).into(),
            access_token: Default::default(),
            refresh_token: Default::default(),
            id_token: Default::default(),
            access_token_expires_at: Default::default(),
            refresh_token_expires_at: Default::default(),
            scope: Default::default(),
            ..Default::default()
        })
        .await
        .unwrap();
    let old = auth
        .store()
        .create_session(input(user.id.typed().unwrap().clone()))
        .await
        .unwrap();

    cache.fail_delete_next.store(true, Ordering::SeqCst);
    let error = auth
        .store()
        .verify_user_and_revoke_unproven_access(user.id.typed().unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuthError::Internal(message) if message == "secondary deletion failed")
    );
    assert!(
        !auth
            .store()
            .get_user_by_id(user.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .email_verified()
    );
    assert_eq!(
        auth.store()
            .get_user_accounts(user.id.typed().unwrap())
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        auth.store()
            .get_session(old.token())
            .await
            .unwrap()
            .is_some()
    );

    assert!(
        auth.store()
            .verify_user_and_revoke_unproven_access(user.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .email_verified()
    );
    assert!(
        auth.store()
            .get_user_accounts(user.id.typed().unwrap())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(cache.get(old.token()).await.unwrap().is_none());
    assert!(
        auth.store()
            .get_session(old.token())
            .await
            .unwrap()
            .is_none()
    );
    let owner = auth
        .store()
        .create_session(input(user.id.typed().unwrap().clone()))
        .await
        .unwrap();
    assert!(
        auth.store()
            .verify_user_and_revoke_unproven_access(user.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
            .email_verified()
    );
    let sessions = auth
        .store()
        .get_user_sessions(user.id.typed().unwrap())
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions.first().unwrap().token(), owner.token());
}

#[tokio::test]
async fn transaction_user_changes_refresh_or_revoke_cached_sessions_only_after_commit() {
    for delete in [false, true] {
        for commit in [false, true] {
            let (auth, _, hooks) = setup(false).await;
            let user = auth
                .store()
                .create_user(
                    CreateUser::new()
                        .with_email("transaction-user@example.com")
                        .with_name("Original"),
                )
                .await
                .unwrap();
            let session = auth
                .store()
                .create_session(input(user.id.typed().unwrap().clone()))
                .await
                .unwrap();
            let token = session.token().to_owned();
            let user_id = user.id.clone();
            let cached_token = token.clone();
            let cache = hooks.cache.clone();
            let result: AuthResult<()> = transaction(auth.store().as_ref(), move |tx| {
                Box::pin(async move {
                    let _ = tx
                        .update_user(
                            user_id.typed().unwrap(),
                            better_auth::prelude::UpdateUser {
                                name: Some("Updated".into()),
                                ..Default::default()
                            },
                        )
                        .await?;
                    if delete {
                        tx.delete_user(user_id.typed().unwrap()).await?;
                    }
                    let encoded = cache.get(&cached_token).await?.unwrap();
                    let cached: serde_json::Value =
                        serde_json::from_str(encoded.as_str().unwrap())?;
                    assert_eq!(
                        cached
                            .pointer("/user/name")
                            .and_then(serde_json::Value::as_str),
                        Some("Original")
                    );
                    if commit {
                        Ok(())
                    } else {
                        Err(AuthError::internal("rollback"))
                    }
                })
            })
            .await;
            assert_eq!(result.is_ok(), commit);
            let cached = hooks.cache.get(&token).await.unwrap();
            let stored = auth
                .store()
                .get_user_by_id(user.id.typed().unwrap())
                .await
                .unwrap();
            if delete && commit {
                assert!(cached.is_none());
                assert!(stored.is_none());
                assert!(auth.store().get_session(&token).await.unwrap().is_none());
            } else {
                let encoded = cached.unwrap();
                let cached: serde_json::Value =
                    serde_json::from_str(encoded.as_str().unwrap()).unwrap();
                let name = if commit { "Updated" } else { "Original" };
                assert_eq!(
                    cached
                        .pointer("/user/name")
                        .and_then(serde_json::Value::as_str),
                    Some(name)
                );
                assert_eq!(stored.unwrap().name(), Some(name));
            }
        }
    }
}

#[tokio::test]
async fn transaction_user_changes_without_secondary_follow_database_commit_and_rollback() {
    for delete in [false, true] {
        for commit in [false, true] {
            let database = Database::connect("sqlite::memory:").await.unwrap();
            migrator::run_migrations(&database).await.unwrap();
            let config = AuthConfig::new("database-transaction-secret-at-least-32-characters");
            let auth = AuthBuilder::<BundledSchema>::new(config.clone())
                .store(SeaOrmStore::<BundledSchema>::new(config, database))
                .build()
                .await
                .unwrap();
            let user = auth
                .store()
                .create_user(
                    CreateUser::new()
                        .with_email("database-transaction@example.com")
                        .with_name("Original"),
                )
                .await
                .unwrap();
            let session = auth
                .store()
                .create_session(input(user.id.typed().unwrap().clone()))
                .await
                .unwrap();
            let user_id = user.id.clone();
            let result: AuthResult<()> = transaction(auth.store().as_ref(), move |tx| {
                Box::pin(async move {
                    let updated = tx
                        .update_user(
                            user_id.typed().unwrap(),
                            better_auth::prelude::UpdateUser {
                                name: Some("Updated".into()),
                                ..Default::default()
                            },
                        )
                        .await?;
                    assert_eq!(updated.name(), Some("Updated"));
                    if delete {
                        tx.delete_user(user_id.typed().unwrap()).await?;
                        assert!(tx.get_user_by_id(user_id.typed().unwrap()).await?.is_none());
                    }
                    if commit {
                        Ok(())
                    } else {
                        Err(AuthError::internal("database transaction rollback"))
                    }
                })
            })
            .await;
            if commit {
                result.unwrap();
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "Internal server error: database transaction rollback"
                );
            }
            let stored = auth
                .store()
                .get_user_by_id(user.id.typed().unwrap())
                .await
                .unwrap();
            if delete && commit {
                assert!(stored.is_none());
                assert!(
                    auth.store()
                        .get_session(session.token())
                        .await
                        .unwrap()
                        .is_none()
                );
            } else {
                let name = if commit { "Updated" } else { "Original" };
                assert_eq!(stored.unwrap().name(), Some(name));
                assert!(
                    auth.store()
                        .get_session(session.token())
                        .await
                        .unwrap()
                        .is_some()
                );
            }
        }
    }
}
