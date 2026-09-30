#![cfg(feature = "seaorm2")]
#![allow(
    clippy::unwrap_used,
    reason = "integration fixtures fail immediately when setup or assertions fail"
)]

use async_trait::async_trait;
use better_auth::prelude::{
    AuthSession, AuthUser, AuthVerification, CreateAccount, CreateSession, CreateUser,
    CreateVerification,
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
    pure: bool,
}

#[async_trait]
impl SeaOrmHooks<BundledSchema> for Hooks {
    async fn before_create_session(
        &self,
        input: &mut CreateSession,
        ctx: &SeaOrmHookContext<'_>,
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
        session: &Session,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        if self.pure {
            assert!(ctx.tx.is_none());
            assert!(self.cache.get(session.token()).await?.is_some());
        }
        self.events.lock().unwrap().push("after-session");
        Ok(())
    }
    async fn before_create_verification(
        &self,
        input: &mut CreateVerification,
        _: &SeaOrmHookContext<'_>,
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
        verification: &Verification,
        _: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        assert!(
            self.cache
                .get(&format!("verification:{}", verification.identifier()))
                .await?
                .is_some()
        );
        self.events.lock().unwrap().push("after-verification");
        Ok(())
    }
    async fn before_delete_session(
        &self,
        _: &Session,
        _: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.events.lock().unwrap().push("before-delete");
        Ok(HookControl::Continue)
    }
    async fn after_delete_session(&self, _: &Session, _: &SeaOrmHookContext<'_>) -> AuthResult<()> {
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
        user_id,
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
        .create_session(input(user.id.clone()))
        .await
        .unwrap();
    assert_eq!(session.user_agent(), Some("hook-agent"));
    let verification = auth
        .store()
        .create_verification(CreateVerification {
            identifier: "first".into(),
            value: "original".into(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();
    assert_eq!(verification.value(), "hook-value");
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
            .create_session(input(other.id.clone()))
            .await
            .is_err()
    );
    assert!(
        hooks
            .cache
            .get(&format!("active-sessions-{}", other.id))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        auth.store()
            .create_verification(CreateVerification {
                identifier: "cancelled".into(),
                value: "original".into(),
                expires_at: Utc::now() + Duration::hours(1),
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
                let session = tx.create_session(input(user.id)).await?;
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
async fn preserved_session_revoke_ends_the_row_and_runs_delete_hooks_once() {
    let (auth, database, hooks) = setup(true).await;
    let user = auth
        .store()
        .create_user(CreateUser::new().with_email("preserve@example.com"))
        .await
        .unwrap();
    let session = auth.store().create_session(input(user.id)).await.unwrap();
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
    let preserved = SessionEntity::find_by_id(&session.id)
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert!(preserved.expires_at <= Utc::now());
    assert_eq!(preserved.updated_at, session.updated_at);
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
                user_id: user.id.clone(),
                account_id: user.id.clone(),
                provider_id: "credential".into(),
                password: Some("unproven".into()),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
            })
            .await
            .unwrap();
        let session = auth
            .store()
            .create_session(input(user.id.clone()))
            .await
            .unwrap();
        let result = auth
            .store()
            .verify_user_and_revoke_unproven_access(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(result.email_verified());
        assert_eq!(
            auth.store()
                .get_user_accounts(&user.id)
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
        .create_session(input(user.id.clone()))
        .await
        .unwrap();

    cache.pause_next.store(true, Ordering::SeqCst);
    let late = {
        let auth = auth.clone();
        let id = user.id.clone();
        tokio::spawn(async move {
            auth.store()
                .verify_user_and_revoke_unproven_access(&id)
                .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), cache.entered.notified())
        .await
        .unwrap();
    let winner = auth
        .store()
        .verify_user_and_revoke_unproven_access(&user.id)
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
        .create_session(input(user.id.clone()))
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
    let active = auth.store().get_user_sessions(&user.id).await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active.first().unwrap().token(), proven.token());
}

struct FailAfterVerification;

#[async_trait]
impl SeaOrmHooks<BundledSchema> for FailAfterVerification {
    async fn after_update_user(
        &self,
        _: &<BundledSchema as better_auth::AuthSchema>::User,
        ctx: &SeaOrmHookContext<'_>,
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
        .create_session(input(user.id.clone()))
        .await
        .unwrap();
    let error = auth
        .store()
        .verify_user_and_revoke_unproven_access(&user.id)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuthError::Internal(message) if message == "verification after hook failed")
    );
    assert!(
        auth.store()
            .get_user_by_id(&user.id)
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
            .get_user_sessions(&user.id)
            .await
            .unwrap()
            .is_empty()
    );

    let owner = auth
        .store()
        .create_session(input(user.id.clone()))
        .await
        .unwrap();
    assert!(
        auth.store()
            .verify_user_and_revoke_unproven_access(&user.id)
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
            user_id: user.id.clone(),
            account_id: user.id.clone(),
            provider_id: "credential".into(),
            password: Some("unproven".into()),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
        })
        .await
        .unwrap();
    let old = auth
        .store()
        .create_session(input(user.id.clone()))
        .await
        .unwrap();

    cache.fail_delete_next.store(true, Ordering::SeqCst);
    let error = auth
        .store()
        .verify_user_and_revoke_unproven_access(&user.id)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuthError::Internal(message) if message == "secondary deletion failed")
    );
    assert!(
        !auth
            .store()
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap()
            .email_verified()
    );
    assert_eq!(
        auth.store()
            .get_user_accounts(&user.id)
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
            .verify_user_and_revoke_unproven_access(&user.id)
            .await
            .unwrap()
            .unwrap()
            .email_verified()
    );
    assert!(
        auth.store()
            .get_user_accounts(&user.id)
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
        .create_session(input(user.id.clone()))
        .await
        .unwrap();
    assert!(
        auth.store()
            .verify_user_and_revoke_unproven_access(&user.id)
            .await
            .unwrap()
            .unwrap()
            .email_verified()
    );
    let sessions = auth.store().get_user_sessions(&user.id).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions.first().unwrap().token(), owner.token());
}
