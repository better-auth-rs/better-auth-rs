#![expect(
    clippy::panic_in_result_fn,
    reason = "The concurrent verification contract asserts ownership and persisted cleanup after hook failure."
)]

use super::*;
use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::{
    AuthConfig, AuthUser, CreateAccount, CreateSession, CreateUser, UpdateUser,
    store::{AccountStore, SessionStore, UserStore, VerificationStore},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use chrono::Utc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::{sync::Barrier, task::JoinSet};

struct FailAfterVerification;
#[better_auth_core::database_hooks()]
impl crate::hooks::SeaOrmHooks<BundledSchema> for FailAfterVerification {
    async fn after_update_user(
        &self,
        _user: Option<&better_auth_core::wire::UserView>,
        ctx: &crate::hooks::SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert!(ctx.tx.is_none());
        Err(better_auth_core::AuthError::internal(
            "verification hook failed",
        ))
    }
}

fn session(user_id: &str) -> CreateSession {
    CreateSession {
        inherited_fields: Default::default(),
        additional_fields: Default::default(),
        user_id: user_id.to_owned().into(),
        expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn database_cleanup_reservations_preserve_new_owner_sessions_after_committed_hook_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let directory =
        std::env::temp_dir().join(format!("better-auth-email-proof-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory)?;
    let outcome = async {
        let mut options = sea_orm::ConnectOptions::new(format!("sqlite://{}?mode=rwc", directory.join("auth.sqlite").display()));
        let _ = options.min_connections(8).max_connections(8);
        let database = sea_orm::Database::connect(options).await?;
        let result = async {
            run_migrations(&database).await?;
            let mut config = AuthConfig::new("a-secret-that-is-at-least-32-characters");
            let reservation_reads = Arc::new(Barrier::new(8));
            let synchronize_reservations = Arc::new(AtomicBool::new(false));
            let reservation_outputs = Arc::new(AtomicUsize::new(0));
            let synchronize_outputs = synchronize_reservations.clone();
            let _ = config.verification.additional_fields.insert("value".into(), UserFieldConfig {
                required: Some(true),
                transform: Some(FieldTransforms {
                    input: None,
                    output: Some(UserFieldTransform::new_async(move |value| {
                        let reservation_reads = reservation_reads.clone();
                        let synchronize_outputs = synchronize_outputs.clone();
                        let reservation_outputs = reservation_outputs.clone();
                        async move {
                            // Output projection runs in child tasks, so the barrier cannot use a caller task-local.
                            if synchronize_outputs.load(Ordering::Acquire)
                                && reservation_outputs.fetch_add(1, Ordering::AcqRel) < 8
                            {
                                // Upstream rethrows the insert error if the owner releases before the duplicate readback.
                                let _ = tokio::time::timeout(std::time::Duration::from_secs(10), reservation_reads.wait())
                                    .await.map_err(|error| AuthError::internal(format!("Reservation readback barrier: {error}")))?;
                            }
                            Ok(value)
                        }
                    })),
                }),
                ..Default::default()
            });
            let store = Arc::new(SeaOrmStore::<BundledSchema>::new(config.clone(), database.clone()));
            let user = store.create_user(CreateUser::new().with_email("proof@example.com").with_name("Fixture")).await?;
            let user_id = user.id().into_owned();
            let _ = store.create_account(CreateAccount {
user_id: user_id.clone(),
account_id: user_id.clone(),
provider_id: "credential".into(),
password: (Some("unproven".into())).into(),
access_token: Default::default(),
refresh_token: Default::default(),
id_token: Default::default(),
access_token_expires_at: Default::default(),
refresh_token_expires_at: Default::default(),
scope: Default::default(),
..Default::default()
}).await?;
            let _ = store.create_session(session(user_id.typed()?)).await?;
            let failing = SeaOrmStore::<BundledSchema>::new(config, database.clone()).hook(FailAfterVerification);
            assert!(matches!(failing.verify_user_and_revoke_unproven_access(user_id.typed()?).await, Err(better_auth_core::AuthError::Internal(message)) if message == "verification hook failed"));
            assert!(store.get_user_by_id(user_id.typed()?).await?.ok_or_else(|| AuthError::internal("Verified user is absent"))?.email_verified().typed().copied()?);
            assert!(store.get_user_accounts(user_id.typed()?).await?.is_empty());
            assert!(store.get_user_sessions(user_id.typed()?).await?.is_empty());
            assert!(store.get_verification_by_identifier(&format!("revoke-unproven-account-access:{}", user_id.typed()?)).await?.is_none());
            let _ = store.update_user(user_id.typed()?, UpdateUser { email_verified: Some(false), ..Default::default() }).await?;
            synchronize_reservations.store(true, Ordering::Release);
            let barrier = Arc::new(Barrier::new(8));
            let mut tasks = JoinSet::new();
            for _ in 0..8 {
                let store = store.clone(); let barrier = barrier.clone(); let user_id = user_id.clone();
                let _ = tasks.spawn(async move {
                    let _ = barrier.wait().await;
                    let user = store.verify_user_and_revoke_unproven_access(user_id.typed()?).await?.ok_or_else(|| AuthError::internal("Verified user is absent"))?;
                    assert!(user.email_verified().typed().copied()?);
                    store.create_session(session(user_id.typed()?)).await
                });
            }
            while let Some(result) = tasks.join_next().await { let _ = result??; }
            assert_eq!(store.get_user_sessions(user_id.typed()?).await?.len(), 8);
            assert!(store.get_verification_by_identifier(&format!("revoke-unproven-account-access:{}", user_id.typed()?)).await?.is_none());
            Ok::<_, Box<dyn std::error::Error>>(())
        }.await;
        database.close().await?;
        result
    }.await;
    std::fs::remove_dir_all(directory)?;
    outcome
}
