use super::*;
use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::store::{TwoFactorStore, UserStore};
use better_auth_core::{AuthConfig, AuthUser, CreateTwoFactor, CreateUser};
use sea_orm::{ConnectOptions, Database};
use std::sync::Arc;
use tokio::{sync::Barrier, task::JoinSet};

struct RejectVerificationHook(crate::hooks::HookControl);

// Upstream internal-adapter.reserveVerificationValue uses a deterministic primary key.
#[tokio::test]
async fn email_claim_reservations_have_one_winner_and_can_be_released()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    let store = Arc::new(SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("a-secret-that-is-at-least-32-characters"),
        database.clone(),
    ));
    let claim = CreateVerification {
        identifier: "siwe-email-claim-owner@example.com".into(),
        value: "wallet-address".into(),
        expires_at: (Utc::now() + chrono::Duration::minutes(1)).into(),
        ..Default::default()
    };
    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = JoinSet::new();
    for _ in 0..8 {
        let store = store.clone();
        let barrier = barrier.clone();
        let claim = claim.clone();
        let _ = tasks.spawn(async move {
            let _ = barrier.wait().await;
            store
                .reserve_verification("deterministic-claim", claim)
                .await
        });
    }
    let mut winners = 0;
    while let Some(result) = tasks.join_next().await {
        winners += usize::from(result??);
    }
    assert_eq!(winners, 1);
    let reservation = store
        .consume_verification_by_identifier(claim.identifier.typed()?)
        .await?
        .ok_or_else(|| std::io::Error::other("winning reservation must persist"))?;
    assert_eq!(reservation.id, "deterministic-claim");
    assert_eq!(reservation.value, claim.value);
    assert!(
        store
            .reserve_verification("deterministic-claim", claim)
            .await?
    );
    database.close().await?;
    Ok(())
}

#[better_auth_core::database_hooks()]
impl crate::hooks::SeaOrmHooks<BundledSchema> for RejectVerificationHook {
    async fn before_delete_verification(
        &self,
        _verification: &better_auth_core::wire::VerificationView,
        _ctx: &crate::hooks::SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<crate::hooks::HookControl> {
        Ok(self.0)
    }

    async fn after_delete_verification(
        &self,
        _verification: &better_auth_core::wire::VerificationView,
        ctx: &crate::hooks::SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert!(ctx.tx.is_none());
        Err(better_auth_core::AuthError::internal("after hook failed"))
    }
}

#[tokio::test]
async fn consume_hooks_preserve_cancellation_and_do_not_restore_committed_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    let config = AuthConfig::new("a-secret-that-is-at-least-32-characters");
    let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database.clone());
    let _ = store
        .create_verification(CreateVerification {
            identifier: "hook-credential".into(),
            value: "user-id".into(),
            expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
            ..Default::default()
        })
        .await?;
    let cancelled = SeaOrmStore::<BundledSchema>::new(config.clone(), database.clone())
        .hook(RejectVerificationHook(crate::hooks::HookControl::Cancel));
    assert!(
        cancelled
            .consume_verification_by_identifier("hook-credential")
            .await?
            .is_none()
    );
    assert!(
        store
            .get_verification_by_identifier("hook-credential")
            .await?
            .is_some()
    );
    let failing = SeaOrmStore::<BundledSchema>::new(config, database.clone())
        .hook(RejectVerificationHook(crate::hooks::HookControl::Continue));
    let failure = failing
        .consume_verification_by_identifier("hook-credential")
        .await;
    assert!(
        matches!(failure, Err(better_auth_core::AuthError::Internal(message)) if message == "after hook failed")
    );
    assert!(
        store
            .consume_verification_by_identifier("hook-credential")
            .await?
            .is_none()
    );
    database.close().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_sqlite_credentials_are_consumed_once_and_failures_are_not_lost()
-> Result<(), Box<dyn std::error::Error>> {
    let directory =
        std::env::temp_dir().join(format!("better-auth-verification-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory)?;
    let outcome = async {
        let mut options = ConnectOptions::new(format!(
            "sqlite://{}?mode=rwc",
            directory.join("auth.sqlite").display()
        ));
        let _ = options.min_connections(8).max_connections(8);
        let database = Database::connect(options).await?;
        let result = async {
            run_migrations(&database).await?;
            let store = Arc::new(SeaOrmStore::<BundledSchema>::new(
                AuthConfig::new("a-secret-that-is-at-least-32-characters"),
                database.clone(),
            ));
            let created_at = Utc::now();
            for (value, created_at) in [
                ("old", created_at - chrono::Duration::seconds(1)),
                ("latest", created_at),
            ] {
                let _ = store
                    .create_verification(CreateVerification {
                        identifier: "one-use".into(),
                        value: value.into(),
                        expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
                        created_at: created_at.into(),
                        ..Default::default()
                    })
                    .await?;
            }
            let barrier = Arc::new(Barrier::new(32));
            let mut tasks = JoinSet::new();
            for _ in 0..32 {
                let store = store.clone();
                let barrier = barrier.clone();
                let _ = tasks.spawn(async move {
                    let _ = barrier.wait().await;
                    store.consume_verification_by_identifier("one-use").await
                });
            }
            let mut values = Vec::new();
            while let Some(result) = tasks.join_next().await {
                if let Some(record) = result?? {
                    values.push(record.value.typed().unwrap().clone());
                }
            }
            let consumed_again = store.consume_verification_by_identifier("one-use").await?;
            let created_at = Utc::now();
            for (value, seconds, created_at) in [
                ("old-valid", 60, created_at - chrono::Duration::seconds(1)),
                ("new-expired", -60, created_at),
            ] {
                let _ = store
                    .create_verification(CreateVerification {
                        identifier: "expired-latest".into(),
                        value: value.into(),
                        expires_at: (Utc::now() + chrono::Duration::seconds(seconds)).into(),
                        created_at: created_at.into(),
                        ..Default::default()
                    })
                    .await?;
            }
            let expired = store
                .consume_verification_by_identifier("expired-latest")
                .await?;
            let resurrected = store
                .consume_verification_by_identifier("expired-latest")
                .await?;

            let user = store
                .create_user(CreateUser::new().with_email("atomic@example.com"))
                .await?;
            let factor = store
                .create_two_factor(CreateTwoFactor {
                    user_id: user.id().into_owned().typed().unwrap().clone(),
                    secret: "encrypted-secret".into(),
                    backup_codes: "original-codes".into(),
                    verified: true,
                })
                .await?;
            let barrier = Arc::new(Barrier::new(32));
            let mut tasks = JoinSet::new();
            for _ in 0..32 {
                let store = store.clone();
                let barrier = barrier.clone();
                let id = factor.id.clone();
                let _ = tasks.spawn(async move {
                    let _ = barrier.wait().await;
                    let consumed = store
                        .compare_exchange_two_factor_backup_codes(
                            &id,
                            "original-codes",
                            "remaining-codes",
                        )
                        .await?;
                    store
                        .record_two_factor_failure(
                            &id,
                            10,
                            Utc::now() + chrono::Duration::minutes(15),
                        )
                        .await?;
                    Ok::<_, crate::error::AuthError>(consumed)
                });
            }
            let mut backup_winners = 0;
            while let Some(result) = tasks.join_next().await {
                backup_winners += usize::from(result??);
            }
            let stored = store
                .get_two_factor_by_user_id(user.id().typed().unwrap().as_ref())
                .await?;
            Ok::<_, Box<dyn std::error::Error>>((
                values,
                consumed_again,
                expired,
                resurrected,
                backup_winners,
                stored,
            ))
        }
        .await;
        database.close().await?;
        result
    }
    .await;
    std::fs::remove_dir_all(&directory)?;
    let (values, consumed_again, expired, resurrected, backup_winners, factor) = outcome?;
    assert_eq!(values, ["latest"]);
    assert!(consumed_again.is_none());
    assert!(expired.is_none());
    assert!(
        resurrected.is_none(),
        "an expired newest credential must invalidate older valid records"
    );
    assert_eq!(backup_winners, 1);
    let factor = factor
        .ok_or_else(|| std::io::Error::other("two-factor record must survive verification"))?;
    assert_eq!(factor.failed_verification_count, 32);
    assert!(factor.locked_until.is_some_and(|until| until > Utc::now()));
    Ok(())
}
