use super::*;
use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::AuthConfig;
use better_auth_core::store::ConsumeApiKeyResult;
use sea_orm::{ConnectOptions, Database};
use std::sync::Arc;
use tokio::sync::Barrier;
use tokio::task::JoinSet;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_sqlite_connections_consume_quota_without_lock_upgrade_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let directory =
        std::env::temp_dir().join(format!("better-auth-api-key-{}", uuid::Uuid::new_v4()));
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
            let key = store
                .create_api_key(CreateApiKey {
                    additional_fields: Default::default(),
                    reference_id: "owner".to_string(),
                    config_id: "default".to_string(),
                    name: None,
                    prefix: None,
                    key_hash: "concurrent-key-hash".to_string(),
                    start: None,
                    expires_at: None,
                    remaining: Some(12.5),
                    rate_limit_enabled: true,
                    rate_limit_time_window: Some(86_400_000.0),
                    rate_limit_max: Some(2.5),
                    refill_interval: None,
                    refill_amount: None,
                    permissions: None,
                    metadata: None,
                    enabled: true,
                })
                .await?;
            let barrier = Arc::new(Barrier::new(32));
            let mut tasks = JoinSet::new();
            for _ in 0..32 {
                let store = store.clone();
                let barrier = barrier.clone();
                let snapshot = key.clone();
                let _ = tasks.spawn(async move {
                    let _ = barrier.wait().await;
                    store.consume_api_key_usage(&snapshot, true).await
                });
            }
            let mut counts = [0; 3];
            while let Some(result) = tasks.join_next().await {
                match result?? {
                    ConsumeApiKeyResult::Allowed(_) => counts[0] += 1,
                    ConsumeApiKeyResult::RateLimited { .. } => counts[1] += 1,
                    ConsumeApiKeyResult::UsageExhausted => counts[2] += 1,
                }
            }
            let persisted = store.get_api_key_by_id(key.id.typed()?).await?;
            Ok::<_, Box<dyn std::error::Error>>((counts, persisted))
        }
        .await;
        let closed = database.close().await;
        closed?;
        result
    }
    .await;
    let removed = std::fs::remove_dir_all(&directory);
    removed?;
    let (counts, persisted) = outcome?;
    // Upstream accepts fractional limits and consumes quota before rate-limit rejection.
    assert_eq!(counts, [3, 10, 19]);
    let persisted = persisted
        .ok_or_else(|| std::io::Error::other("fractional exhausted quota must retain the key"))?;
    assert_eq!(persisted.remaining, Some(-0.5));
    assert_eq!(persisted.request_count, Some(3.0));
    Ok(())
}
