use super::*;
use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::AuthConfig;
use better_auth_core::store::ConsumeApiKeyResult;
use sea_orm::{ConnectOptions, Database};
use std::sync::Arc;
use tokio::sync::Barrier;
use tokio::task::JoinSet;

#[tokio::test]
async fn increment_overrides_set_policies_for_the_same_physical_column() -> AuthResult<()> {
    use better_auth_core::AuthInitContext;
    use better_auth_core::user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    for logical in ["requestCount", "counterAlias"] {
        for (fail_input, fail_output) in [(false, false), (true, false), (false, true)] {
            let database = Database::connect("sqlite::memory:")
                .await
                .map_err(map_db_err)?;
            run_migrations(&database).await.map_err(map_db_err)?;
            let mut store = SeaOrmStore::<BundledSchema>::new(
                AuthConfig::new("a-secret-that-is-at-least-32-characters"),
                database,
            );
            let at = Utc::now();
            let _ = store
                .create_api_key_record(FieldMap::from([
                    ("id".into(), "atomic-count".into()),
                    ("referenceId".into(), "owner".into()),
                    ("key".into(), "atomic-count-key".into()),
                    ("createdAt".into(), at.into()),
                    ("updatedAt".into(), at.into()),
                    ("requestCount".into(), 2.0.into()),
                    ("lastRequest".into(), at.into()),
                ]))
                .await?;
            let reader = store.clone();
            let setters = Arc::new(AtomicUsize::new(0));
            let outputs = Arc::new(AtomicUsize::new(0));
            let mut init = AuthInitContext::new(store.config.clone(), Arc::new(store.clone()));
            init.register_model_fields(
                EntityRole::ApiKey,
                UserConfig {
                    additional_fields: Some(
                        [(
                            logical.into(),
                            UserFieldConfig {
                                field_type: UserFieldType::Number,
                                field_name: Some("request_count".into()),
                                on_update: Some(Arc::new({
                                    let setters = setters.clone();
                                    move || {
                                        let _ = setters.fetch_add(1, Ordering::SeqCst);
                                        if fail_input {
                                            Err(AuthError::internal("counter input rejected"))
                                        } else {
                                            Ok(99.0.into())
                                        }
                                    }
                                })),
                                transform: Some(FieldTransforms {
                                    output: Some(UserFieldTransform::new({
                                        let outputs = outputs.clone();
                                        move |value| {
                                            let _ = outputs.fetch_add(1, Ordering::SeqCst);
                                            if fail_output {
                                                Err(AuthError::internal("counter output rejected"))
                                            } else {
                                                Ok(value)
                                            }
                                        }
                                    })),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        )]
                        .into(),
                    ),
                },
            )?;
            store.model_fields = init.into_parts().plugin_fields;

            let write_at = at + chrono::Duration::seconds(1);
            let outcome = store
                .write_api_key_usage(
                    &"atomic-count".to_owned().into(),
                    ApiKeyUsageWrite::IncrementWindow {
                        previous_after: (at - chrono::Duration::seconds(1)).into(),
                        maximum: 10.0.into(),
                        at: write_at,
                    },
                )
                .await;
            if fail_input {
                assert!(
                    matches!(outcome, Err(AuthError::Internal(message)) if message == "counter input rejected")
                );
            } else if fail_output {
                assert!(
                    matches!(outcome, Err(AuthError::Internal(message)) if message == "counter output rejected")
                );
            } else {
                let row = outcome?.ok_or_else(|| {
                    AuthError::internal("Expected the guarded increment to match")
                })?;
                assert_eq!(row.request_count, Some(3.0));
            }
            assert_eq!(setters.load(Ordering::SeqCst), 1);
            assert_eq!(outputs.load(Ordering::SeqCst), usize::from(!fail_input));
            let persisted = reader
                .get_api_key_by_id("atomic-count")
                .await?
                .ok_or_else(|| AuthError::internal("Expected the updated API Key"))?;
            assert_eq!(
                persisted.request_count,
                Some(if fail_input { 2.0 } else { 3.0 })
            );
            assert_eq!(
                persisted.last_request,
                Some(better_auth_core::FieldDate::from(if fail_input {
                    at
                } else {
                    write_at
                }))
            );
        }
    }
    Ok(())
}

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
                    name: None.into(),
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
                    enabled: true.into(),
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
