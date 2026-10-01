//! Exercise atomic database rate limits against real SQLite statements and failures.
#![cfg(feature = "seaorm2")]
#![allow(
    clippy::panic_in_result_fn,
    reason = "Regression assertions retain setup errors through Result"
)]

use better_auth::seaorm::{Database, SeaOrmStore, sea_orm};
use better_auth::{AuthConfig, middleware::EndpointRateLimit, store::RateLimitStore};
use better_auth_seaorm::store::{
    __private_test_support::bundled_schema::BundledSchema, entities::rate_limit,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

async fn fixture() -> TestResult<(sea_orm::DatabaseConnection, SeaOrmStore<BundledSchema>)> {
    let db = Database::connect("sqlite::memory:").await?;
    let _ = db
        .execute(
            &sea_orm::Schema::new(db.get_database_backend())
                .create_table_from_entity(rate_limit::Entity),
        )
        .await?;
    let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), db.clone());
    Ok((db, store))
}

async fn row(db: &sea_orm::DatabaseConnection, key: &str) -> TestResult<rate_limit::Model> {
    rate_limit::Entity::find()
        .filter(rate_limit::Column::Key.eq(key))
        .one(db)
        .await?
        .ok_or_else(|| std::io::Error::other("rate-limit row missing").into())
}

async fn seed(db: &sea_orm::DatabaseConnection, key: &str, count: f64, last: i64) -> TestResult {
    let _ = rate_limit::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        key: Set(key.to_owned()),
        count: Set(count.into()),
        last_request: Set(last),
    }
    .insert(db)
    .await?;
    Ok(())
}

#[tokio::test]
async fn numeric_rules_preserve_database_comparisons_and_denials_do_not_write() -> TestResult {
    let (db, store) = fixture().await?;
    for (key, window, max, expected) in [
        ("fractional", 10.0, 1.5, [true, true, false]),
        ("negative-max", 10.0, -1.0, [true, false, false]),
        ("zero", 0.0, 1.0, [true; 3]),
        ("negative", -1.0, 1.0, [true; 3]),
        ("nan-window", f64::NAN, 1.0, [true, false, false]),
        ("nan-max", 10.0, f64::NAN, [true, false, false]),
        ("infinite-window", f64::INFINITY, 1.0, [true, false, false]),
        ("infinite-max", 10.0, f64::INFINITY, [true; 3]),
    ] {
        let rule = EndpointRateLimit {
            window,
            max_requests: max,
        };
        for expected in expected {
            let before = rate_limit::Entity::find()
                .filter(rate_limit::Column::Key.eq(key))
                .one(&db)
                .await?;
            let decision = store.consume_rate_limit(key, rule, 100.0).await?;
            assert_eq!(decision.allowed, expected, "{key}");
            if !decision.allowed {
                assert_eq!(
                    Some(row(&db, key).await?),
                    before,
                    "denied {key} must not mutate the row"
                );
                if window.is_nan() {
                    assert!(decision.retry_after.is_some_and(f64::is_nan));
                } else if window.is_infinite() {
                    assert_eq!(decision.retry_after, Some(f64::INFINITY));
                }
            }
        }
        if window <= 0.0 {
            assert_eq!(f64::from(row(&db, key).await?.count), 1.0);
        }
    }
    Ok(())
}

#[tokio::test]
async fn competing_connections_share_one_key_and_never_exceed_the_allowance() -> TestResult {
    let path = std::env::temp_dir().join(format!(
        "better-auth-rate-limit-{}.db",
        uuid::Uuid::new_v4()
    ));
    let mut options = sea_orm::ConnectOptions::new(format!("sqlite://{}?mode=rwc", path.display()));
    let _ = options.max_connections(8).sqlx_logging(false);
    let db = Database::connect(options).await?;
    let _ = db
        .execute(
            &sea_orm::Schema::new(db.get_database_backend())
                .create_table_from_entity(rate_limit::Entity),
        )
        .await?;
    let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), db.clone());
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..64 {
        let store = store.clone();
        let _ = tasks.spawn(async move {
            store
                .consume_rate_limit(
                    "shared",
                    EndpointRateLimit {
                        window: 60.0,
                        max_requests: 7.0,
                    },
                    60.0,
                )
                .await
        });
    }
    let mut allowed = 0;
    while let Some(result) = tasks.join_next().await {
        allowed += usize::from(result??.allowed);
    }
    assert_eq!(allowed, 7);
    let rows = rate_limit::Entity::find().all(&db).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(f64::from(row(&db, "shared").await?.count), 7.0);
    drop(store);
    db.close().await?;
    std::fs::remove_file(path)?;
    Ok(())
}

#[tokio::test]
async fn only_successful_resets_prune_and_pruning_failure_keeps_the_reset() -> TestResult {
    let (db, store) = fixture().await?;
    let now = chrono::Utc::now().timestamp_millis();
    seed(&db, "stale", 99.0, now - 120_000).await?;
    seed(&db, "reset", 99.0, now - 20_000).await?;
    let rule = EndpointRateLimit {
        window: 10.0,
        max_requests: 2.0,
    };
    assert!(store.consume_rate_limit("new", rule, 60.0).await?.allowed);
    assert!(store.consume_rate_limit("new", rule, 60.0).await?.allowed);
    assert!(!store.consume_rate_limit("new", rule, 60.0).await?.allowed);
    assert_eq!(f64::from(row(&db, "stale").await?.count), 99.0);
    let _ = db.execute_unprepared("CREATE TRIGGER reject_rate_pruning BEFORE DELETE ON rate_limit BEGIN SELECT RAISE(FAIL, 'pruning unavailable'); END").await?;
    assert!(store.consume_rate_limit("reset", rule, 60.0).await?.allowed);
    assert_eq!(f64::from(row(&db, "reset").await?.count), 1.0);
    assert_eq!(f64::from(row(&db, "stale").await?.count), 99.0);
    let _ = db
        .execute_unprepared("DROP TRIGGER reject_rate_pruning")
        .await?;
    assert!(
        store
            .consume_rate_limit(
                "reset",
                EndpointRateLimit {
                    window: 0.0,
                    max_requests: 0.0
                },
                60.0
            )
            .await?
            .allowed
    );
    assert!(
        rate_limit::Entity::find()
            .filter(rate_limit::Column::Key.eq("stale"))
            .one(&db)
            .await?
            .is_none()
    );
    assert!(row(&db, "new").await?.last_request >= now);
    Ok(())
}

#[tokio::test]
async fn counter_read_insert_and_update_errors_propagate() -> TestResult {
    let (db, store) = fixture().await?;
    let rule = EndpointRateLimit {
        window: 10.0,
        max_requests: 2.0,
    };
    let _ = db.execute_unprepared("CREATE TRIGGER reject_rate_insert BEFORE INSERT ON rate_limit BEGIN SELECT RAISE(FAIL, 'insert unavailable'); END").await?;
    assert!(
        store
            .consume_rate_limit("failure", rule, 60.0)
            .await
            .is_err()
    );
    let _ = db
        .execute_unprepared("DROP TRIGGER reject_rate_insert")
        .await?;
    assert!(
        store
            .consume_rate_limit("failure", rule, 60.0)
            .await?
            .allowed
    );
    let before = row(&db, "failure").await?;
    let _ = db.execute_unprepared("CREATE TRIGGER reject_rate_update BEFORE UPDATE ON rate_limit BEGIN SELECT RAISE(FAIL, 'update unavailable'); END").await?;
    assert!(
        store
            .consume_rate_limit("failure", rule, 60.0)
            .await
            .is_err()
    );
    assert_eq!(row(&db, "failure").await?, before);
    let _ = db.execute_unprepared("DROP TABLE rate_limit").await?;
    assert!(
        store
            .consume_rate_limit("failure", rule, 60.0)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn ephemeral_database_storage_preserves_adapter_predicates() -> TestResult {
    let store = better_auth::store::EphemeralStore::default();
    for (key, window, maximum) in [("window", f64::NAN, 1.0), ("maximum", 10.0, f64::NAN)] {
        let rule = EndpointRateLimit {
            window,
            max_requests: maximum,
        };
        assert!(store.consume_rate_limit(key, rule, 60.0).await?.allowed);
        assert!(!store.consume_rate_limit(key, rule, 60.0).await?.allowed);
    }
    let rule = EndpointRateLimit {
        window: 0.0,
        max_requests: -1.0,
    };
    assert!(store.consume_rate_limit("reset", rule, 60.0).await?.allowed);
    assert!(store.consume_rate_limit("reset", rule, 60.0).await?.allowed);
    Ok(())
}
