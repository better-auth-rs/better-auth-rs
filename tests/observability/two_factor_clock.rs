use super::{Capture, config};
use better_auth::{AuthError, AuthResult};
use better_auth_core::{
    CreateTwoFactor, FieldValue,
    store::{EphemeralStore, MemoryCacheAdapter, TwoFactorStore, secondary::SecondaryStore},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tracing::Instrument;

fn events(capture: &Capture, collection: &str) -> AuthResult<Value> {
    let records = capture
        .0
        .lock()
        .map_err(|_| AuthError::internal("capture poisoned"))?;
    let mut events = Vec::new();
    for record in records.iter() {
        assert_eq!(record.closed, 1);
        assert!(record.exceptions.is_empty());
        assert!(!record.fields.contains_key("otel.status_code"));
        let name = record.fields.get("otel.name").and_then(Value::as_str);
        if name == Some("deadline clock") {
            events.push(json!({"type":"clock", "millis":record.fields["clock.milliseconds"]}));
        } else {
            assert_eq!(name, Some(format!("db incrementOne {collection}").as_str()));
            assert_eq!(
                record.fields.get("db.operation.name"),
                Some(&json!("incrementOne"))
            );
            assert_eq!(
                record.fields.get("db.collection.name"),
                Some(&json!(collection))
            );
            events.push(json!({"type":"incrementOne"}));
        }
    }
    Ok(json!(events))
}

async fn check(store: &impl TwoFactorStore, collection: &str) -> AuthResult<()> {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/account-lockout-clock-1.7.6.json"))?;
    let factor = store
        .create_two_factor(CreateTwoFactor {
            additional_fields: [("lockedUntil".into(), FieldValue::Null)].into(),
            user_id: "ordinary-clock".into(),
            secret: "ordinary-secret".into(),
            backup_codes: "ordinary-codes".into(),
            verified: true,
        })
        .await?;
    let max_attempts = fixture["maxAttempts"]
        .as_i64()
        .expect("integer attempt count");
    let duration = fixture["durationSeconds"]
        .as_f64()
        .expect("numeric duration");
    for case in fixture["cases"].as_array().expect("captured cases") {
        let capture = Capture::default();
        let now = case["incrementCompletedMillis"]
            .as_i64()
            .expect("fixed clock");
        store
            .record_two_factor_failure(&factor.id, max_attempts, &|| {
                let _clock = tracing::info_span!(
                    target: "better-auth", "deadline", "otel.name" = "deadline clock",
                    "clock.milliseconds" = now
                );
                better_auth_core::utils::date::from_milliseconds(now as f64 + duration * 1000.0)
                    .map(Into::into)
                    .ok_or_else(|| AuthError::config("Fixed deadline is out of range"))
            })
            .instrument(capture.span())
            .await?;
        capture.wait_closed().await?;
        let stored = store
            .get_two_factor_by_user_id("ordinary-clock")
            .await?
            .expect("created factor remains");
        assert_eq!(
            events(&capture, collection)?,
            case["events"],
            "{}",
            case["name"]
        );
        assert_eq!(
            json!({"failedVerificationCount":stored.failed_verification_count,"lockedUntil":stored.locked_until.json()?}),
            case["stored"],
            "{}",
            case["name"]
        );
    }

    let factor = store
        .create_two_factor(CreateTwoFactor {
            additional_fields: [("lockedUntil".into(), FieldValue::Null)].into(),
            user_id: "ordinary-deadline-error".into(),
            secret: "ordinary-secret".into(),
            backup_codes: "ordinary-codes".into(),
            verified: true,
        })
        .await?;
    let capture = Capture::default();
    let error = store
        .record_two_factor_failure(&factor.id, 1, &|| {
            let _clock = tracing::info_span!(
                target: "better-auth", "deadline", "otel.name" = "deadline clock",
                "clock.milliseconds" = 2_000_000_002_123_i64
            );
            Err(AuthError::internal("ordinary deadline error"))
        })
        .instrument(capture.span())
        .await
        .expect_err("original deadline error must propagate");
    assert!(
        matches!(error, AuthError::Internal(ref message) if message == "ordinary deadline error")
    );
    capture.wait_closed().await?;
    assert_eq!(
        events(&capture, collection)?,
        json!([
            {"type":"incrementOne"}, {"type":"clock","millis":2_000_000_002_123_i64}
        ])
    );
    let stored = store
        .get_two_factor_by_user_id("ordinary-deadline-error")
        .await?
        .expect("created factor remains");
    assert_eq!(stored.failed_verification_count, Some(1.0));
    assert!(stored.locked_until.typed()?.is_none());
    Ok(())
}

#[tokio::test]
async fn memory_lockout_clock_follows_the_threshold_increment() -> AuthResult<()> {
    check(&EphemeralStore::new(config().into()), "twoFactor").await
}

#[tokio::test]
async fn secondary_lockout_clock_follows_the_threshold_increment() -> AuthResult<()> {
    let config = Arc::new(config());
    let store = SecondaryStore::new(
        Arc::new(EphemeralStore::new(config.clone())),
        Arc::new(MemoryCacheAdapter::new()),
        config,
        Default::default(),
    )?;
    check(&store, "twoFactor").await
}

#[cfg(feature = "seaorm2")]
#[tokio::test]
async fn sqlite_lockout_clock_follows_the_threshold_increment() -> AuthResult<()> {
    use better_auth_seaorm::{
        SeaOrmStore,
        sea_orm::{ConnectionTrait, Database, Schema},
        store::{__private_test_support::bundled_schema::BundledSchema, entities},
    };
    let db = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let _ = db
        .execute(
            &Schema::new(db.get_database_backend())
                .create_table_from_entity(entities::two_factor::Entity),
        )
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    check(
        &SeaOrmStore::<BundledSchema>::new(config(), db),
        "two_factor",
    )
    .await
}
