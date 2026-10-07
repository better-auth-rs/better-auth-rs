#![expect(
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    reason = "Contract assertions fail the test; Result propagates setup and observation errors."
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateUser, FieldMap, UserView,
    store::{EphemeralStore, StatelessSchema, UserStore, secondary::SecondaryStore, transaction},
};
use better_auth_seaorm::{SeaOrmStore, sea_orm::DatabaseConnection};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

#[path = "../account_user_auth_boundary_reference_tests/models.rs"]
mod models;
#[path = "refresh_observer.rs"]
mod observer;
#[path = "refresh_storage.rs"]
mod storage;
#[path = "../support/device_where_values.rs"]
#[expect(
    dead_code,
    reason = "The shared observer also provides fixture revival, which this contract does not use."
)]
mod values;

use observer::{Cache, Hooks, Recorder};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const SEED_DATE: &str = "2030-01-02T03:04:05.000Z";
const EXPIRY: &str = "2100-01-02T03:04:05.000Z";
const SCENARIOS: [&str; 9] = [
    "immediate-refresh-error",
    "committed-refresh-error",
    "missing-immediate",
    "cancel-committed",
    "after-error-immediate",
    "after-error-committed",
    "rollback",
    "parallel-partial",
    "malformed-cache-envelope",
];
const VALUE_SCENARIOS: [&str; 3] = [
    "numeric-cached-expires-at",
    "non-array-active-index",
    "mixed-active-index",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    backend: String,
    scenario: String,
    transaction: bool,
    before: Value,
    events: Value,
    outcome: Value,
    after_return: Value,
    after: Value,
}

impl Case {
    fn parallel(&self) -> bool {
        self.scenario == "parallel-partial"
    }
}

async fn observed_user(user: Option<&UserView>, config: &AuthConfig) -> AuthResult<Value> {
    let Some(user) = user else {
        return Ok(Value::Null);
    };
    let projected = UserView::with_internal_fields(user, &config.user, &Default::default()).await?;
    values::observe(&FieldMap::from(projected).into())
}

async fn record_update(
    result: AuthResult<Option<UserView>>,
    recorder: &Recorder,
    config: &AuthConfig,
) -> AuthResult<Option<UserView>> {
    match &result {
        Ok(user) => recorder.push(json!({
            "kind": "update.return", "value": observed_user(user.as_ref(), config).await?,
        })),
        Err(error) => {
            recorder.push(json!({"kind": "update.throw", "error": observer::error(error)}))
        }
    }
    result
}

async fn operation<S: AuthSchema>(
    store: SecondaryStore<S>,
    config: Arc<AuthConfig>,
    recorder: Recorder,
    case: &Case,
) -> AuthResult<Option<UserView>> {
    let id = if case.scenario == "missing-immediate" {
        "missing-owner"
    } else {
        "owner"
    };
    let result = if case.transaction {
        let events = recorder.clone();
        let options = config.clone();
        let rollback = case.scenario == "rollback";
        transaction(&store, move |tx| {
            Box::pin(async move {
                let result = tx.update_user_optional(id, super::update("Updated")).await;
                let user = record_update(result, &events, &options).await?;
                let after = events.clone();
                tx.queue_after_commit(Box::pin(async move {
                    after.push(json!({"kind": "transaction.after"}));
                    Ok(())
                }))?;
                if rollback {
                    let error = AuthError::internal("refresh-transaction-rollback");
                    events.push(json!({
                        "kind": "transaction.work.throw", "error": observer::error(&error),
                    }));
                    return Err(error);
                }
                let value = observed_user(user.as_ref(), &options).await?;
                events.push(json!({"kind": "transaction.work.return", "value": value}));
                Ok(user)
            })
        })
        .await
    } else {
        record_update(
            store
                .update_user_optional(id, super::update("Updated"))
                .await,
            &recorder,
            &config,
        )
        .await
    };
    match &result {
        Ok(user) => recorder.push(json!({"kind": "operation.return", "value": observed_user(user.as_ref(), &config).await?})),
        Err(error) => recorder.push(json!({"kind": "operation.throw", "error": observer::error(error)})),
    }
    result
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    database: Option<&DatabaseConnection>,
    case: &Case,
) -> TestResult {
    let date = SEED_DATE.parse::<chrono::DateTime<Utc>>()?;
    let _ = raw
        .create_user(CreateUser {
            id: Some("owner".into()),
            name: Some("Original".into()).into(),
            email: Some("owner@secondary-user-refresh.test".into()),
            email_verified: Some(true),
            image: None::<String>.into(),
            created_at: Some(date.into()),
            updated_at: Some(date.into()),
            ..Default::default()
        })
        .await?;
    let recorder = Recorder::default();
    let mut config = configuration();
    config.logger.level = Some(better_auth_core::observability::LogLevel::Debug);
    config.logger.log = Some(Arc::new(recorder.clone()));
    let config = Arc::new(config);
    let cache = Arc::new(Cache::new(case, recorder.clone())?);
    let hooks = Hooks {
        recorder: recorder.clone(),
        scenario: case.scenario.clone(),
    };
    let inner = raw.with_runtime(config.clone(), vec![Arc::new(hooks)], Default::default())?;
    let store = SecondaryStore::new(inner, cache.clone(), config.clone(), Default::default())?;
    let before = storage::snapshot(raw.as_ref(), database, &cache, &config).await?;
    assert!(recorder.snapshot().is_empty());

    let start = Utc::now().timestamp_millis();
    let release_failure = async {
        if case.parallel() {
            tokio::time::timeout(Duration::from_secs(5), cache.both_entered()).await??;
            recorder.push(json!({"kind": "gate.release", "token": "token-a"}));
            cache.release_a.add_permits(1);
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (result, released) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(5),
            operation(store, config.clone(), recorder.clone(), case)
        ),
        release_failure,
    );
    released?;
    let result = result?;
    let outcome = match result {
        Ok(user) => {
            json!({"kind": "returned", "value": observed_user(user.as_ref(), &config).await?})
        }
        Err(error) => json!({"kind": "thrown", "error": observer::error(&error)}),
    };
    let after_return = storage::snapshot(raw.as_ref(), database, &cache, &config).await?;
    if case.parallel() {
        assert_eq!(outcome["kind"], "returned");
        assert_eq!(after_return["cache"], before["cache"]);
        recorder.push(json!({"kind": "gate.release", "token": "token-b"}));
        cache.release_b.add_permits(1);
        tokio::time::timeout(Duration::from_secs(5), cache.sibling_finished()).await??;
    }
    let end = Utc::now().timestamp_millis();
    let after = storage::snapshot(raw.as_ref(), database, &cache, &config).await?;
    let events = recorder.snapshot();
    let mut actual = json!({"before": before, "events": events, "outcome": outcome, "afterReturn": after_return, "after": after});
    validate_and_normalize(&mut actual, start, end, &case.scenario)?;
    let mut expected = json!({"before": case.before, "events": case.events, "outcome": case.outcome, "afterReturn": case.after_return, "after": case.after});
    if case.transaction {
        let events = expected["events"]
            .as_array_mut()
            .ok_or("Expected reference events")?;
        let diagnostic = events.remove(0);
        let adapter = if case.backend == "memory" {
            "Memory"
        } else {
            "Kysely"
        };
        assert_eq!(
            diagnostic,
            json!({
                "kind": "logger", "level": "debug",
                "message": format!("[{adapter} Adapter] - Using provided transaction implementation."),
                "args": [],
            })
        );
    }
    observer::project_reference(&mut expected, &case.scenario)?;
    if database.is_none() {
        for phase in ["before", "afterReturn", "after"] {
            let tables = expected[phase]["database"]
                .as_object_mut()
                .ok_or("Expected Memory tables")?;
            assert_eq!(tables.remove("verification"), Some(json!([])));
        }
    }
    assert_eq!(actual, expected, "{} / {}", case.backend, case.scenario);
    Ok(())
}

fn validate_and_normalize(value: &mut Value, start: i64, end: i64, scenario: &str) -> TestResult {
    let seed = value["before"]["cache"]
        .as_array()
        .ok_or("Expected cache entries")?
        .iter()
        .find(|entry| entry["key"] == "token-b")
        .and_then(|entry| entry["value"].as_str())
        .ok_or("Expected seeded token-b cache")?;
    let seed: Value = serde_json::from_str(seed)?;
    let expiry = EXPIRY.parse::<chrono::DateTime<Utc>>()?.timestamp_millis();
    assert_eq!(
        seed["session"]["expiresAt"],
        if scenario == "numeric-cached-expires-at" {
            json!(expiry)
        } else {
            json!(EXPIRY)
        }
    );
    let events = value["events"]
        .as_array_mut()
        .ok_or("Expected event array")?;
    let updated_at = events.iter().find_map(|event| {
        event
            .pointer("/value/updatedAt/value")
            .or_else(|| event.pointer("/data/updatedAt/value"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    if let Some(updated_at) = &updated_at {
        let milliseconds = updated_at
            .parse::<chrono::DateTime<Utc>>()?
            .timestamp_millis();
        assert!((start..=end).contains(&milliseconds));
    }
    for event in events {
        if event["kind"] != "cache.set.start" {
            continue;
        }
        assert_eq!(event["key"], "token-b");
        let cached: Value =
            serde_json::from_str(event["value"].as_str().ok_or("Expected cache text")?)?;
        assert_eq!(cached["session"], seed["session"]);
        assert_eq!(cached["user"]["name"], "Updated");
        assert_eq!(cached["user"]["updatedAt"].as_str(), updated_at.as_deref());
        let ttl = event["ttl"].as_i64().ok_or("Expected integer TTL")?;
        assert!(
            ((expiry - end).div_euclid(1000)..=(expiry - start).div_euclid(1000)).contains(&ttl)
        );
        event["ttl"] = "<validated-session-ttl>".into();
    }
    if let Some(updated_at) = updated_at {
        normalize_date(value, &updated_at);
    }
    Ok(())
}

fn normalize_date(value: &mut Value, updated_at: &str) {
    match value {
        Value::String(text) => *text = text.replace(updated_at, "<user.updatedAt>"),
        Value::Array(values) => values
            .iter_mut()
            .for_each(|value| normalize_date(value, updated_at)),
        Value::Object(fields) => fields
            .values_mut()
            .for_each(|value| normalize_date(value, updated_at)),
        _ => {}
    }
}

fn configuration() -> AuthConfig {
    let mut config =
        AuthConfig::new("secondary-user-refresh-fixture-secret-at-least-thirty-two-characters");
    config.session.store_session_in_database = Some(true);
    config.verification.store_in_database = true;
    config
}

#[tokio::test]
async fn secondary_user_refresh_matches_upstream_memory_and_sqlite() -> TestResult {
    fixture("secondary-user-refresh-1.7.6.json", &SCENARIOS).await
}

#[tokio::test]
async fn secondary_user_refresh_values_match_upstream_memory_and_sqlite() -> TestResult {
    fixture("secondary-user-refresh-values-1.7.6.json", &VALUE_SCENARIOS).await
}

async fn fixture(name: &str, scenarios: &[&str]) -> TestResult {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases: Vec<Case> = serde_json::from_value(fixture["cases"].clone())?;
    assert_eq!(cases.len(), scenarios.len() * 2);
    for backend in ["memory", "sqlite"] {
        let selected: Vec<_> = cases
            .iter()
            .filter(|case| case.backend == backend)
            .collect();
        assert_eq!(
            selected
                .iter()
                .map(|case| case.scenario.as_str())
                .collect::<Vec<_>>(),
            scenarios
        );
        for case in selected {
            if backend == "memory" {
                let store = Arc::new(EphemeralStore::new(Arc::new(configuration())));
                contract::<StatelessSchema>(store, None, case).await?;
            } else {
                let database = storage::sqlite().await?;
                let store = Arc::new(SeaOrmStore::<models::Core>::new(
                    configuration(),
                    database.clone(),
                ));
                contract(store, Some(&database), case).await?;
            }
        }
    }
    Ok(())
}
