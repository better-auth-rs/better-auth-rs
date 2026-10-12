#![expect(
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    clippy::expect_used,
    reason = "The isolated contract checks complete frozen observations and uses source dates within Chrono's range."
)]

use super::{ApiKeyConfig, ApiKeyGenerator, ApiKeyPlugin, CreateKeyRequest};
use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthResult, FieldDate, FieldFunction, FieldMap,
    FieldObject, FieldValue, NativeRequest,
    endpoint_dispatch::EndpointDispatcher,
    observability::EndpointHooks,
    plugin_runtime::ModelFields,
    store::{EphemeralStore, RuntimeStore, StatelessSchema, schema::EntityRole},
};
use chrono::{DateTime, Utc};
use serde_json::{Value as Json, json};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering},
};

use crate::plugins::test_helpers::native_observation as observation;
use crate::plugins::test_helpers::native_source as source;

const EPOCH: i64 = 2_000_000_000_000;

fn lock<T>(value: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Cleanup clock observation lock poisoned"))
}

fn row(id: &str, expiration: FieldValue) -> FieldMap {
    FieldMap::from([("id".into(), id.into()), ("expiresAt".into(), expiration)])
}

#[test]
fn shared_cleanup_clock_uses_isolated_processes() -> Result<(), Box<dyn std::error::Error>> {
    for child in [
        "shared_clock_source_helper",
        "shared_clock_real_create_caller",
        "epoch_zero_and_separate_samples",
    ] {
        let name = format!("plugins::api_key::cleanup_clock_tests::{child}");
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", &name, "--ignored"])
            .output()?;
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
            "{name}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[derive(Default)]
struct CleanupTrace {
    next_span: AtomicU64,
    deletes: AtomicUsize,
}

struct SpanName<'a>(&'a AtomicUsize);

impl tracing::field::Visit for SpanName<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "otel.name" && value == "db deleteMany apikey" {
            let _ = self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
}

impl tracing::Subscriber for CleanupTrace {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }
    fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        attributes.record(&mut SpanName(&self.deletes));
        tracing::span::Id::from_u64(self.next_span.fetch_add(1, Ordering::Relaxed) + 1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

struct FailedGenerator {
    error: FieldValue,
    calls: AtomicUsize,
}

#[async_trait]
impl ApiKeyGenerator for FailedGenerator {
    async fn generate(&self, _: usize, _: Option<&str>) -> AuthResult<String> {
        let _ = self.calls.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::from_thrown(self.error.clone()))
    }
}

struct Instance {
    context: AuthContext<StatelessSchema>,
    plugin: ApiKeyPlugin,
    store: EphemeralStore,
    clock_reads: Arc<Mutex<Vec<i64>>>,
    calls: AtomicUsize,
    generator: Arc<FailedGenerator>,
    logger_calls: Arc<AtomicUsize>,
}

impl Instance {
    fn new(clock: &Arc<AtomicI64>) -> AuthResult<Self> {
        Self::with_rows(
            clock,
            vec![
                row(
                    "expired",
                    FieldDate::from_milliseconds((EPOCH - 1) as f64).into(),
                ),
                row(
                    "boundary",
                    FieldDate::from_milliseconds(EPOCH as f64).into(),
                ),
                row(
                    "live",
                    FieldDate::from_milliseconds((EPOCH + 100_000) as f64).into(),
                ),
                row("never", FieldValue::Null),
            ],
        )
    }

    fn with_rows(clock: &Arc<AtomicI64>, rows: Vec<FieldMap>) -> AuthResult<Self> {
        let logger_calls = Arc::new(AtomicUsize::new(0));
        let logger: FieldObject = FieldMap::from([("level".into(), "error".into())]).into();
        logger.set(
            "log",
            FieldFunction::contextual({
                let calls = logger_calls.clone();
                move |_, _| {
                    let _ = calls.fetch_add(1, Ordering::SeqCst);
                    Ok(FieldValue::Undefined)
                }
            })
            .into(),
        )?;
        let mut config = AuthConfig::new("cleanup-clock-contract-secret-at-least-thirty-two");
        config.base_url = "https://api-key-delete-expired.test".into();
        config.telemetry.enabled = false;
        config.logger = logger.into();
        let config = Arc::new(config);
        let store = EphemeralStore::from_storage(
            config.clone(),
            [
                ("user".into(), Vec::new()),
                ("session".into(), Vec::new()),
                ("account".into(), Vec::new()),
                ("verification".into(), Vec::new()),
                ("apikey".into(), rows),
            ],
        )?;
        let generator = Arc::new(FailedGenerator {
            error: FieldMap::from([("owner".into(), "generator".into())]).into(),
            calls: AtomicUsize::new(0),
        });
        let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
            custom_key_generator: Some(generator.clone()),
            ..Default::default()
        });
        let clock_reads = Arc::new(Mutex::new(Vec::new()));
        let mut fields = ModelFields::default();
        AuthPlugin::<StatelessSchema>::schema(&plugin, &mut fields)?;
        let database = store.with_runtime(config.clone(), Vec::new(), fields)?;
        let clock = clock.clone();
        let reads = clock_reads.clone();
        let mut context = AuthContext::new(config, database)?.with_clock(move || {
            let current = clock.load(Ordering::SeqCst);
            reads
                .lock()
                .expect("The clock recorder is not poisoned")
                .push(current);
            DateTime::<Utc>::from_timestamp_millis(current)
                .expect("The frozen source clock is within Chrono's supported dates")
        });
        context
            .extensions
            .insert(Arc::new(EndpointDispatcher::<StatelessSchema>::new(
                Arc::new(vec![Box::new(plugin.clone())]),
                EndpointHooks::default(),
                [],
            )));
        Ok(Self {
            context,
            plugin,
            store,
            clock_reads,
            calls: AtomicUsize::new(0),
            generator,
            logger_calls,
        })
    }

    fn memory(&self) -> AuthResult<Json> {
        let mut tables = FieldMap::new();
        for (name, role) in [
            ("user", EntityRole::User),
            ("session", EntityRole::Session),
            ("account", EntityRole::Account),
            ("verification", EntityRole::Verification),
            ("apikey", EntityRole::ApiKey),
        ] {
            let rows = self.store.storage_rows(role)?;
            let _ = tables.insert(
                name.into(),
                rows.into_iter()
                    .map(FieldValue::from)
                    .collect::<Vec<_>>()
                    .into(),
            );
        }
        observation::NativeObservation::default().observe(&tables.into())
    }
}

async fn replay(create_caller: bool) -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/api-key-delete-expired-1.7.6.json"
    ))?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"]
        .as_array()
        .expect("Frozen source cases are an array");
    let source = cases
        .iter()
        .find(|case| case["name"] == "shared-clock")
        .expect("The successful source run includes shared-clock");
    let steps = source["steps"]
        .as_array()
        .expect("Source steps are an array");
    assert_eq!(steps.len(), 8);
    assert_eq!(
        steps
            .iter()
            .map(|step| step["calls"].clone())
            .collect::<Vec<_>>(),
        [1, 0, 0, 0, 1, 2, 1, 2].map(Json::from)
    );
    let trace = Arc::new(CleanupTrace::default());
    tracing::subscriber::set_global_default(trace.clone()).map_err(|error| {
        AuthError::internal(format!("Cannot install isolated cleanup trace: {error}"))
    })?;
    let clock = Arc::new(AtomicI64::new(EPOCH));
    let first = Instance::new(&clock)?;
    let second = Instance::new(&clock)?;
    for (index, step) in steps.iter().enumerate() {
        let instance = if step["instance"] == "first" {
            &first
        } else {
            &second
        };
        clock.store(
            step["clock"].as_i64().expect("Source clock is an integer"),
            Ordering::SeqCst,
        );
        observation::assert_replay(
            &instance.memory()?,
            &source::source_value(&step["before"])?,
            "before",
        );
        let previous_calls = trace.deletes.load(Ordering::SeqCst);
        let previous_reads = lock(&instance.clock_reads)?.len();
        let endpoint = step["endpoint"]
            .as_bool()
            .expect("Source endpoint flag is boolean");
        let result = if endpoint {
            instance
                .plugin
                .delete_all_expired_api_keys(
                    &instance.context,
                    NativeRequest::default(),
                    FieldMap::from([("native".into(), true.into())]).into(),
                    FieldMap::from([("ignored".into(), true.into())]).into(),
                )
                .await?
        } else if create_caller {
            let result = instance
                .plugin
                .create_key(
                    &instance.context,
                    &CreateKeyRequest {
                        user_id: Some("trusted-owner".into()),
                        ..Default::default()
                    },
                )
                .await;
            let error = result.err().ok_or_else(|| {
                AuthError::internal("The original generator failure must propagate")
            })?;
            assert!(
                error
                    .into_thrown_value()?
                    .strict_equals(&instance.generator.error)
            );
            FieldValue::Undefined
        } else {
            instance
                .plugin
                .maybe_delete_expired(&instance.context, false)
                .await?;
            FieldValue::Undefined
        };
        if !create_caller || endpoint {
            let observed = observation::NativeObservation::default().observe(&result)?;
            observation::assert_replay(
                &observed,
                &source::source_value(&step["outcome"]["result"])?,
                "result",
            );
        }
        let deletes = trace.deletes.load(Ordering::SeqCst) - previous_calls;
        let _ = instance.calls.fetch_add(deletes, Ordering::SeqCst);
        assert_eq!(
            Json::from(instance.calls.load(Ordering::SeqCst)),
            step["calls"]
        );
        let source_deletes = step["events"]
            .as_array()
            .expect("Source events are an array")
            .iter()
            .filter(|event| event["phase"] == "adapter:deleteMany")
            .collect::<Vec<_>>();
        assert_eq!(deletes, source_deletes.len());
        let reads = lock(&instance.clock_reads)?;
        let samples = &reads[previous_reads..];
        assert_eq!(samples.len(), [2, 1, 1, 1, 3, 2, 1, 3][index]);
        drop(reads);
        observation::assert_replay(
            &instance.memory()?,
            &source::source_value(&step["after"])?,
            "after",
        );
    }
    assert_eq!(
        first.logger_calls.load(Ordering::SeqCst) + second.logger_calls.load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        first.generator.calls.load(Ordering::SeqCst)
            + second.generator.calls.load(Ordering::SeqCst),
        if create_caller { 7 } else { 0 }
    );
    assert_eq!(source["loggerCalls"], 0);
    assert_eq!(source["functions"], json!([]));
    Ok(())
}

#[tokio::test]
#[ignore = "The parent starts a fresh process because upstream cleanup state is module-global"]
async fn shared_clock_source_helper() -> AuthResult<()> {
    replay(false).await
}

#[tokio::test]
#[ignore = "The parent starts a fresh process because upstream cleanup state is module-global"]
async fn shared_clock_real_create_caller() -> AuthResult<()> {
    replay(true).await
}

#[tokio::test]
#[ignore = "The parent starts a fresh process because upstream cleanup state is module-global"]
async fn epoch_zero_and_separate_samples() -> AuthResult<()> {
    let trace = Arc::new(CleanupTrace::default());
    tracing::subscriber::set_global_default(trace.clone()).map_err(|error| {
        AuthError::internal(format!("Cannot install isolated cleanup trace: {error}"))
    })?;
    let clock = Arc::new(AtomicI64::new(0));
    let rows = vec![
        row("expired", FieldDate::from_milliseconds(-1.0).into()),
        row("stamp", FieldDate::from_milliseconds(0.0).into()),
        row("cutoff", FieldDate::from_milliseconds(1.0).into()),
        row("next-stamp", FieldDate::from_milliseconds(10_001.0).into()),
        row("next-cutoff", FieldDate::from_milliseconds(10_002.0).into()),
        row("live", FieldDate::from_milliseconds(100_000.0).into()),
        row("never", FieldValue::Null),
    ];
    let mut instance = Instance::with_rows(&clock, rows.clone())?;
    let mut expected = instance.memory()?;
    let reads = instance.clock_reads.clone();
    let ticks = clock.clone();
    instance.context = instance.context.with_clock(move || {
        let current = ticks.fetch_add(1, Ordering::SeqCst);
        reads
            .lock()
            .expect("The clock recorder is not poisoned")
            .push(current);
        DateTime::<Utc>::from_timestamp_millis(current)
            .expect("The scripted clock is within Chrono's supported dates")
    });
    instance
        .plugin
        .maybe_delete_expired(&instance.context, false)
        .await?;
    assert_eq!(
        instance.store.plugin_storage_rows(EntityRole::ApiKey)?,
        rows[2..]
    );
    expected["apikey"] = observation::NativeObservation::default().observe(
        &rows[2..]
            .iter()
            .cloned()
            .map(FieldValue::from)
            .collect::<Vec<_>>()
            .into(),
    )?;
    observation::assert_replay(
        &instance.memory()?,
        &expected,
        "cutoff 1 deletes stamp 0 and retains boundary 1",
    );
    instance
        .plugin
        .maybe_delete_expired(&instance.context, false)
        .await?;
    observation::assert_replay(
        &instance.memory()?,
        &expected,
        "the skipped epoch-zero check leaves all tables unchanged",
    );
    assert_eq!(
        trace.deletes.load(Ordering::SeqCst),
        1,
        "A Date at epoch zero still establishes the shared interval"
    );
    clock.store(10_000, Ordering::SeqCst);
    instance
        .plugin
        .maybe_delete_expired(&instance.context, false)
        .await?;
    assert_eq!(
        instance.store.plugin_storage_rows(EntityRole::ApiKey)?,
        rows[4..]
    );
    expected["apikey"] = observation::NativeObservation::default().observe(
        &rows[4..]
            .iter()
            .cloned()
            .map(FieldValue::from)
            .collect::<Vec<_>>()
            .into(),
    )?;
    observation::assert_replay(
        &instance.memory()?,
        &expected,
        "cutoff 10002 deletes stamp 10001 and retains boundary 10002",
    );
    clock.store(-100, Ordering::SeqCst);
    instance
        .plugin
        .maybe_delete_expired(&instance.context, true)
        .await?;
    clock.store(9_900, Ordering::SeqCst);
    instance
        .plugin
        .maybe_delete_expired(&instance.context, false)
        .await?;
    assert_eq!(
        *lock(&instance.clock_reads)?,
        [
            0, 1, 2, 10_000, 10_001, 10_002, -100, -99, 9_900, 9_901, 9_902
        ]
    );
    assert_eq!(trace.deletes.load(Ordering::SeqCst), 4);
    observation::assert_replay(
        &instance.memory()?,
        &expected,
        "future rows survive the rollback cutoffs",
    );
    assert_eq!(instance.logger_calls.load(Ordering::SeqCst), 0);
    Ok(())
}
