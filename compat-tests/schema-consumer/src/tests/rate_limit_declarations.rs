use std::sync::{Arc, Mutex};

use better_auth::{
    AuthConfig, AuthResult, BetterAuth,
    middleware::{RateLimitConfig, RateLimitStorageKind},
    observability::{TelemetryEvent, TelemetryTransport},
    seaorm::{
        Database, DatabaseConnection, SeaOrmStore,
        sea_orm::{ConnectionTrait, DbBackend, Statement},
    },
    store::MemoryCacheAdapter,
};
use serde_json::Value;

mod omitted {
    include!(env!("BETTER_AUTH_RATE_MODEL_OMITTED_SCHEMA"));
}
mod empty {
    include!(env!("BETTER_AUTH_RATE_MODEL_EMPTY_SCHEMA"));
}
mod explicit_defaults {
    include!(env!("BETTER_AUTH_RATE_MODEL_DEFAULTS_SCHEMA"));
}
mod renamed {
    include!(env!("BETTER_AUTH_RATE_MODEL_RENAMED_SCHEMA"));
}

#[derive(Default)]
struct Reports(Mutex<Vec<Value>>);

#[better_auth::__private_core::__private_async_trait::async_trait]
impl TelemetryTransport for Reports {
    async fn send(&self, event: &TelemetryEvent) -> AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push(event.payload["config"]["rateLimit"].clone());
        Ok(())
    }
}

fn configuration() -> (AuthConfig, Arc<Reports>) {
    let reports = Arc::new(Reports::default());
    let mut config = AuthConfig::new("rate-model-declaration-consumer-secret-0123456789")
        .base_url("https://example.test");
    config.telemetry.enabled = true;
    config.telemetry.track = Some(reports.clone());
    (config, reports)
}

async fn compare(name: &str, database: &DatabaseConnection, reports: &Reports) {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/telemetry-rate-limit-model-1.7.6.json"
    ))
    .unwrap();
    let case = &fixture[name];
    {
        let reports = reports.0.lock().unwrap();
        assert_eq!(reports.len(), 1, "{name}");
        assert_eq!(reports[0], case["expected"], "{name}");
    }
    let table = case["options"]["rateLimit"]["modelName"]
        .as_str()
        .unwrap_or("rate_limit");
    let columns = database
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            format!("PRAGMA table_info(\"{table}\")"),
        ))
        .await
        .unwrap();
    for (field, default_column) in [
        ("key", "key"),
        ("count", "count"),
        ("lastRequest", "last_request"),
    ] {
        let column = case["options"]["rateLimit"]["fields"][field]
            .as_str()
            .unwrap_or(default_column);
        assert!(
            columns
                .iter()
                .any(|row| row.try_get::<String>("", "name").unwrap() == column),
            "{name}: missing {table}.{column}"
        );
    }
    let row = database
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            format!("SELECT COUNT(*) AS count FROM \"{table}\""),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<i64>("", "count").unwrap(), 0, "{name}");
}

#[tokio::test]
async fn rate_limit_declarations_follow_generated_models_and_secondary_wrappers() {
    macro_rules! check {
        ($module:ident, $name:literal) => {{
            for secondary in [false, true] {
                let database = Database::connect("sqlite::memory:").await.unwrap();
                $module::create_auth_tables(&database).await.unwrap();
                let (config, reports) = configuration();
                let store =
                    SeaOrmStore::<$module::AppAuthSchema>::new(config.clone(), database.clone())
                        .with_plugin_schema::<$module::AppPluginSchema>();
                let mut builder = BetterAuth::<$module::AppAuthSchema>::new(config)
                    .store(store)
                    .rate_limit(RateLimitConfig::default().storage(RateLimitStorageKind::Database));
                if secondary {
                    builder = builder.secondary_storage(Arc::new(MemoryCacheAdapter::new()));
                }
                let auth = builder.build().await.unwrap();
                compare($name, &database, &reports).await;
                let reported_name = auth
                    .store()
                    .rate_limit_model_declaration()
                    .and_then(|model| model.model_name);
                assert_eq!(
                    reported_name,
                    reports.0.lock().unwrap()[0]["modelName"].as_str()
                );
            }
        }};
    }
    check!(omitted, "omitted");
    check!(empty, "empty");
    check!(explicit_defaults, "explicitDefaults");
    check!(renamed, "renamed");
}

#[tokio::test]
async fn replacing_plugin_schema_replaces_the_reported_rate_limit_declaration() {
    macro_rules! check {
        ($module:ident, $name:literal) => {{
            let database = Database::connect("sqlite::memory:").await.unwrap();
            $module::create_auth_tables(&database).await.unwrap();
            let (config, reports) = configuration();
            let store =
                SeaOrmStore::<renamed::AppAuthSchema>::new(config.clone(), database.clone())
                    .with_plugin_schema::<renamed::AppPluginSchema>()
                    .with_plugin_schema::<$module::AppPluginSchema>();
            let _auth = BetterAuth::<renamed::AppAuthSchema>::new(config)
                .store(store)
                .rate_limit(RateLimitConfig::default().storage(RateLimitStorageKind::Database))
                .build()
                .await
                .unwrap();
            compare($name, &database, &reports).await;
        }};
    }
    check!(omitted, "omitted");
    check!(explicit_defaults, "explicitDefaults");
}
