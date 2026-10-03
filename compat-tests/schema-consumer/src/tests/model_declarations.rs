use std::sync::{Arc, Mutex};

use better_auth::{
    AuthConfig, AuthResult, BetterAuth,
    observability::{TelemetryEvent, TelemetryTransport},
    seaorm::{
        Database, DatabaseConnection, SeaOrmStore,
        sea_orm::{ConnectionTrait, DbBackend, Statement},
    },
};
use serde_json::{Map, Value};

mod omitted {
    include!(env!("BETTER_AUTH_DECLARATIONS_OMITTED_SCHEMA"));
}
mod empty {
    include!(env!("BETTER_AUTH_DECLARATIONS_EMPTY_SCHEMA"));
}
mod explicit_defaults {
    include!(env!("BETTER_AUTH_DECLARATIONS_DEFAULTS_SCHEMA"));
}
mod renamed {
    include!(env!("BETTER_AUTH_DECLARATIONS_RENAMED_SCHEMA"));
}

#[derive(Default)]
struct Reports(Mutex<Vec<Value>>);

#[better_auth::__private_core::__private_async_trait::async_trait]
impl TelemetryTransport for Reports {
    async fn send(&self, event: &TelemetryEvent) -> AuthResult<()> {
        self.0.lock().unwrap().push(event.payload["config"].clone());
        Ok(())
    }
}

async fn compare(name: &str, database: &DatabaseConnection, reports: &Reports) {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/telemetry-model-declarations-1.7.6.json"
    ))
    .unwrap();
    let expected = &fixture[name]["expected"];
    let actual = {
        let reports = reports.0.lock().unwrap();
        assert_eq!(reports.len(), 1, "{name}");
        reports[0].clone()
    };
    let mut declarations = Map::new();
    for (model, default_table, field, default_column) in [
        ("user", "users", "email", "email"),
        ("session", "sessions", "ipAddress", "ip_address"),
        ("account", "accounts", "providerId", "provider_id"),
        ("verification", "verification", "identifier", "identifier"),
    ] {
        let values = ["modelName", "fields"]
            .into_iter()
            .filter_map(|key| {
                actual[model]
                    .get(key)
                    .map(|value| (key.into(), value.clone()))
            })
            .collect::<Map<_, _>>();
        declarations.insert(model.into(), Value::Object(values));
        let table = expected[model]["modelName"]
            .as_str()
            .unwrap_or(default_table);
        let column = expected[model]["fields"][field]
            .as_str()
            .unwrap_or(default_column);
        let columns = database
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                format!("PRAGMA table_info(\"{table}\")"),
            ))
            .await
            .unwrap();
        assert!(
            columns
                .iter()
                .any(|row| row.try_get::<String>("", "name").unwrap() == column),
            "{name}: missing {table}.{column}"
        );
        let count = database
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                format!("SELECT COUNT(*) AS count FROM \"{table}\""),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            count.try_get::<i64>("", "count").unwrap(),
            0,
            "{name}/{model}"
        );
    }
    assert_eq!(Value::Object(declarations), *expected, "{name}");
}

#[tokio::test]
async fn generated_declarations_match_real_initialization_and_sqlite_mappings() {
    macro_rules! check {
        ($module:ident, $name:literal) => {{
            let database = Database::connect("sqlite::memory:").await.unwrap();
            $module::create_auth_tables(&database).await.unwrap();
            let reports = Arc::new(Reports::default());
            let mut config = AuthConfig::new("model-declaration-consumer-secret-0123456789")
                .base_url("https://example.test");
            config.telemetry.enabled = true;
            config.telemetry.track = Some(reports.clone());
            let _auth = BetterAuth::<$module::AppAuthSchema>::new(config.clone())
                .store(SeaOrmStore::<$module::AppAuthSchema>::new(
                    config,
                    database.clone(),
                ))
                .build()
                .await
                .unwrap();
            compare($name, &database, &reports).await;
        }};
    }
    check!(omitted, "omitted");
    check!(empty, "empty");
    check!(explicit_defaults, "explicitDefaults");
    check!(renamed, "renamed");
}
