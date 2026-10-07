#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Pinned fixture fields and ordinary local database rows must exist for this contract."
)]

use better_auth::plugins::DeviceAuthorizationPlugin;
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::{
    AuthRequest, AuthSchema, AuthStore, HttpMethod,
    middleware::RateLimitConfig,
    store::{DeviceCodeStore, EphemeralStore, StatelessSchema},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::Duration;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

const ORIGIN: &str = "http://device-interval.test";
const DEVICE_CODE: &str = "ordinary-device-interval";
const USER_CODE: &str = "ABCDEF12";

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Observation {
    backend: String,
    name: String,
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
    stored_interval: f64,
    sql: Value,
}

fn config() -> AuthConfig {
    let mut config =
        AuthConfig::new("ordinary-device-interval-secret-at-least-32-characters").base_url(ORIGIN);
    config.logger.disabled = Some(true);
    config
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/device-interval-1.7.6.json")).unwrap()
}

async fn issuance<S: AuthSchema>(
    store: impl AuthStore<S> + 'static,
    expected: &Value,
    database: Option<&DatabaseConnection>,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected: Observation = serde_json::from_value(expected.clone())?;
    let mut plugin = DeviceAuthorizationPlugin::new()
        .generate_device_code_with(|| async { Ok(DEVICE_CODE.into()) })
        .generate_user_code_with(|| async { Ok(USER_CODE.into()) });
    if expected.name == "fractional" {
        plugin = plugin.interval(Duration::microseconds(1500));
    } else if expected.name == "negative" {
        plugin = plugin
            .interval(Duration::microseconds(-1500))
            .expires_in(Duration::milliseconds(-500));
    }
    let auth = BetterAuth::<S>::new(config())
        .store(store)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(plugin)
        .build()
        .await?;
    let request = AuthRequest::from_parts(
        HttpMethod::Post,
        "/api/auth/device/code".into(),
        [
            ("content-type".into(), "application/json".into()),
            ("origin".into(), ORIGIN.into()),
        ]
        .into(),
        Some(serde_json::to_vec(
            &json!({"client_id": "ordinary-client", "scope": "read"}),
        )?),
        None,
    );
    let response = auth.handle_request(request).await?;
    let mut headers: Vec<_> = response
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    headers.sort();
    let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
    let stored = auth
        .store()
        .get_device_code_by_device_code(DEVICE_CODE)
        .await?
        .unwrap();
    assert_eq!(stored.polling_interval, Some(expected.stored_interval));
    let stored_interval = serde_json::to_value(&stored)?["pollingInterval"]
        .as_f64()
        .unwrap();
    let sql = if let Some(database) = database {
        let column = database
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT type, [notnull] AS required FROM pragma_table_info('device_code') WHERE name = 'polling_interval'",
            ))
            .await?
            .unwrap();
        let raw = database
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT typeof(polling_interval) AS storage_class FROM device_code WHERE device_code = ?",
                [DEVICE_CODE.into()],
            ))
            .await?
            .unwrap();
        json!({
            "columnType": column.try_get::<String>("", "type")?,
            "nullable": column.try_get::<i64>("", "required")? == 0,
            "storageClass": raw.try_get::<String>("", "storage_class")?,
        })
    } else {
        Value::Null
    };
    assert_eq!(
        Observation {
            backend: expected.backend.clone(),
            name: expected.name.clone(),
            status: response.status,
            headers,
            body,
            stored_interval,
            sql,
        },
        expected,
    );
    Ok(())
}

#[tokio::test]
async fn unconsumed_issuance_preserves_pinned_interval_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    for expected in fixture()["cases"].as_array().unwrap() {
        if expected["backend"] == "memory" {
            issuance::<StatelessSchema>(EphemeralStore::new(Arc::new(config())), expected, None)
                .await?;
        } else {
            let database = Database::connect("sqlite::memory:").await?;
            migrator::run_migrations(&database).await?;
            issuance::<BundledSchema>(
                SeaOrmStore::<BundledSchema>::new(config(), database.clone()),
                expected,
                Some(&database),
            )
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn existing_bigint_columns_read_integer_and_fractional_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    let _ = database
        .execute_unprepared(
            "CREATE TABLE device_code (
                id TEXT PRIMARY KEY, device_code TEXT NOT NULL UNIQUE,
                user_code TEXT NOT NULL UNIQUE, user_id TEXT, expires_at TEXT NOT NULL,
                status TEXT NOT NULL, last_polled_at TEXT, polling_interval BIGINT,
                client_id TEXT, scope TEXT
            );
            INSERT INTO device_code (id, device_code, user_code, expires_at, status, polling_interval)
            VALUES ('integer', 'ordinary-integer', 'INTEGER1', '2030-01-01T00:00:00Z', 'pending', 5000),
                   ('fractional', 'ordinary-fractional', 'FRACTION', '2030-01-01T00:00:00Z', 'pending', 1.5)",
        )
        .await?;
    let store = SeaOrmStore::<BundledSchema>::new(config(), database.clone());
    for (code, interval) in [("ordinary-integer", 5000.0), ("ordinary-fractional", 1.5)] {
        let row = store.get_device_code_by_device_code(code).await?.unwrap();
        assert_eq!(row.polling_interval, Some(interval));
        assert_eq!(serde_json::to_value(row)?["pollingInterval"], interval);
    }
    let column = database
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT type FROM pragma_table_info('device_code') WHERE name = 'polling_interval'",
        ))
        .await?
        .unwrap();
    assert_eq!(column.try_get::<String>("", "type")?, "BIGINT");
    Ok(())
}
