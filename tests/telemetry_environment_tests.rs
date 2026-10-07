#![expect(
    clippy::panic_in_result_fn,
    reason = "tests propagate setup failures and assert pinned upstream behavior"
)]

use async_trait::async_trait;
use better_auth::observability::{TelemetryEvent, TelemetryTransport};
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use serde_json::{Value, json};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const OBSERVATION_DIR_ENV: &str = "BETTER_AUTH_TELEMETRY_OBSERVATION_DIR";
const UPSTREAM_OBSERVATION_ENV: &str = "BETTER_AUTH_TELEMETRY_UPSTREAM_OBSERVATION";

fn fixture() -> Result<Value, serde_json::Error> {
    serde_json::from_str(include_str!("fixtures/telemetry-environment-1.7.6.json"))
}

#[test]
fn initialization_metadata_matches_upstream_in_independent_processes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let keys = fixture
        .get("clearedKeys")
        .and_then(Value::as_array)
        .ok_or("missing environment keys")?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_object)
        .ok_or("missing environment cases")?;
    let observation_dir = std::env::var_os(OBSERVATION_DIR_ENV).map(PathBuf::from);
    if let Some(directory) = &observation_dir {
        std::fs::create_dir_all(directory)?;
    }
    let upstream_observation = std::env::var_os(UPSTREAM_OBSERVATION_ENV);
    for (name, case) in cases {
        let mut child = std::process::Command::new(std::env::current_exe()?);
        let _ = child.args(["--exact", "environment_case", "--ignored"]);
        for key in keys {
            let _ = child.env_remove(key.as_str().ok_or("invalid environment key")?);
        }
        let env = case
            .get("env")
            .and_then(Value::as_object)
            .ok_or("missing case environment")?;
        for (key, value) in env {
            let _ = child.env(key, value.as_str().ok_or("invalid environment value")?);
        }
        let _ = child.env("BETTER_AUTH_TEST_TELEMETRY_CASE", name);
        if let Some(directory) = &observation_dir {
            let _ = child.env(OBSERVATION_DIR_ENV, directory);
        }
        if let Some(path) = &upstream_observation {
            let _ = child.env(UPSTREAM_OBSERVATION_ENV, path);
        }
        let output = child.output()?;
        assert!(
            output.status.success(),
            "{name}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[derive(Default)]
struct Reports(Mutex<Vec<TelemetryEvent>>);
#[async_trait]
impl TelemetryTransport for Reports {
    async fn send(&self, event: &TelemetryEvent) -> AuthResult<()> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("telemetry capture poisoned"))?
            .push(event.clone());
        Ok(())
    }
}

fn compare_metadata(actual: &Value, expected: &Value) {
    for key in ["environment", "packageManager"] {
        assert_eq!(actual.get(key), expected.get(key), "{key}");
    }
    assert_eq!(
        actual.pointer("/systemInfo/deploymentVendor"),
        expected.pointer("/systemInfo/deploymentVendor")
    );
    for key in ["cpuCount", "cpuModel", "cpuSpeed", "memory"] {
        assert_eq!(
            actual.get("systemInfo").and_then(|system| system.get(key)),
            Some(&Value::Null),
            "{key}"
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(
            actual.pointer("/systemInfo/systemRelease"),
            Some(&Value::Null)
        );
        assert_eq!(
            actual.pointer("/systemInfo/isWSL"),
            Some(&Value::Bool(false))
        );
    }
    assert!(
        actual.pointer("/systemInfo/isTTY").is_none(),
        "piped children must omit isTTY"
    );
    assert_eq!(
        actual.get("runtime"),
        Some(&json!({"name":"rust","version":null}))
    );
}

fn compare_host(actual: &Value, expected: &Value) -> AuthResult<()> {
    let actual_system = actual
        .get("systemInfo")
        .and_then(Value::as_object)
        .ok_or_else(|| AuthError::internal("missing Rust system metadata"))?;
    let expected_system = expected
        .get("systemInfo")
        .and_then(Value::as_object)
        .ok_or_else(|| AuthError::internal("missing upstream system observation"))?;
    assert_eq!(
        actual_system.keys().collect::<Vec<_>>(),
        expected_system.keys().collect::<Vec<_>>(),
        "system metadata keys and order must match the upstream event from this runner"
    );
    for key in ["isDocker", "isWSL"] {
        let pointer = format!("/systemInfo/{key}");
        let value = expected
            .pointer(&pointer)
            .and_then(Value::as_bool)
            .ok_or_else(|| AuthError::internal(format!("missing upstream {key} observation")))?;
        assert_eq!(
            actual.pointer(&pointer),
            Some(&Value::Bool(value)),
            "{key} must match the upstream event from this runner"
        );
    }
    #[cfg(target_os = "linux")]
    {
        let release = expected
            .pointer("/systemInfo/systemRelease")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::internal("missing upstream release observation"))?;
        assert_eq!(
            actual.pointer("/systemInfo/systemRelease"),
            Some(&json!(release)),
            "Linux release must match the upstream event from this runner"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "the parent provides each isolated environment and fixture case"]
async fn environment_case() -> AuthResult<()> {
    let name = std::env::var("BETTER_AUTH_TEST_TELEMETRY_CASE")
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let fixture = fixture()?;
    let case = fixture
        .get("cases")
        .and_then(|cases| cases.get(&name))
        .ok_or_else(|| AuthError::internal("unknown telemetry environment case"))?;
    let expected = case
        .get("metadata")
        .ok_or_else(|| AuthError::internal("missing expected metadata"))?;
    let metadata = Value::Object(
        better_auth::__private_core::observability::telemetry::Telemetry::initialization_metadata(),
    );
    let reports = Arc::new(Reports::default());
    let mut config = AuthConfig::new("telemetry-environment-normal-secret-0123456789")
        .base_url("https://example.test");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = true;
    config.telemetry.track = Some(reports.clone());
    let auth = BetterAuth::stateless(config).build().await;
    let events = reports
        .0
        .lock()
        .map_err(|_| AuthError::internal("telemetry capture poisoned"))?;
    if let Some(directory) = std::env::var_os(OBSERVATION_DIR_ENV) {
        let path = PathBuf::from(directory).join(format!("rust-{name}.json"));
        let observation = json!({
            "case": name,
            "env": case.get("env"),
            "package": {"name": env!("CARGO_PKG_NAME"), "version": env!("CARGO_PKG_VERSION")},
            "stdout": {"mode": "pipe", "isTerminal": std::io::stdout().is_terminal()},
            "initializationMetadata": metadata,
            "auth": &*events,
            "buildError": auth.as_ref().err().map(ToString::to_string),
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&observation)?).map_err(|error| {
            AuthError::internal(format!(
                "cannot write telemetry observation {}: {error}",
                path.display()
            ))
        })?;
    }
    let _auth = auth?;
    compare_metadata(&metadata, expected);
    assert_eq!(
        Some(events.len() as u64),
        case.get("authEvents").and_then(Value::as_u64)
    );
    for event in events.iter() {
        compare_metadata(&event.payload, expected);
    }
    if let Some(path) = std::env::var_os(UPSTREAM_OBSERVATION_ENV) {
        let path = PathBuf::from(path);
        let upstream: Value = serde_json::from_slice(&std::fs::read(&path).map_err(|error| {
            AuthError::internal(format!(
                "cannot read upstream telemetry observation {}: {error}",
                path.display()
            ))
        })?)?;
        let observation = upstream
            .get("cases")
            .and_then(|cases| cases.get(&name))
            .and_then(|case| case.get("observation"))
            .ok_or_else(|| AuthError::internal("missing upstream telemetry case"))?;
        let direct = observation
            .pointer("/direct/0/payload")
            .ok_or_else(|| AuthError::internal("missing upstream direct telemetry event"))?;
        compare_host(&metadata, direct)?;
        let upstream_events = observation
            .get("auth")
            .and_then(Value::as_array)
            .ok_or_else(|| AuthError::internal("missing upstream auth telemetry events"))?;
        assert_eq!(events.len(), upstream_events.len());
        for (event, upstream_event) in events.iter().zip(upstream_events) {
            let payload = upstream_event
                .get("payload")
                .ok_or_else(|| AuthError::internal("missing upstream auth telemetry payload"))?;
            compare_host(&event.payload, payload)?;
        }
    }
    Ok(())
}
