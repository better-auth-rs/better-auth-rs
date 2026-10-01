#![expect(
    clippy::panic_in_result_fn,
    reason = "tests propagate setup failures and assert pinned upstream behavior"
)]

use async_trait::async_trait;
use better_auth::observability::{TelemetryEvent, TelemetryTransport};
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

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
struct Reports(Mutex<Vec<Value>>);
#[async_trait]
impl TelemetryTransport for Reports {
    async fn send(&self, event: &TelemetryEvent) -> AuthResult<()> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("telemetry capture poisoned"))?
            .push(event.payload.clone());
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
    for key in [
        "systemRelease",
        "cpuCount",
        "cpuModel",
        "cpuSpeed",
        "memory",
        "isWSL",
        "isDocker",
    ] {
        assert_eq!(
            actual.get("systemInfo").and_then(|system| system.get(key)),
            Some(&Value::Null),
            "{key}"
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
    compare_metadata(
        &Value::Object(better_auth::__private_core::observability::telemetry::Telemetry::initialization_metadata()),
        expected,
    );
    let reports = Arc::new(Reports::default());
    let mut config = AuthConfig::new("telemetry-environment-normal-secret-0123456789")
        .base_url("https://example.test");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = true;
    config.telemetry.track = Some(reports.clone());
    let _auth = BetterAuth::stateless(config).build().await?;
    let events = reports
        .0
        .lock()
        .map_err(|_| AuthError::internal("telemetry capture poisoned"))?;
    assert_eq!(
        Some(events.len() as u64),
        case.get("authEvents").and_then(Value::as_u64)
    );
    for event in events.iter() {
        compare_metadata(event, expected);
    }
    Ok(())
}
