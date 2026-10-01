mod options;
pub use options::{
    EmailPasswordTelemetry, EmailVerificationTelemetry, PasswordTelemetry, PluginTelemetry,
};

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::{Rng, distributions::Alphanumeric};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::logger::{LogArgument, LoggerConfig};
use crate::{AuthConfig, AuthResult};

/// Usage reporting is disabled unless explicitly enabled here or through BETTER_AUTH_TELEMETRY.
#[derive(Clone, Default)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub debug: bool,
    /// Application-controlled reporting. This callback takes precedence over an endpoint.
    pub track: Option<Arc<dyn TelemetryTransport>>,
}

/// Serialized report. Authentication secrets and request records must not enter the payload.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryEvent {
    #[serde(rename = "type")]
    pub kind: String,
    pub payload: Value,
    pub anonymous_id: String,
}

#[async_trait]
pub trait TelemetryTransport: Send + Sync {
    async fn send(&self, event: &TelemetryEvent) -> AuthResult<()>;
}

/// Per-auth opt-in state. The host supplies HTTP transport using its existing HTTP client.
#[derive(Clone)]
pub struct Telemetry {
    transport: Option<Arc<dyn TelemetryTransport>>,
    debug: bool,
    anonymous_id: String,
}

fn environment_bool(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
    })
}

fn is_test() -> bool {
    std::env::var("NODE_ENV").is_ok_and(|value| value == "test")
        || std::env::var("TEST").is_ok_and(|value| !value.is_empty() && value != "false")
}

impl Telemetry {
    pub fn enabled(&self) -> bool {
        self.transport.is_some()
    }

    pub fn new(
        config: &AuthConfig,
        endpoint_transport: Option<Arc<dyn TelemetryTransport>>,
    ) -> Self {
        let custom = config.telemetry.track.clone();
        let transport = custom.clone().or(endpoint_transport);
        let enabled =
            (config.telemetry.enabled || environment_bool("BETTER_AUTH_TELEMETRY")) && !is_test();
        let anonymous_id = if enabled && transport.is_some() {
            // The upstream telemetry module reuses one project ID across initialized instances.
            static PROJECT_ID: OnceLock<String> = OnceLock::new();
            PROJECT_ID
                .get_or_init(
                    || match config.base_url.as_static().filter(|url| !url.is_empty()) {
                        Some(url) => STANDARD.encode(Sha256::digest(url.as_bytes())),
                        None => rand::thread_rng()
                            .sample_iter(Alphanumeric)
                            .take(32)
                            .map(char::from)
                            .collect(),
                    },
                )
                .clone()
        } else {
            String::new()
        };
        Self {
            transport: if enabled { transport } else { None },
            debug: custom.is_none()
                && (config.telemetry.debug || environment_bool("BETTER_AUTH_TELEMETRY_DEBUG")),
            anonymous_id,
        }
    }

    /// Transport errors are logged as specified by upstream and do not fail authentication.
    pub async fn publish(&self, kind: impl Into<String>, payload: Value) -> AuthResult<()> {
        let Some(transport) = &self.transport else {
            return Ok(());
        };
        let event = TelemetryEvent {
            kind: kind.into(),
            payload,
            anonymous_id: self.anonymous_id.clone(),
        };
        if self.debug {
            let value = Value::String(serde_json::to_string_pretty(&event)?);
            LoggerConfig::default().info("telemetry event", &[LogArgument::Value(&value)]);
        } else if let Err(error) = transport.send(&event).await {
            LoggerConfig::default().log(
                super::logger::LogLevel::Error,
                LogArgument::Error(&error),
                &[],
            );
        }
        Ok(())
    }
}
