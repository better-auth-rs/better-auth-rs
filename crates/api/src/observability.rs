//! Host transport for optional Better Auth telemetry.
use async_trait::async_trait;
use better_auth_core::observability::telemetry::{Telemetry, TelemetryEvent, TelemetryTransport};
use better_auth_core::{AuthConfig, AuthError, AuthResult};
use std::sync::Arc;
struct HttpTelemetry {
    endpoint: String,
    client: reqwest::Client,
}
#[async_trait]
impl TelemetryTransport for HttpTelemetry {
    async fn send(&self, event: &TelemetryEvent) -> AuthResult<()> {
        let _ = self
            .client
            .post(&self.endpoint)
            .json(event)
            .send()
            .await
            .map_err(|error| AuthError::internal(format!("Telemetry transport failed: {error}")))?;
        Ok(())
    }
}

pub fn initialize_telemetry(config: &AuthConfig) -> Telemetry {
    let endpoint = std::env::var("BETTER_AUTH_TELEMETRY_ENDPOINT")
        .ok()
        .filter(|value| !value.is_empty());
    let transport = endpoint.map(|endpoint| {
        Arc::new(HttpTelemetry {
            endpoint,
            client: reqwest::Client::new(),
        }) as Arc<dyn TelemetryTransport>
    });
    Telemetry::new(config, transport)
}
