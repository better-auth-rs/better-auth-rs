use super::*;
use better_auth::observability::{TelemetryEvent, TelemetryTransport};

#[derive(Default)]
struct Reports(Mutex<Vec<Value>>);

#[async_trait]
impl TelemetryTransport for Reports {
    async fn send(&self, event: &TelemetryEvent) -> AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push(event.payload["config"]["advanced"]["cookieAttributes"].clone());
        Ok(())
    }
}

#[tokio::test]
async fn explicit_expiration_telemetry_preserves_utc_milliseconds_and_omission() {
    let fixture = fixture();
    let source_anchor = fixture["metadata"]["serializerNow"].as_i64().unwrap();
    for (name, expected) in fixture["telemetry"].as_object().unwrap() {
        let now = anchor();
        let reports = Arc::new(Reports::default());
        let mut config = config();
        config.advanced.default_cookie_attributes.expires =
            date(&expected["input"]["expires"], source_anchor, now);
        config.telemetry.enabled = true;
        config.telemetry.track = Some(reports.clone());
        let _auth = BetterAuth::stateless(config).build().await.unwrap();
        let reports = reports.0.lock().unwrap();
        assert_eq!(reports.len(), 1, "{name}");
        assert_eq!(
            normalize(&reports[0], now),
            normalize(&expected["projected"]["attributes"], source_anchor),
            "{name}"
        );
    }
}
