#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "Pinned fixture fields and ordinary successful issuance rows must exist for this contract."
)]

use better_auth::plugins::DeviceAuthorizationPlugin;
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::{
    AuthRequest, HttpMethod,
    middleware::RateLimitConfig,
    store::{EphemeralStore, StatelessSchema},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

const ORIGIN: &str = "http://device-issuance.test";
const DEVICE_CODE: &str = "ordinary-issuance-device";
const USER_CODE: &str = "ABCD 2345+";

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Observation {
    name: String,
    configuration: Value,
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
    persisted_codes_match: Value,
    stored: StoredObservation,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredObservation {
    client_id: Option<String>,
    scope: Option<String>,
    status: String,
    polling_interval: f64,
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions report contract differences; Result propagates setup and API errors."
)]
async fn ordinary_device_issuance_matches_pinned_code_and_uri_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/device-issuance-1.7.6.json"))?;
    for expected in fixture["cases"].as_array().expect("captured cases") {
        let expected: Observation = serde_json::from_value(expected.clone())?;
        let default_device_code = expected.configuration["defaultDeviceCode"]
            .as_bool()
            .expect("generator selection");
        let mut plugin = DeviceAuthorizationPlugin::new()
            .generate_user_code_with(|| async { Ok(USER_CODE.into()) });
        if !default_device_code {
            plugin = plugin.generate_device_code_with(|| async { Ok(DEVICE_CODE.into()) });
        }
        if let Some(uri) = expected.configuration.get("verificationUri") {
            plugin = plugin.verification_uri(uri.as_str().expect("configured URI"));
        }
        if let Some(length) = expected.configuration.get("deviceCodeLength") {
            plugin = plugin.device_code_length(usize::try_from(
                length.as_u64().expect("configured length"),
            )?);
        }
        let mut config = AuthConfig::new("ordinary-device-issuance-secret-at-least-32-characters")
            .base_url(ORIGIN);
        config.logger.disabled = Some(true);
        let store = EphemeralStore::new(Arc::new(config.clone()));
        let auth = BetterAuth::<StatelessSchema>::new(config)
            .store(store)
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(plugin)
            .build()
            .await?;
        let response = auth
            .handle_request(AuthRequest::from_parts(
                HttpMethod::Post,
                "/api/auth/device/code".into(),
                [
                    ("content-type".into(), "application/json".into()),
                    ("origin".into(), ORIGIN.into()),
                ]
                .into(),
                Some(serde_json::to_vec(
                    &json!({"client_id":"ordinary-client","scope":"read"}),
                )?),
                None,
            ))
            .await?;
        let mut headers: Vec<_> = response
            .headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect();
        headers.sort();
        let mut body: Value = serde_json::from_slice(&response.body.bytes()?)?;
        let device_code = body["device_code"]
            .as_str()
            .expect("issued device code")
            .to_owned();
        let user_code = body["user_code"]
            .as_str()
            .expect("issued user code")
            .to_owned();
        let stored = auth
            .store()
            .get_device_code_by_device_code(&device_code)
            .await?
            .expect("issued code is stored");
        let persisted_codes_match = json!({
            "deviceCode":stored.device_code == device_code,
            "userCode":stored.user_code == user_code,
        });
        if default_device_code {
            body["device_code"] = json!({
                "length":device_code.chars().count(),
                "asciiAlphanumeric":!device_code.is_empty() && device_code.chars().all(|value| value.is_ascii_alphanumeric()),
            });
        }
        assert_eq!(
            Observation {
                name: expected.name.clone(),
                configuration: expected.configuration.clone(),
                status: response.status,
                headers,
                body,
                persisted_codes_match,
                stored: StoredObservation {
                    client_id: stored.client_id.typed()?.clone(),
                    scope: stored.scope.typed()?.clone(),
                    status: stored.status.typed()?.clone(),
                    polling_interval: stored
                        .polling_interval
                        .typed()?
                        .expect("stored polling interval"),
                },
            },
            expected,
        );
    }
    Ok(())
}
