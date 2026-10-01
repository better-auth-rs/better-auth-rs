#![cfg(feature = "seaorm2")]
#![allow(
    clippy::panic_in_result_fn,
    reason = "Tests propagate setup errors and assert observable middleware behavior"
)]

use std::time::Duration;

use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::DeviceAuthorizationPlugin;
use better_auth::prelude::{AuthRequest, HttpMethod};
use better_auth::{AuthConfig, BetterAuth};
use better_auth_seaorm::{Database, SeaOrmStore};

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

#[tokio::test]
async fn device_limits_respect_base_paths_overrides_and_disable()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (RateLimitConfig::new().enabled(true), 5),
        (
            RateLimitConfig::new()
                .enabled(true)
                .endpoint("/device", Duration::from_secs(60), 2),
            2,
        ),
        (
            RateLimitConfig::new().enabled(true).endpoint(
                "/custom/auth/device",
                Duration::from_secs(60),
                3,
            ),
            5,
        ),
        (RateLimitConfig::new().enabled(false), 6),
    ];
    for (case, (rate_limit, allowed)) in cases.into_iter().enumerate() {
        let config = AuthConfig::new("device-limit-tests-secret-at-least-32-characters")
            .base_url("http://localhost:3000")
            .base_path("/custom/auth");
        let database = Database::connect("sqlite::memory:").await?;
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await?;
        let auth = BetterAuth::<TestSchema>::new(config.clone())
            .store(SeaOrmStore::<TestSchema>::new(config, database))
            .plugin(DeviceAuthorizationPlugin::new())
            .rate_limit(rate_limit)
            .build()
            .await?;
        for index in 0..6 {
            let mut request = AuthRequest::new(HttpMethod::Get, "/custom/auth/device");
            let _ = request
                .headers
                .insert("x-forwarded-for".into(), format!("192.0.2.{}", case + 1));
            let _ = request
                .query
                .get_or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
                .unwrap()
                .insert("user_code".into(), serde_json::Value::from("UNKNOWN"));
            let response = auth.handle_request(request).await?;
            assert_eq!(response.status, if index < allowed { 400 } else { 429 });
        }
    }
    Ok(())
}
