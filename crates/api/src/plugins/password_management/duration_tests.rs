#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "The unit test compares dates with the captured upstream fixture."
)]

use super::PasswordManagementConfig;
use better_auth_core::AuthError;
use chrono::{Duration, Utc};

#[test]
fn reset_dates_match_pinned_millisecond_clock_and_fractional_lifetimes() {
    let fixture: std::collections::BTreeMap<String, serde_json::Value> = serde_json::from_str(
        include_str!("../../../../../tests/fixtures/duration-options-1.7.6.json"),
    )
    .unwrap();
    for (name, expected) in fixture {
        let configured = if name == "nan" {
            Some(f64::NAN)
        } else {
            expected
                .get("configured")
                .and_then(serde_json::Value::as_f64)
        };
        let config = PasswordManagementConfig {
            reset_password_token_expires_in: configured,
            ..Default::default()
        };
        let now = chrono::DateTime::from_timestamp_millis(expected["now"].as_i64().unwrap())
            .unwrap()
            + Duration::nanoseconds(999_999);
        assert_eq!(
            config
                .reset_token_expires_at(now)
                .unwrap()
                .timestamp_millis(),
            expected["expiresAt"].as_i64().unwrap(),
            "{name}"
        );
    }
    for seconds in [f64::INFINITY, f64::NEG_INFINITY, f64::MAX, -f64::MAX] {
        let config = PasswordManagementConfig {
            reset_password_token_expires_in: Some(seconds),
            ..Default::default()
        };
        assert!(matches!(
            config.reset_token_expires_at(Utc::now()),
            Err(AuthError::Config(message)) if message == "Reset token expiry is out of range"
        ));
    }
}
