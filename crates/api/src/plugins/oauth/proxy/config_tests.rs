use super::{OAuthProxyConfig, OAuthProxyPlugin};
use crate::plugins::test_helpers;
use better_auth_core::{AuthInitContext, AuthPlugin};

#[tokio::test]
async fn max_age_initialization_accepts_all_numeric_values() {
    let ctx = test_helpers::create_test_context().await;
    for max_age in [
        60.125,
        -60.125,
        0.0,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ] {
        for plugin in [
            OAuthProxyPlugin::new().max_age(max_age),
            OAuthProxyPlugin::with_config(OAuthProxyConfig {
                max_age,
                ..Default::default()
            }),
        ] {
            let mut init = AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
            let result = plugin.on_init(&mut init).await;
            assert!(result.is_ok(), "{max_age}: {result:?}");
        }
    }
}

#[test]
fn profile_age_matches_all_captured_millisecond_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/oauth-proxy-max-age-1.7.6.json"
    )))?;
    let now = fixture
        .get("now")
        .and_then(serde_json::Value::as_i64)
        .ok_or("Missing clock")?;
    let cases = fixture
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or("Missing cases")?;
    assert_eq!(cases.len(), 16);
    for case in cases {
        let limit = case.get("maxAge").ok_or("Missing maxAge")?;
        let max_age = if let Some(number) = limit.as_f64() {
            number
        } else {
            match limit.get("value").and_then(serde_json::Value::as_str) {
                Some("NaN") => f64::NAN,
                Some("Infinity") => f64::INFINITY,
                Some("-Infinity") => f64::NEG_INFINITY,
                _ => return Err("Unknown captured maxAge".into()),
            }
        };
        let timestamp = case
            .get("payload")
            .and_then(|value| value.get("timestamp"))
            .and_then(serde_json::Value::as_f64)
            .ok_or("Missing profile timestamp")?;
        let accepted = case
            .get("accepted")
            .and_then(serde_json::Value::as_bool)
            .ok_or("Missing acceptance")?;
        assert_eq!(
            !OAuthProxyPlugin::new()
                .max_age(max_age)
                .profile_expired(timestamp, now),
            accepted,
            "{case}"
        );
    }
    Ok(())
}
