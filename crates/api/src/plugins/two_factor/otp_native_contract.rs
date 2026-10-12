#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Pinned OTP contracts must fail on invalid fixtures, callback order, or persistence observations."
)]

use super::*;
use crate::plugins::test_helpers::verification_consumer_native::{
    Harness, NOW, ReplayFailures, SECRET, assert_replay, date,
};
use better_auth_core::{
    AuthPlugin, NativeRequest,
    store::{StatelessSchema, schema::EntityRole},
};
use serde_json::{Value as Json, json};

const CHALLENGE: &str = "2fa-otp-native";

async fn capture(scenario: &Json) -> AuthResult<Json> {
    let harness = Harness::new(scenario, &format!("2fa-otp-{CHALLENGE}"))?.with_model_rows(
        "twoFactor",
        EntityRole::TwoFactor,
        vec![FieldMap::from([
            ("id".into(), "factor-row".into()),
            ("secret".into(), "native-factor-secret".into()),
            ("backupCodes".into(), "[]".into()),
            ("userId".into(), "owner".into()),
            ("verified".into(), true.into()),
            ("failedVerificationCount".into(), 2.into()),
            ("lockedUntil".into(), FieldValue::Null),
        ])],
    );
    for (id, identifier, value) in [
        ("challenge-row", CHALLENGE.to_owned(), "owner"),
        ("attempts-row", format!("2fa-attempts-{CHALLENGE}"), "0"),
    ] {
        let row = FieldValue::from(FieldMap::from([
            ("id".into(), id.into()),
            ("identifier".into(), identifier.clone().into()),
            ("value".into(), value.into()),
            ("expiresAt".into(), date((NOW + 60_000) as f64)),
            ("createdAt".into(), date(NOW as f64)),
            ("updatedAt".into(), date(NOW as f64)),
        ]));
        harness.cache.insert(
            &format!("verification:{identifier}"),
            row.stringify()?.unwrap().into(),
        )?;
    }
    let plugin = TwoFactorPlugin::with_config(TwoFactorConfig {
        otp_allowed_attempts: 3,
        otp_storage: TwoFactorOtpStorage::Plain,
        ..Default::default()
    });
    let (context, inner) = harness.context(&[&plugin]).await?;
    let route = <TwoFactorPlugin as AuthPlugin<StatelessSchema>>::routes(&plugin)
        .into_iter()
        .find(|route| route.path == "/two-factor/verify-otp")
        .unwrap();
    let cookie_name = related_cookie_name(&context.config, TWO_FACTOR_COOKIE_SUFFIX);
    let signed = sign_cookie_value(SECRET, CHALLENGE)?;
    let headers =
        std::collections::HashMap::from([("cookie".into(), format!("{cookie_name}={signed}"))]);
    let before = harness.state(&inner)?;
    harness.activate();
    let result = context
        .dispatch_native(
            NativeRequest {
                headers: Some(&headers),
                ..Default::default()
            },
            route,
            Some(json!({"code":"wrong"})),
            None,
            |request, context| async move { plugin.handle_verify_otp(&request, &context).await },
        )
        .await
        .and_then(|response| response.body.field_value());
    harness.finish(before, harness.outcome(result)?, &inner)
}

async fn replay(contract: &str, expected_cases: usize) -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("../../tests/fixtures/{contract}-1.7.6.json")),
        )
        .unwrap(),
    )?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["contract"], contract);
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), expected_cases);
    let mut failures = ReplayFailures::default();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let actual = capture(&case["scenario"]).await?;
        failures.record(name, || assert_replay(&actual, &case["runtime"], name));
    }
    failures.finish();
    Ok(())
}

#[tokio::test]
async fn otp_methods_match_upstream_conversion_errors_and_failure_persistence() -> AuthResult<()> {
    replay("two-factor-otp-native", 17).await
}

#[tokio::test]
async fn otp_decimal_counter_matches_upstream_rounding_and_radix_boundaries() -> AuthResult<()> {
    replay("two-factor-otp-counter", 4).await
}
