use super::*;

#[tokio::test]
async fn plugin_duration_options_match_real_initialization_without_running_callbacks()
-> AuthResult<()> {
    let fixture: std::collections::BTreeMap<String, Value> =
        serde_json::from_str(include_str!("../fixtures/duration-options-1.7.6.json"))?;
    for (name, expected) in fixture {
        let seconds = if name == "nan" {
            Some(f64::NAN)
        } else {
            expected.get("configured").and_then(Value::as_f64)
        };
        let (config, reports) = configuration();
        let reset = PasswordManagementPlugin::with_config(
            better_auth::plugins::password_management::PasswordManagementConfig {
                reset_password_token_expires_in: seconds,
                send_reset_password: Some(Arc::new(Callbacks)),
                ..Default::default()
            },
        );
        let mut verification = EmailVerificationPlugin::new();
        if let Some(seconds) = seconds.filter(|seconds| seconds.is_finite()) {
            verification = verification
                .verification_token_expiry(chrono::Duration::nanoseconds((seconds * 1e9) as i64));
        }
        let _auth = BetterAuth::stateless(config)
            .plugin(EmailPasswordPlugin::new())
            .plugin(reset)
            .plugin(verification)
            .build()
            .await?;
        let actual = reports.config()?;
        assert_eq!(
            actual.get("emailAndPassword"),
            expected.get("emailAndPassword"),
            "{name}"
        );
        if name != "nan" {
            assert_eq!(
                actual.get("emailVerification"),
                expected.get("emailVerification"),
                "{name}"
            );
        }
    }
    Ok(())
}
