use super::*;
use better_auth::plugins::OAuthPlugin;
use better_auth::plugins::email_verification::EmailVerificationConfig;
use better_auth::plugins::oauth::OAuthProvider;
use std::sync::atomic::{AtomicUsize, Ordering};

struct VerificationSender(Arc<AtomicUsize>);

#[async_trait]
impl core::email::SendVerificationEmail for VerificationSender {
    async fn send(&self, _: &better_auth_core::FieldValue, _: &str, _: &str) -> AuthResult<()> {
        let _ = self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn verification(name: &str, calls: &Arc<AtomicUsize>) -> AuthResult<EmailVerificationPlugin> {
    let config = match name {
        "pluginOmitted" => EmailVerificationConfig::default(),
        "pluginDefaults" | "pluginValues" => EmailVerificationConfig {
            verification_token_expiry: Some(chrono::Duration::seconds(
                if name == "pluginDefaults" { 3600 } else { 90 },
            )),
            ..Default::default()
        },
        "callbacks" => {
            let before = calls.clone();
            let after = calls.clone();
            EmailVerificationConfig {
                send_on_sign_up: Some(true),
                send_on_sign_in: true,
                auto_sign_in_after_verification: true,
                send_verification_email: Some(Arc::new(VerificationSender(calls.clone()))),
                before_email_verification: Some(Arc::new(move |_| {
                    let calls = before.clone();
                    Box::pin(async move {
                        let _ = calls.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                })),
                after_email_verification: Some(Arc::new(move |_| {
                    let calls = after.clone();
                    Box::pin(async move {
                        let _ = calls.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                })),
                ..Default::default()
            }
        }
        _ => return Err(AuthError::internal("unknown verification telemetry case")),
    };
    Ok(EmailVerificationPlugin::with_config(config))
}

#[tokio::test]
async fn private_verification_metadata_matches_upstream_without_invoking_callbacks()
-> AuthResult<()> {
    for oauth in [false, true] {
        for name in [
            "pluginOmitted",
            "pluginDefaults",
            "pluginValues",
            "callbacks",
        ] {
            let expected = oracle(name)?
                .get("emailVerification")
                .cloned()
                .ok_or_else(|| AuthError::internal("oracle has no verification metadata"))?;
            let calls = Arc::new(AtomicUsize::new(0));
            let verification = Arc::new(verification(name, &calls)?);
            let (config, reports) = configuration();
            let builder = BetterAuth::stateless(config).plugin(InitOrder(reports.clone()));
            let builder = if oauth {
                builder.plugin(
                    OAuthPlugin::new()
                        .add_provider("github", OAuthProvider::github("client", "secret"))
                        .with_email_verification(verification),
                )
            } else {
                builder.plugin(EmailPasswordPlugin::new().with_email_verification(verification))
            };
            let _auth = builder.build().await?;
            assert_eq!(
                reports.config()?.get("emailVerification"),
                Some(&expected),
                "{name}, oauth={oauth}"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "metadata must not invoke verification callbacks: {name}, oauth={oauth}"
            );
        }
    }
    Ok(())
}
