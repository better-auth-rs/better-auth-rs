use super::{OAuthProxyConfig, OAuthProxyPlugin};
use crate::plugins::test_helpers;
use better_auth_core::{AuthError, AuthInitContext, AuthPlugin};

#[tokio::test]
async fn max_age_initialization_requires_finite_values() {
    let ctx = test_helpers::create_test_context().await;
    for (max_age, valid) in [
        (60.125, true),
        (-60.125, true),
        (0.0, true),
        (f64::NAN, false),
        (f64::INFINITY, false),
        (f64::NEG_INFINITY, false),
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
            if valid {
                assert!(result.is_ok(), "{max_age}: {result:?}");
            } else {
                assert!(matches!(result, Err(AuthError::Config(_))));
            }
        }
    }
}
