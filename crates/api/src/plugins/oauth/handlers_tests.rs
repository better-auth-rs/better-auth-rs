use super::*;
use crate::plugins::test_helpers;

// Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck respects ctx.context.skipOriginCheck.
#[tokio::test]
async fn validate_redirect_target_respects_disable_origin_check() {
    let config = test_helpers::create_test_config().disable_origin_check(true);
    let ctx = test_helpers::create_test_context_with_config(config).await;

    assert!(
        validate_redirect_target("https://evil.com/phish", &ctx, "Invalid callbackURL").is_ok()
    );
}

// Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck rejects untrusted origins by default.
#[tokio::test]
async fn validate_redirect_target_rejects_untrusted_by_default() {
    let ctx = test_helpers::create_test_context().await;

    assert!(
        validate_redirect_target("https://evil.com/phish", &ctx, "Invalid callbackURL").is_err()
    );
}

// Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck allows relative paths.
#[tokio::test]
async fn validate_redirect_target_allows_relative() {
    let ctx = test_helpers::create_test_context().await;

    assert!(validate_redirect_target("/dashboard", &ctx, "Invalid callbackURL").is_ok());
}
