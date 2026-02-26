//! Property-based tests using `proptest` for input validation.
//!
//! These tests generate random inputs to exercise boundary conditions in
//! password validation, email handling, token format checks, and config
//! validation — covering classes of inputs that hand-written tests miss.

mod compat;

use compat::helpers::*;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Password validation properties
// ---------------------------------------------------------------------------

/// Passwords shorter than `password_min_length` (8) must be rejected (400).
proptest! {
    #[test]
    fn short_passwords_are_rejected(password in "[a-zA-Z0-9]{1,7}") {
        // The test auth uses password_min_length = 8
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let auth = create_test_auth().await;
            let (status, body) = send_request(
                &auth,
                post_json(
                    "/sign-up/email",
                    serde_json::json!({
                        "name": "Prop User",
                        "email": "proptest_short@example.com",
                        "password": password
                    }),
                ),
            )
            .await;
            prop_assert_eq!(
                status, 400,
                "Password '{}' (len={}) should be rejected, got status {} body: {}",
                password, password.len(), status, body
            );
            Ok(())
        })?;
    }
}

/// Passwords at or above `password_min_length` (8) should not trigger a
/// "too short" error.  They may still fail for other reasons (duplicate
/// email, etc.) but they must NOT return the min-length error message.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]
    #[test]
    fn valid_length_passwords_not_rejected_for_length(
        password in "[a-zA-Z0-9!@#$%]{8,64}"
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let auth = create_test_auth().await;
            // Use a unique email per test case to avoid duplicate-email errors
            let email = format!("proplen_{}@example.com", rand_suffix());
            let (status, body) = send_request(
                &auth,
                post_json(
                    "/sign-up/email",
                    serde_json::json!({
                        "name": "Prop Len User",
                        "email": email,
                        "password": password
                    }),
                ),
            )
            .await;
            // Should succeed (200) or fail for a reason OTHER than password length
            if status == 400 {
                let msg = body["message"].as_str().unwrap_or("");
                prop_assert!(
                    !msg.contains("Password must be at least"),
                    "Password '{}' (len={}) wrongly rejected for length: {}",
                    password, password.len(), msg
                );
            }
            Ok(())
        })?;
    }
}

// ---------------------------------------------------------------------------
// Email validation properties
// ---------------------------------------------------------------------------

/// Clearly invalid emails must not produce a 200 on sign-up.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]
    #[test]
    fn invalid_emails_are_rejected(
        local in "[a-z]{1,10}",
    ) {
        // Emails without '@' or domain are invalid
        let email = local.clone(); // no @ sign
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let auth = create_test_auth().await;
            let (status, _body) = send_request(
                &auth,
                post_json(
                    "/sign-up/email",
                    serde_json::json!({
                        "name": "Invalid Email",
                        "email": email,
                        "password": "password123"
                    }),
                ),
            )
            .await;
            prop_assert!(
                status >= 400,
                "Email '{}' should be rejected, got status {}",
                email, status
            );
            Ok(())
        })?;
    }
}

// ---------------------------------------------------------------------------
// Token format validation properties
// ---------------------------------------------------------------------------

/// `validate_token_format` accepts tokens that start with "session_" and
/// are longer than 40 characters.
proptest! {
    #[test]
    fn valid_token_format_accepted(suffix in "[a-zA-Z0-9]{34,80}") {
        let token = format!("session_{}", suffix);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let auth = create_test_auth().await;
            let session_mgr = auth.session_manager();
            prop_assert!(
                session_mgr.validate_token_format(&token),
                "Token '{}' (len={}) should be valid",
                token, token.len()
            );
            Ok(())
        })?;
    }
}

/// Tokens that are too short or have the wrong prefix must be rejected.
proptest! {
    #[test]
    fn invalid_token_format_rejected(token in "[a-zA-Z0-9_]{0,39}") {
        // Tokens shorter than 41 chars total should be rejected
        // (prefix "session_" = 8 chars, so suffix must be > 32 chars)
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let auth = create_test_auth().await;
            let session_mgr = auth.session_manager();
            if !token.starts_with("session_") || token.len() <= 40 {
                prop_assert!(
                    !session_mgr.validate_token_format(&token),
                    "Token '{}' (len={}) should be invalid",
                    token, token.len()
                );
            }
            Ok(())
        })?;
    }
}

// ---------------------------------------------------------------------------
// Config validation properties
// ---------------------------------------------------------------------------

/// Secret keys shorter than 32 characters must fail validation.
proptest! {
    #[test]
    fn short_secrets_fail_validation(secret in "[a-zA-Z0-9]{1,31}") {
        let config = better_auth::AuthConfig::new(&secret);
        prop_assert!(
            config.validate().is_err(),
            "Secret of length {} should fail validation",
            secret.len()
        );
    }
}

/// Secret keys of 32+ characters must pass validation.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]
    #[test]
    fn long_secrets_pass_validation(secret in "[a-zA-Z0-9]{32,128}") {
        let config = better_auth::AuthConfig::new(&secret);
        prop_assert!(
            config.validate().is_ok(),
            "Secret of length {} should pass validation",
            secret.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a short random suffix for unique emails in property tests.
fn rand_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!("{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}
