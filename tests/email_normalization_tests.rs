#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "email normalization tests intentionally use panic-on-failure assertions and direct JSON indexing for concise behavior checks"
)]

mod compat;

use better_auth::prelude::{CreateUser, UpdateUser};
use compat::helpers::*;
use serde_json::json;

#[tokio::test]
async fn store_create_user_normalizes_email_and_lookup_matches_any_case() {
    let harness = TestHarness::minimal().await;
    let auth = harness.auth();

    let mut create_user = CreateUser::new().with_name("Mixed Case");
    create_user.email = Some("Mixed.Case@Test.com".to_string());

    let user = auth.database().create_user(create_user).await.unwrap();

    assert_eq!(user.email.as_deref(), Some("mixed.case@test.com"));

    let lower = auth
        .database()
        .get_user_by_email("mixed.case@test.com")
        .await
        .unwrap()
        .expect("lowercase lookup should find the user");
    let upper = auth
        .database()
        .get_user_by_email("MIXED.CASE@TEST.COM")
        .await
        .unwrap()
        .expect("uppercase lookup should find the user");

    assert_eq!(lower.id, user.id);
    assert_eq!(upper.id, user.id);
}

#[tokio::test]
async fn store_update_user_normalizes_email_before_persisting() {
    let harness = TestHarness::minimal().await;
    let auth = harness.auth();

    let mut create_user = CreateUser::new().with_name("Original");
    create_user.email = Some("original@test.com".to_string());

    let user = auth.database().create_user(create_user).await.unwrap();

    let updated = auth
        .database()
        .update_user(
            &user.id,
            UpdateUser {
                email: Some("Updated.Case@Test.com".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.email.as_deref(), Some("updated.case@test.com"));

    let fetched = auth
        .database()
        .get_user_by_email("UPDATED.CASE@TEST.COM")
        .await
        .unwrap()
        .expect("normalized lookup should find the updated user");
    assert_eq!(fetched.id, user.id);
}

#[tokio::test]
async fn signup_mixed_case_email_persists_lowercase_and_signin_accepts_lowercase() {
    let harness = TestHarness::minimal().await;
    let auth = harness.auth();

    let (_signup_token, signup_body) =
        signup_user(auth, "Mixed.Signup@Test.com", "password123", "Mixed Signup").await;
    assert_eq!(signup_body["user"]["email"], "mixed.signup@test.com");

    let (_signin_token, signin_body) =
        signin_user(auth, "mixed.signup@test.com", "password123").await;
    assert_eq!(signin_body["user"]["email"], "mixed.signup@test.com");
}

#[tokio::test]
async fn signup_rejects_duplicate_email_with_different_case() {
    let harness = TestHarness::minimal().await;
    let auth = harness.auth();

    let _ = signup_user(auth, "Duplicate.Case@Test.com", "password123", "Duplicate").await;

    let (status, body) = send_request(
        auth,
        post_json(
            "/sign-up/email",
            json!({
                "email": "duplicate.case@test.com",
                "password": "password123",
                "name": "Duplicate Lowercase"
            }),
        ),
    )
    .await;

    assert_eq!(status, 422);
    assert_eq!(body["message"], "User already exists. Use another email.");
}

#[tokio::test]
async fn request_password_reset_finds_user_from_lowercase_email() {
    let harness = TestHarness::minimal().await;
    let auth = harness.auth();

    let _ = signup_user(auth, "Reset.Case@Test.com", "password123", "Reset Case").await;

    let (status, body) = send_request(
        auth,
        post_json(
            "/request-password-reset",
            json!({
                "email": "reset.case@test.com",
                "redirectTo": "http://localhost:3000/reset"
            }),
        ),
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(body["status"], true);
    assert!(
        take_reset_password_token("reset.case@test.com").is_some(),
        "password reset token should be captured for the normalized email"
    );
}
