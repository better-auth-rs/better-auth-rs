//! Compatibility tests for phase 10 admin stateful flows.
//!
//! Focused on the shared banned-user session gate and admin stateful semantics
//! that cross route boundaries.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "compat contract tests use direct assertions and JSON indexing for endpoint checks"
)]

mod compat;

use better_auth::prelude::{AuthUser, UpdateUser};
use chrono::{Duration, Utc};
use compat::helpers::*;
use serde_json::json;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn setup_admin(auth: &better_auth::BetterAuth<TestSchema>) -> String {
    let (token, _) = signup_user(auth, "admin-stateful@test.com", "password123", "Admin").await;

    let user = auth
        .store()
        .get_user_by_email("admin-stateful@test.com")
        .await
        .unwrap()
        .unwrap();

    let _ = auth
        .store()
        .update_user(
            &user.id(),
            UpdateUser {
                role: Some("admin".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    token
}

#[tokio::test]
async fn test_banned_user_sign_in_returns_banned_user_code() {
    let auth = create_test_auth().await;
    let admin_token = setup_admin(&auth).await;

    let (_, signup_json) = signup_user(
        &auth,
        "banned-stateful@test.com",
        "password123",
        "Banned User",
    )
    .await;
    let user_id = signup_json["user"]["id"].as_str().unwrap();

    let ban_req = post_json_with_auth(
        "/admin/ban-user",
        json!({
            "userId": user_id,
            "banReason": "stateful test",
        }),
        &admin_token,
    );
    let (ban_status, _ban_json) = send_request(&auth, ban_req).await;
    assert_eq!(ban_status, 200);

    let sign_in_req = post_json(
        "/sign-in/email",
        json!({
            "email": "banned-stateful@test.com",
            "password": "password123",
        }),
    );
    let (status, body) = send_request(&auth, sign_in_req).await;

    assert_eq!(status, 403);
    assert_eq!(body["code"], "BANNED_USER");
}

#[tokio::test]
async fn test_expired_ban_is_cleared_on_sign_in() {
    let auth = create_test_auth().await;
    let (_, signup_json) = signup_user(
        &auth,
        "expired-ban@test.com",
        "password123",
        "Expired Ban User",
    )
    .await;
    let user_id = signup_json["user"]["id"].as_str().unwrap().to_string();

    let _ = auth
        .store()
        .update_user(
            &user_id,
            UpdateUser {
                banned: Some(true),
                ban_reason: Some("expired".to_string()),
                ban_expires: Some(Utc::now() - Duration::minutes(1)),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let sign_in_req = post_json(
        "/sign-in/email",
        json!({
            "email": "expired-ban@test.com",
            "password": "password123",
        }),
    );
    let (status, body) = send_request(&auth, sign_in_req).await;
    assert_eq!(status, 200, "expired ban sign-in should succeed: {}", body);
    assert!(body["token"].is_string());

    let user = auth
        .store()
        .get_user_by_id(&user_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!user.banned());
    assert!(user.ban_reason().is_none());
    assert!(user.ban_expires().is_none());
}
