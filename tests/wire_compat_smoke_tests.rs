#![allow(
    clippy::indexing_slicing,
    reason = "wire smoke tests use direct JSON indexing for concise transport assertions"
)]

mod compat;

use compat::dual_server::*;
use compat::helpers::*;

#[tokio::test]
async fn wire_get_session_no_auth() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let rust = rust_send(&auth, get_request("/get-session")).await;
    let mut ref_client = RefClient::new();
    let reference = ref_client
        .get_full("/get-session")
        .await
        .unwrap_or_else(ref_error_response);

    assert_report_pass(compare_full(
        "GET /get-session (no auth transport)",
        &rust,
        &reference,
    ));
}

#[tokio::test]
async fn wire_signin_sets_session_cookie() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let email = unique_email("wire_signin");
    let signup_body = serde_json::json!({
        "name": "Wire Signin User",
        "email": email,
        "password": "password123",
    });
    let _ = rust_send(&auth, post_json("/sign-up/email", signup_body.clone())).await;
    let _ = ref_client.post_full("/sign-up/email", &signup_body).await;

    let body = serde_json::json!({
        "email": email,
        "password": "password123",
    });
    let rust = rust_send(&auth, post_json("/sign-in/email", body.clone())).await;
    let reference = ref_client
        .post_full("/sign-in/email", &body)
        .await
        .unwrap_or_else(ref_error_response);

    assert_report_pass(compare_full(
        "POST /sign-in/email (cookie transport)",
        &rust,
        &reference,
    ));
}

#[tokio::test]
async fn wire_signout_clears_session_cookie() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let (email, rust_token, _rust_user_id) =
        signup_on_both(&auth, &mut ref_client, "wire_signout").await;

    let signin_body = serde_json::json!({
        "email": email,
        "password": "password123",
    });
    let _ = rust_send(&auth, post_json("/sign-in/email", signin_body.clone())).await;
    let _ = ref_client
        .post_full("/sign-in/email", &signin_body)
        .await
        .unwrap_or_else(ref_error_response);

    let rust = rust_send(&auth, post_with_auth("/sign-out", &rust_token)).await;
    let reference = ref_client
        .post_full("/sign-out", &serde_json::json!({}))
        .await
        .unwrap_or_else(ref_error_response);

    assert_report_pass(compare_full(
        "POST /sign-out (cookie clear)",
        &rust,
        &reference,
    ));
}

#[tokio::test]
async fn wire_is_username_available_not_taken() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let body = serde_json::json!({ "username": "fresh_user_xyz" });

    let rust = rust_send(&auth, post_json("/is-username-available", body.clone())).await;
    let reference = ref_client
        .post_full("/is-username-available", &body)
        .await
        .unwrap_or_else(ref_error_response);

    assert_report_pass(compare_full(
        "POST /is-username-available (not taken)",
        &rust,
        &reference,
    ));
}

#[tokio::test]
async fn wire_is_username_available_taken() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();

    // Sign up a user with a username on both servers
    let email = unique_email("wire_uname_taken");
    let signup_body = serde_json::json!({
        "name": "Username User",
        "email": email,
        "password": "password123",
        "username": "taken_user",
    });
    let _ = rust_send(&auth, post_json("/sign-up/email", signup_body.clone())).await;
    let _ = ref_client.post_full("/sign-up/email", &signup_body).await;

    let body = serde_json::json!({ "username": "taken_user" });
    let rust = rust_send(&auth, post_json("/is-username-available", body.clone())).await;
    let reference = ref_client
        .post_full("/is-username-available", &body)
        .await
        .unwrap_or_else(ref_error_response);

    assert_report_pass(compare_full(
        "POST /is-username-available (taken)",
        &rust,
        &reference,
    ));
}

#[tokio::test]
async fn wire_is_username_available_too_short() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let body = serde_json::json!({ "username": "ab" });

    let rust = rust_send(&auth, post_json("/is-username-available", body.clone())).await;
    let reference = ref_client
        .post_full("/is-username-available", &body)
        .await
        .unwrap_or_else(ref_error_response);

    assert_report_pass(compare_full(
        "POST /is-username-available (too short)",
        &rust,
        &reference,
    ));
}

#[tokio::test]
async fn wire_list_sessions_no_auth() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let rust = rust_send(&auth, get_request("/list-sessions")).await;
    let mut ref_client = RefClient::new();
    let reference = ref_client
        .get_full("/list-sessions")
        .await
        .unwrap_or_else(ref_error_response);

    assert_report_pass(compare_full(
        "GET /list-sessions (no auth transport)",
        &rust,
        &reference,
    ));
}
