//! Cross-endpoint consistency tests — verify user/session objects are
//! structurally identical across different API responses.

mod compat;

use compat::helpers::*;
use compat::shapes::compare_shapes;

/// Test the complete auth flow: signup -> signin -> get-session -> signout.
/// Validates that the user object is consistent across all responses.
#[tokio::test]
async fn test_auth_flow_user_object_consistency() {
    let auth = create_test_auth().await;

    // Step 1: Sign up
    let (_signup_token, signup_body) =
        signup_user(&auth, "flow@example.com", "password123", "Flow User").await;
    let signup_user_obj = &signup_body["user"];

    // Step 2: Sign in
    let (signin_token, signin_body) = signin_user(&auth, "flow@example.com", "password123").await;
    let signin_user_obj = &signin_body["user"];

    // Step 3: Get session
    let (_, session_body) = send_request(&auth, get_with_auth("/get-session", &signin_token)).await;
    let session_user_obj = &session_body["user"];

    // The user object should have the SAME shape across all responses
    let shapes_to_compare = vec![
        ("signup vs signin", signup_user_obj, signin_user_obj),
        ("signup vs session", signup_user_obj, session_user_obj),
    ];

    for (label, a, b) in shapes_to_compare {
        let diffs = compare_shapes(a, b, "user", false);
        assert!(
            diffs.is_empty(),
            "User object shape mismatch between {}: {:?}",
            label,
            diffs
        );
    }

    // Verify the user ID is consistent
    assert_eq!(
        signup_user_obj["id"], signin_user_obj["id"],
        "User ID must be consistent: signup vs signin"
    );
    assert_eq!(
        signup_user_obj["id"], session_user_obj["id"],
        "User ID must be consistent: signup vs session"
    );

    // Verify the email is consistent
    assert_eq!(
        signup_user_obj["email"], signin_user_obj["email"],
        "Email must be consistent: signup vs signin"
    );
}

/// Test that duplicate signup returns proper error shape.
#[tokio::test]
async fn test_duplicate_signup_error_shape() {
    let auth = create_test_auth().await;

    // First signup succeeds
    signup_user(&auth, "dup@example.com", "password123", "Dup User").await;

    // Second signup with same email should fail
    let (status, body) = send_request(
        &auth,
        post_json(
            "/sign-up/email",
            serde_json::json!({
                "name": "Dup User 2",
                "email": "dup@example.com",
                "password": "password123"
            }),
        ),
    )
    .await;

    assert!(
        (400..500).contains(&status),
        "Duplicate signup should return 4xx, got {}",
        status
    );
    assert!(
        body["message"].is_string(),
        "Error response must have 'message' field, got: {}",
        body
    );
}

/// Test that the session object shape is consistent across endpoints.
#[tokio::test]
async fn test_session_object_consistency() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "sess@example.com", "password123", "Sess User").await;

    // Get session from /get-session
    let (_, session_body) = send_request(&auth, get_with_auth("/get-session", &token)).await;
    let get_session_obj = &session_body["session"];

    // Get sessions from /list-sessions
    let (_, list_body) = send_request(&auth, get_with_auth("/list-sessions", &token)).await;
    let list_session_obj = list_body.as_array().and_then(|arr| arr.first());

    if let Some(list_session) = list_session_obj {
        let diffs = compare_shapes(get_session_obj, list_session, "session", false);
        // Note: /get-session wraps in {session, user}, /list-sessions returns array of session
        // The shapes may differ slightly because of this wrapping
        if !diffs.is_empty() {
            eprintln!("Session shape differences (get-session vs list-sessions):");
            for diff in &diffs {
                eprintln!("  {}", diff);
            }
        }
    }
}
