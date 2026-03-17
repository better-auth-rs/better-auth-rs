//! Field-level smoke tests for camelCase enforcement and representative type signatures.
#![allow(
    clippy::indexing_slicing,
    reason = "field-level compatibility tests use direct JSON indexing for concise response shape assertions"
)]

mod compat;

use compat::helpers::*;
use compat::shapes::{check_camel_case_fields, extract_type_signature};

/// All response fields must use camelCase (not snake_case) for frontend compatibility.
#[tokio::test]
async fn test_all_responses_use_camel_case() {
    let auth = create_test_auth().await;

    // Sign up a user to test all authenticated endpoints
    let (token, signup_body) =
        signup_user(&auth, "camel@example.com", "password123", "Camel User").await;

    // Collect all responses to check
    let test_cases: Vec<(&str, serde_json::Value)> =
        vec![("POST /sign-up/email", signup_body.clone())];

    // Endpoints that require auth
    let auth_endpoints: Vec<(&str, better_auth::prelude::AuthRequest)> = vec![
        ("GET /get-session", get_with_auth("/get-session", &token)),
        (
            "GET /list-sessions",
            get_with_auth("/list-sessions", &token),
        ),
        (
            "GET /list-accounts",
            get_with_auth("/list-accounts", &token),
        ),
    ];

    let mut all_violations = Vec::new();

    // Check pre-collected responses
    for (endpoint, body) in &test_cases {
        let violations = check_camel_case_fields(body, "");
        if !violations.is_empty() {
            all_violations.push(format!("{}: {:?}", endpoint, violations));
        }
    }

    // Check authenticated endpoint responses
    for (endpoint, req) in auth_endpoints {
        let (status, body) = send_request(&auth, req).await;
        if status == 200 {
            let violations = check_camel_case_fields(&body, "");
            if !violations.is_empty() {
                all_violations.push(format!("{}: {:?}", endpoint, violations));
            }
        }
    }

    // Sign in response
    let (_, signin_body) = signin_user(&auth, "camel@example.com", "password123").await;
    let violations = check_camel_case_fields(&signin_body, "");
    if !violations.is_empty() {
        all_violations.push(format!("POST /sign-in/email: {:?}", violations));
    }

    if !all_violations.is_empty() {
        eprintln!("\n=== camelCase Violations ===");
        for v in &all_violations {
            eprintln!("  {}", v);
        }
        eprintln!("===========================\n");
    }

    assert!(
        all_violations.is_empty(),
        "Found snake_case fields in responses. All field names must use camelCase for frontend compatibility.\n\
         Violations:\n{}",
        all_violations.join("\n")
    );
}

/// Generate and print representative response type signatures for review.
/// This is documentation-oriented smoke coverage, not the compatibility gate.
#[tokio::test]
async fn test_response_type_signatures() {
    let auth = create_test_auth().await;

    let (token, signup_body) =
        signup_user(&auth, "sig@example.com", "password123", "Sig User").await;
    let (_, signin_body) = signin_user(&auth, "sig@example.com", "password123").await;

    let (_, session_body) = send_request(&auth, get_with_auth("/get-session", &token)).await;
    let (_, sessions_body) = send_request(&auth, get_with_auth("/list-sessions", &token)).await;
    let (_, accounts_body) = send_request(&auth, get_with_auth("/list-accounts", &token)).await;
    let (_, ok_body) = send_request(&auth, get_request("/ok")).await;
    let (_, error_body) = send_request(&auth, get_request("/error")).await;

    eprintln!("\n=== Response Type Signatures ===\n");

    let endpoints: Vec<(&str, &serde_json::Value)> = vec![
        ("GET /ok", &ok_body),
        ("GET /error", &error_body),
        ("POST /sign-up/email", &signup_body),
        ("POST /sign-in/email", &signin_body),
        ("GET /get-session", &session_body),
        ("GET /list-sessions", &sessions_body),
        ("GET /list-accounts", &accounts_body),
    ];

    for (endpoint, body) in endpoints {
        let sig = extract_type_signature(body, 0);
        eprintln!("{}\n{}\n", endpoint, sig);
    }

    eprintln!("================================\n");
}
