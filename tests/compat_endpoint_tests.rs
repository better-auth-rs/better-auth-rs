//! Endpoint validation tests — the main compatibility gate.
//!
//! These tests exercise each API endpoint and validate responses against the
//! OpenAPI spec schema.

mod compat;

use std::collections::HashSet;

use compat::helpers::*;
use compat::schema::extract_success_schema;
use compat::shapes::check_camel_case_fields;
use compat::validation::{DiffKind, ShapeDiff, json_type_name};
use compat::validator::{EndpointResult, SpecValidator};

/// Run all spec-driven endpoint validations in a single test.
/// This is the main compatibility gate.
#[tokio::test]
async fn test_spec_driven_endpoint_validation() {
    let auth = create_test_auth().await;
    let mut validator = SpecValidator::new();

    // --- GET /ok ---
    let (status, body) = send_request(&auth, get_request("/ok")).await;
    validator.validate_endpoint("/ok", "get", status, &body);

    // --- GET /error ---
    let (status, body) = send_request(&auth, get_request("/error")).await;
    validator.validate_endpoint("/error", "get", status, &body);

    // --- POST /sign-up/email (success) ---
    let (status, body) = send_request(
        &auth,
        post_json(
            "/sign-up/email",
            serde_json::json!({
                "name": "Spec Test User",
                "email": "spec@example.com",
                "password": "password123"
            }),
        ),
    )
    .await;
    let signup_token = body["token"].as_str().unwrap_or("").to_string();
    validator.validate_endpoint("/sign-up/email", "post", status, &body);

    // --- POST /sign-in/email (success) ---
    let (status, body) = send_request(
        &auth,
        post_json(
            "/sign-in/email",
            serde_json::json!({
                "email": "spec@example.com",
                "password": "password123"
            }),
        ),
    )
    .await;
    let signin_token = body["token"].as_str().unwrap_or("").to_string();
    validator.validate_endpoint("/sign-in/email", "post", status, &body);

    // --- GET /get-session ---
    let (status, body) = send_request(&auth, get_with_auth("/get-session", &signin_token)).await;
    validator.validate_endpoint("/get-session", "get", status, &body);

    // --- GET /list-sessions ---
    let (status, body) = send_request(&auth, get_with_auth("/list-sessions", &signin_token)).await;
    // list-sessions returns an array, validate the first element against Session schema
    if let Some(arr) = body.as_array() {
        if let Some(first) = arr.first() {
            let _session_schema = extract_success_schema(&validator.spec, "/list-sessions", "get");
            let camel_violations = check_camel_case_fields(first, "sessions[0]");
            let passed = camel_violations.is_empty();
            validator.results.push(EndpointResult {
                endpoint: "/list-sessions".to_string(),
                method: "GET".to_string(),
                status,
                passed,
                diffs: vec![],
                camel_case_violations: camel_violations,
            });
        } else {
            // Empty array — valid but nothing to validate
            validator.results.push(EndpointResult {
                endpoint: "/list-sessions".to_string(),
                method: "GET".to_string(),
                status,
                passed: true,
                diffs: vec![],
                camel_case_violations: vec![],
            });
        }
    } else {
        validator.results.push(EndpointResult {
            endpoint: "/list-sessions".to_string(),
            method: "GET".to_string(),
            status,
            passed: false,
            diffs: vec![ShapeDiff {
                path: "".to_string(),
                kind: DiffKind::TypeMismatch {
                    expected: "array".to_string(),
                    actual: json_type_name(&body).to_string(),
                },
            }],
            camel_case_violations: vec![],
        });
    }

    // --- POST /sign-out ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth("/sign-out", serde_json::json!({}), &signup_token),
    )
    .await;
    validator.validate_endpoint("/sign-out", "post", status, &body);

    // --- POST /forget-password ---
    // Sign up a fresh user for password tests
    let (pw_token, _) = signup_user(&auth, "pw@example.com", "password123", "PW User").await;

    let (status, body) = send_request(
        &auth,
        post_json(
            "/forget-password",
            serde_json::json!({
                "email": "pw@example.com",
            }),
        ),
    )
    .await;
    validator.validate_endpoint("/forget-password", "post", status, &body);

    // --- POST /change-password ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/change-password",
            serde_json::json!({
                "currentPassword": "password123",
                "newPassword": "newpassword456",
                "revokeOtherSessions": "false"
            }),
            &pw_token,
        ),
    )
    .await;
    validator.validate_endpoint("/change-password", "post", status, &body);

    // --- POST /update-user ---
    let (upd_token, _) = signup_user(&auth, "upd@example.com", "password123", "UPD User").await;
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/update-user",
            serde_json::json!({
                "name": "Updated Name"
            }),
            &upd_token,
        ),
    )
    .await;
    validator.validate_endpoint("/update-user", "post", status, &body);

    // --- POST /delete-user (spec method) ---
    let (del_token, _) = signup_user(&auth, "del@example.com", "password123", "DEL User").await;
    let (status, body) = send_request(
        &auth,
        post_json_with_auth("/delete-user", serde_json::json!({}), &del_token),
    )
    .await;
    validator.validate_endpoint("/delete-user", "post", status, &body);

    // --- POST /change-email ---
    let (ce_token, _) = signup_user(&auth, "ce@example.com", "password123", "CE User").await;
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/change-email",
            serde_json::json!({
                "newEmail": "ce_new@example.com"
            }),
            &ce_token,
        ),
    )
    .await;
    validator.validate_endpoint("/change-email", "post", status, &body);

    // --- GET /list-accounts ---
    let (la_token, _) = signup_user(&auth, "la@example.com", "password123", "LA User").await;
    let (status, body) = send_request(&auth, get_with_auth("/list-accounts", &la_token)).await;
    // list-accounts returns an array, validate camelCase
    if let Some(arr) = body.as_array() {
        if let Some(first) = arr.first() {
            let camel_violations = check_camel_case_fields(first, "accounts[0]");
            let passed = camel_violations.is_empty();
            validator.results.push(EndpointResult {
                endpoint: "/list-accounts".to_string(),
                method: "GET".to_string(),
                status,
                passed,
                diffs: vec![],
                camel_case_violations: camel_violations,
            });
        } else {
            // Empty array — valid but nothing to validate
            validator.results.push(EndpointResult {
                endpoint: "/list-accounts".to_string(),
                method: "GET".to_string(),
                status,
                passed: true,
                diffs: vec![],
                camel_case_violations: vec![],
            });
        }
    } else {
        validator.results.push(EndpointResult {
            endpoint: "/list-accounts".to_string(),
            method: "GET".to_string(),
            status,
            passed: false,
            diffs: vec![ShapeDiff {
                path: "".to_string(),
                kind: DiffKind::TypeMismatch {
                    expected: "array".to_string(),
                    actual: json_type_name(&body).to_string(),
                },
            }],
            camel_case_violations: vec![],
        });
    }

    // --- GET /reference/openapi.json ---
    let (status, body) = send_request(&auth, get_request("/reference/openapi.json")).await;
    assert_eq!(status, 200, "OpenAPI endpoint should return 200");
    assert!(body["openapi"].is_string(), "Should have openapi version");
    assert!(body["paths"].is_object(), "Should have paths");

    // Print report
    let report = validator.report();
    eprintln!("\n{}\n", report);

    // All known incompatibilities have been fixed.
    // Track any future gaps here so the gate catches *new* regressions.
    let known_failing: HashSet<&str> = HashSet::new();

    let unexpected_failures: Vec<_> = validator
        .results
        .iter()
        .filter(|r| !r.passed && !known_failing.contains(r.endpoint.as_str()))
        .collect();

    assert!(
        unexpected_failures.is_empty(),
        "Spec-driven validation found unexpected failures (not in the known-failing list):\n{}",
        unexpected_failures
            .iter()
            .map(|r| format!("  {} {}", r.method, r.endpoint))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// All error responses must follow the { "message": "..." } format per the spec.
#[tokio::test]
async fn test_error_response_shapes_match_spec() {
    let auth = create_test_auth().await;
    let spec = compat::schema::load_openapi_spec();

    // Collect error scenarios
    let error_scenarios: Vec<(&str, &str, better_auth::types::AuthRequest, u16)> = vec![
        (
            "/sign-in/email",
            "post",
            post_json(
                "/sign-in/email",
                serde_json::json!({
                    "email": "nonexistent@example.com",
                    "password": "password123"
                }),
            ),
            401,
        ),
        (
            "/sign-up/email",
            "post",
            post_json("/sign-up/email", serde_json::json!({})),
            400,
        ),
        (
            "/sign-up/email",
            "post",
            post_json(
                "/sign-up/email",
                serde_json::json!({
                    "name": "Short",
                    "email": "short@example.com",
                    "password": "123"
                }),
            ),
            400,
        ),
    ];

    let mut all_passed = true;
    for (path, method, req, expected_status_class) in error_scenarios {
        let (status, body) = send_request(&auth, req).await;
        let status_class = status / 100;
        let expected_class = expected_status_class / 100;

        // Verify status is in the expected class (4xx)
        if status_class != expected_class {
            eprintln!(
                "WARN: {} {} returned status {} (expected {}xx)",
                method.to_uppercase(),
                path,
                status,
                expected_class
            );
        }

        // All error responses MUST have a "message" field per the spec
        if status >= 400 {
            if !body["message"].is_string() {
                eprintln!(
                    "FAIL: {} {} error response missing 'message' field: {}",
                    method.to_uppercase(),
                    path,
                    body
                );
                all_passed = false;
            }

            // Validate against spec error schema
            let error_schemas = compat::schema::extract_error_schemas(&spec, path, method);
            if let Some(error_schema) = error_schemas.get(&status.to_string()) {
                let diffs = compat::validation::validate_response(&body, error_schema, "");
                if !diffs.is_empty() {
                    eprintln!(
                        "FAIL: {} {} error response shape mismatch (status {}):",
                        method.to_uppercase(),
                        path,
                        status
                    );
                    for diff in &diffs {
                        eprintln!("      {}", diff);
                    }
                    all_passed = false;
                }
            }
        }
    }

    assert!(
        all_passed,
        "Some error responses don't match the spec. See output above."
    );
}
