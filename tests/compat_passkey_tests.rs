//! Passkey plugin endpoint validation tests.
//!
//! Tests passkey registration, authentication, and management endpoints
//! against the OpenAPI spec. Note: WebAuthn flows require browser interaction,
//! so we validate response shapes for the options-generation endpoints and
//! error shapes for verification endpoints (which need real attestation data).

mod compat;

use compat::helpers::*;
use compat::validator::SpecValidator;

/// Test passkey registration and authentication option generation endpoints.
#[tokio::test]
async fn test_passkey_option_generation_endpoints() {
    let auth = create_test_auth().await;
    let mut validator = SpecValidator::new();

    // Sign up a user
    let (token, _) = signup_user(&auth, "passkey@example.com", "password123", "PK User").await;

    // --- GET /passkey/generate-register-options ---
    let (status, body) = send_request(
        &auth,
        get_with_auth("/passkey/generate-register-options", &token),
    )
    .await;
    assert_eq!(status, 200, "generate-register-options failed: {}", body);
    // WebAuthn options must have challenge and rp fields
    assert!(
        body["challenge"].is_string(),
        "register options should have challenge"
    );
    assert!(
        body["rp"].is_object(),
        "register options should have rp object"
    );
    validator.validate_endpoint("/passkey/generate-register-options", "get", status, &body);

    // --- POST /passkey/generate-authenticate-options ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/passkey/generate-authenticate-options",
            serde_json::json!({}),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status, 200,
        "generate-authenticate-options failed: {}",
        body
    );
    assert!(
        body["challenge"].is_string(),
        "authenticate options should have challenge"
    );
    validator.validate_endpoint(
        "/passkey/generate-authenticate-options",
        "post",
        status,
        &body,
    );

    // Print report
    let report = validator.report();
    eprintln!("\n{}\n", report);

    let failures: Vec<_> = validator.results.iter().filter(|r| !r.passed).collect();
    assert!(
        failures.is_empty(),
        "Passkey option generation spec failures:\n{}",
        failures
            .iter()
            .map(|r| format!("  {} {}", r.method, r.endpoint))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Test passkey verification endpoints (expect errors without real attestation data).
#[tokio::test]
async fn test_passkey_verification_endpoints() {
    let auth = create_test_auth().await;

    let (token, _) = signup_user(&auth, "pk_verify@example.com", "password123", "PK Verify").await;

    // --- POST /passkey/verify-registration ---
    // Without real WebAuthn attestation, this should return an error
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/passkey/verify-registration",
            serde_json::json!({
                "id": "fake-credential-id",
                "rawId": "fake-raw-id",
                "response": {
                    "attestationObject": "fake",
                    "clientDataJSON": "fake"
                },
                "type": "public-key"
            }),
            &token,
        ),
    )
    .await;
    // Expect 4xx error since attestation data is fake
    assert!(
        status >= 400,
        "verify-registration with fake data should fail, got status {}",
        status
    );
    // Error response should have message field per spec
    assert!(
        body["message"].is_string() || body["error"].is_string(),
        "error response should have message or error field: {}",
        body
    );

    // --- POST /passkey/verify-authentication ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/passkey/verify-authentication",
            serde_json::json!({
                "id": "fake-credential-id",
                "rawId": "fake-raw-id",
                "response": {
                    "authenticatorData": "fake",
                    "clientDataJSON": "fake",
                    "signature": "fake"
                },
                "type": "public-key"
            }),
            &token,
        ),
    )
    .await;
    assert!(
        status >= 400,
        "verify-authentication with fake data should fail, got status {}",
        status
    );
    assert!(
        body["message"].is_string() || body["error"].is_string(),
        "error response should have message or error field: {}",
        body
    );
}

/// Test passkey management endpoints (list, delete, update).
#[tokio::test]
async fn test_passkey_management_endpoints() {
    let auth = create_test_auth().await;
    let mut validator = SpecValidator::new();

    let (token, _) = signup_user(&auth, "pk_mgmt@example.com", "password123", "PK Mgmt").await;

    // --- GET /passkey/list-user-passkeys ---
    let (status, body) =
        send_request(&auth, get_with_auth("/passkey/list-user-passkeys", &token)).await;
    assert_eq!(status, 200, "list-user-passkeys failed: {}", body);
    // Should return an array (empty since no passkeys registered)
    assert!(
        body.is_array(),
        "list-user-passkeys should return array, got: {}",
        body
    );

    // --- POST /passkey/delete-passkey ---
    // Try to delete a non-existent passkey
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/passkey/delete-passkey",
            serde_json::json!({ "id": "non-existent-id" }),
            &token,
        ),
    )
    .await;
    // May return 200 (no-op) or 404/400 depending on implementation
    if status == 200 {
        validator.validate_endpoint("/passkey/delete-passkey", "post", status, &body);
    }

    // --- POST /passkey/update-passkey ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/passkey/update-passkey",
            serde_json::json!({
                "id": "non-existent-id",
                "name": "My Passkey"
            }),
            &token,
        ),
    )
    .await;
    // May return 200 (no-op) or 404/400 depending on implementation
    if status == 200 {
        validator.validate_endpoint("/passkey/update-passkey", "post", status, &body);
    }

    // Print report
    let report = validator.report();
    eprintln!("\n{}\n", report);

    let failures: Vec<_> = validator.results.iter().filter(|r| !r.passed).collect();
    assert!(
        failures.is_empty(),
        "Passkey management spec failures:\n{}",
        failures
            .iter()
            .map(|r| format!("  {} {}", r.method, r.endpoint))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
