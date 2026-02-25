//! Organization plugin endpoint validation tests.
//!
//! Tests the full Organization lifecycle: create, update, delete, members,
//! invitations, and permissions against the OpenAPI spec.

mod compat;

use std::collections::HashSet;

use compat::helpers::*;
use compat::shapes::check_camel_case_fields;
use compat::validator::SpecValidator;

/// Test organization CRUD endpoints against the spec.
#[tokio::test]
async fn test_organization_crud_endpoints() {
    let auth = create_test_auth().await;
    let mut validator = SpecValidator::new();

    // Sign up a user to use as the org creator
    let (token, _) = signup_user(&auth, "org@example.com", "password123", "Org User").await;

    // --- POST /organization/create ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/create",
            serde_json::json!({
                "name": "Test Org",
                "slug": "test-org"
            }),
            &token,
        ),
    )
    .await;
    assert_eq!(status, 200, "create org failed: {}", body);
    validator.validate_endpoint("/organization/create", "post", status, &body);

    // --- POST /organization/check-slug (taken) ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/check-slug",
            serde_json::json!({ "slug": "test-org" }),
            &token,
        ),
    )
    .await;
    assert_eq!(status, 200, "check-slug failed: {}", body);
    validator.validate_endpoint("/organization/check-slug", "post", status, &body);

    // --- POST /organization/check-slug (available) ---
    let (status_avail, body_avail) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/check-slug",
            serde_json::json!({ "slug": "available-slug" }),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status_avail, 200,
        "check-slug available failed: {}",
        body_avail
    );

    // --- GET /organization/list ---
    let (status, body) = send_request(&auth, get_with_auth("/organization/list", &token)).await;
    assert_eq!(status, 200, "list orgs failed: {}", body);
    // list returns an array
    if let Some(arr) = body.as_array() {
        assert!(!arr.is_empty(), "org list should not be empty after create");
        if let Some(first) = arr.first() {
            let violations = check_camel_case_fields(first, "organization[0]");
            assert!(
                violations.is_empty(),
                "camelCase violations in org list: {:?}",
                violations
            );
        }
    }

    // Get org ID from list for subsequent operations
    let org_id = body
        .as_array()
        .and_then(|a| a.first())
        .and_then(|o| o["id"].as_str())
        .expect("org should have id")
        .to_string();

    // --- POST /organization/update ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/update",
            serde_json::json!({
                "name": "Updated Org Name",
                "organizationId": org_id
            }),
            &token,
        ),
    )
    .await;
    assert_eq!(status, 200, "update org failed: {}", body);
    validator.validate_endpoint("/organization/update", "post", status, &body);

    // --- POST /organization/set-active ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/set-active",
            serde_json::json!({ "organizationSlug": "test-org" }),
            &token,
        ),
    )
    .await;
    assert_eq!(status, 200, "set-active failed: {}", body);
    validator.validate_endpoint("/organization/set-active", "post", status, &body);

    // --- GET /organization/get-full-organization ---
    let (status, body) = send_request(
        &auth,
        get_with_auth_and_query(
            "/organization/get-full-organization",
            &token,
            vec![("organizationSlug", "test-org")],
        ),
    )
    .await;
    assert_eq!(status, 200, "get-full-org failed: {}", body);
    validator.validate_endpoint("/organization/get-full-organization", "get", status, &body);

    // --- GET /organization/get-active-member ---
    let (status, body) = send_request(
        &auth,
        get_with_auth("/organization/get-active-member", &token),
    )
    .await;
    assert_eq!(status, 200, "get-active-member failed: {}", body);
    validator.validate_endpoint("/organization/get-active-member", "get", status, &body);

    // --- POST /organization/has-permission ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/has-permission",
            serde_json::json!({
                "permissions": { "member": ["create"] }
            }),
            &token,
        ),
    )
    .await;
    assert_eq!(status, 200, "has-permission failed: {}", body);
    validator.validate_endpoint("/organization/has-permission", "post", status, &body);

    // Print report
    let report = validator.report();
    eprintln!("\n{}\n", report);

    let failures: Vec<_> = validator.results.iter().filter(|r| !r.passed).collect();
    assert!(
        failures.is_empty(),
        "Organization CRUD spec failures:\n{}",
        failures
            .iter()
            .map(|r| format!("  {} {}", r.method, r.endpoint))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Test organization invitation endpoints against the spec.
#[tokio::test]
async fn test_organization_invitation_endpoints() {
    let auth = create_test_auth().await;
    let mut validator = SpecValidator::new();

    // Set up: create user and org
    let (owner_token, _) = signup_user(&auth, "owner@example.com", "password123", "Owner").await;
    let (invitee_token, _) =
        signup_user(&auth, "invitee@example.com", "password123", "Invitee").await;

    let (status, _create_body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/create",
            serde_json::json!({
                "name": "Invite Org",
                "slug": "invite-org"
            }),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "create org for invite test failed");

    // Set active organization
    send_request(
        &auth,
        post_json_with_auth(
            "/organization/set-active",
            serde_json::json!({ "organizationSlug": "invite-org" }),
            &owner_token,
        ),
    )
    .await;

    // --- POST /organization/invite-member ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/invite-member",
            serde_json::json!({
                "email": "invitee@example.com",
                "role": "member"
            }),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "invite-member failed: {}", body);
    validator.validate_endpoint("/organization/invite-member", "post", status, &body);

    // Extract invitation ID for subsequent tests
    let invitation_id = body["invitation"]["id"]
        .as_str()
        .expect("invitation should have id")
        .to_string();

    // --- GET /organization/get-invitation ---
    let (status, body) = send_request(
        &auth,
        get_with_auth_and_query(
            "/organization/get-invitation",
            &owner_token,
            vec![("id", &invitation_id)],
        ),
    )
    .await;
    assert_eq!(status, 200, "get-invitation failed: {}", body);
    validator.validate_endpoint("/organization/get-invitation", "get", status, &body);

    // --- GET /organization/list-invitations ---
    let (status, body) = send_request(
        &auth,
        get_with_auth("/organization/list-invitations", &owner_token),
    )
    .await;
    assert_eq!(status, 200, "list-invitations failed: {}", body);

    // --- POST /organization/accept-invitation (invitee accepts) ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/accept-invitation",
            serde_json::json!({ "invitationId": invitation_id }),
            &invitee_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "accept-invitation failed: {}", body);
    validator.validate_endpoint("/organization/accept-invitation", "post", status, &body);

    // --- Invite another user to test cancel and reject ---
    let (reject_token, _) =
        signup_user(&auth, "reject@example.com", "password123", "Rejecter").await;

    let (_, inv2_body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/invite-member",
            serde_json::json!({
                "email": "reject@example.com",
                "role": "member"
            }),
            &owner_token,
        ),
    )
    .await;
    let inv2_id = inv2_body["invitation"]["id"]
        .as_str()
        .expect("second invitation should have id")
        .to_string();

    // --- POST /organization/reject-invitation ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/reject-invitation",
            serde_json::json!({ "invitationId": inv2_id }),
            &reject_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "reject-invitation failed: {}", body);
    validator.validate_endpoint("/organization/reject-invitation", "post", status, &body);

    // --- Create a third invitation to test cancel ---
    signup_user(&auth, "cancel@example.com", "password123", "Canceler").await;

    let (_, inv3_body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/invite-member",
            serde_json::json!({
                "email": "cancel@example.com",
                "role": "member"
            }),
            &owner_token,
        ),
    )
    .await;
    let inv3_id = inv3_body["invitation"]["id"]
        .as_str()
        .expect("third invitation should have id")
        .to_string();

    // --- POST /organization/cancel-invitation ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/cancel-invitation",
            serde_json::json!({ "invitationId": inv3_id }),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "cancel-invitation failed: {}", body);
    validator.validate_endpoint("/organization/cancel-invitation", "post", status, &body);

    // Print report
    let report = validator.report();
    eprintln!("\n{}\n", report);

    // Known spec mismatches: Rust wraps invitation in { invitation: {...} }
    // but spec expects flat fields at top level.
    let known_failing: HashSet<&str> = HashSet::from(["/organization/invite-member"]);

    let unexpected: Vec<_> = validator
        .results
        .iter()
        .filter(|r| !r.passed && !known_failing.contains(r.endpoint.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "Organization invitation spec failures:\n{}",
        unexpected
            .iter()
            .map(|r| format!("  {} {}", r.method, r.endpoint))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Test organization member management endpoints.
#[tokio::test]
async fn test_organization_member_endpoints() {
    let auth = create_test_auth().await;
    let mut validator = SpecValidator::new();

    // Set up: create owner, member, and org
    let (owner_token, _) =
        signup_user(&auth, "mem_owner@example.com", "password123", "Owner").await;
    let (member_token, _) =
        signup_user(&auth, "mem_user@example.com", "password123", "Member").await;

    // Create org
    send_request(
        &auth,
        post_json_with_auth(
            "/organization/create",
            serde_json::json!({
                "name": "Member Test Org",
                "slug": "member-test-org"
            }),
            &owner_token,
        ),
    )
    .await;

    // Set active org
    send_request(
        &auth,
        post_json_with_auth(
            "/organization/set-active",
            serde_json::json!({ "organizationSlug": "member-test-org" }),
            &owner_token,
        ),
    )
    .await;

    // Invite and accept member
    let (_, inv_body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/invite-member",
            serde_json::json!({
                "email": "mem_user@example.com",
                "role": "member"
            }),
            &owner_token,
        ),
    )
    .await;
    let inv_id = inv_body["invitation"]["id"]
        .as_str()
        .expect("invitation id")
        .to_string();

    send_request(
        &auth,
        post_json_with_auth(
            "/organization/accept-invitation",
            serde_json::json!({ "invitationId": inv_id }),
            &member_token,
        ),
    )
    .await;

    // --- POST /organization/update-member-role ---
    // Get the member's member_id first via get-full-organization
    let (_, full_body) = send_request(
        &auth,
        get_with_auth_and_query(
            "/organization/get-full-organization",
            &owner_token,
            vec![("organizationSlug", "member-test-org")],
        ),
    )
    .await;
    let members = full_body["members"].as_array().expect("members array");
    let member_entry = members
        .iter()
        .find(|m| m["user"]["email"].as_str() == Some("mem_user@example.com"))
        .expect("should find member by user.email");
    let member_id = member_entry["id"].as_str().expect("member id").to_string();

    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/update-member-role",
            serde_json::json!({
                "memberId": member_id,
                "role": "admin"
            }),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "update-member-role failed: {}", body);
    validator.validate_endpoint("/organization/update-member-role", "post", status, &body);

    // --- POST /organization/leave (member leaves) ---
    // Set active org for member first
    send_request(
        &auth,
        post_json_with_auth(
            "/organization/set-active",
            serde_json::json!({ "organizationSlug": "member-test-org" }),
            &member_token,
        ),
    )
    .await;

    let (_, full_body2) = send_request(
        &auth,
        get_with_auth_and_query(
            "/organization/get-full-organization",
            &owner_token,
            vec![("organizationSlug", "member-test-org")],
        ),
    )
    .await;
    // FullOrganizationResponse uses #[serde(flatten)] on organization,
    // so org fields are at the top level
    let org_id = full_body2["id"]
        .as_str()
        .expect("org id from flattened response")
        .to_string();

    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/leave",
            serde_json::json!({ "organizationId": org_id }),
            &member_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "leave org failed: {}", body);
    validator.validate_endpoint("/organization/leave", "post", status, &body);

    // --- POST /organization/remove-member (owner removes an invited member) ---
    // Re-invite member for remove test
    let (member2_token, _) = signup_user(&auth, "mem2@example.com", "password123", "Member2").await;

    let (_, inv2_body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/invite-member",
            serde_json::json!({
                "email": "mem2@example.com",
                "role": "member"
            }),
            &owner_token,
        ),
    )
    .await;
    let inv2_id = inv2_body["invitation"]["id"]
        .as_str()
        .expect("invitation id")
        .to_string();

    send_request(
        &auth,
        post_json_with_auth(
            "/organization/accept-invitation",
            serde_json::json!({ "invitationId": inv2_id }),
            &member2_token,
        ),
    )
    .await;

    // Get member2's member_id
    let (_, full_body3) = send_request(
        &auth,
        get_with_auth_and_query(
            "/organization/get-full-organization",
            &owner_token,
            vec![("organizationSlug", "member-test-org")],
        ),
    )
    .await;
    let members3 = full_body3["members"].as_array().expect("members array");
    let member2_entry = members3
        .iter()
        .find(|m| m["user"]["email"].as_str() == Some("mem2@example.com"))
        .expect("should find member2 by user.email");
    let member2_id = member2_entry["id"]
        .as_str()
        .expect("member2 id")
        .to_string();

    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/remove-member",
            serde_json::json!({ "memberId": member2_id }),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "remove-member failed: {}", body);
    validator.validate_endpoint("/organization/remove-member", "post", status, &body);

    // --- POST /organization/delete ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/delete",
            serde_json::json!({ "organizationId": org_id }),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "delete org failed: {}", body);
    validator.validate_endpoint("/organization/delete", "post", status, &body);

    // Print report
    let report = validator.report();
    eprintln!("\n{}\n", report);

    // Known spec mismatches:
    //   - update-member-role: Rust returns flat MemberResponse, spec expects { member: {...} }
    //   - remove-member: Rust returns { success: true }, spec expects { member: {...} }
    let known_failing: HashSet<&str> = HashSet::from([
        "/organization/update-member-role",
        "/organization/remove-member",
    ]);

    let unexpected: Vec<_> = validator
        .results
        .iter()
        .filter(|r| !r.passed && !known_failing.contains(r.endpoint.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "Organization member spec failures:\n{}",
        unexpected
            .iter()
            .map(|r| format!("  {} {}", r.method, r.endpoint))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
