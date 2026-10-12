//! Organization plugin endpoint validation tests.
//!
//! Tests the full Organization lifecycle: create, update, delete, members,
//! invitations, and permissions against the OpenAPI spec.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "organization compatibility tests intentionally use direct JSON assertions over generated fixtures"
)]

mod compat;
#[path = "compat_organization_tests/member_lifecycle.rs"]
mod member_lifecycle;

use std::collections::HashSet;

use compat::helpers::*;
use compat::schema::OpenApiProfile;
use compat::shapes::check_camel_case_fields;
use compat::validator::SpecValidator;

/// Test organization CRUD endpoints against the spec.
#[tokio::test]
async fn test_organization_crud_endpoints() {
    let auth = create_test_auth().await;
    let mut validator = SpecValidator::with_profile(OpenApiProfile::AlignedRs);

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
    assert_eq!(status, 400, "check-slug failed: {}", body);

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
                "organizationId": org_id,
                "data": {
                    "name": "Updated Org Name"
                }
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

    let known_failing: HashSet<&str> = HashSet::from(["/organization/set-active"]);

    let failures: Vec<_> = validator
        .results
        .iter()
        .filter(|r| !r.passed && !r.skipped && !known_failing.contains(r.endpoint.as_str()))
        .collect();
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
    let mut validator = SpecValidator::with_profile(OpenApiProfile::AlignedRs);

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
    let _ = send_request(
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
    let invitation_id = body["id"]
        .as_str()
        .expect("invitation should have id")
        .to_string();

    // --- GET /organization/get-invitation ---
    let (status, body) = send_request(
        &auth,
        get_with_auth_and_query(
            "/organization/get-invitation",
            &invitee_token,
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
    let inv2_id = inv2_body["id"]
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
    let _ = signup_user(&auth, "cancel@example.com", "password123", "Canceler").await;

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
    let inv3_id = inv3_body["id"]
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

    // All spec mismatches have been fixed — no known failures expected.
    let known_failing: HashSet<&str> = HashSet::new();

    let unexpected: Vec<_> = validator
        .results
        .iter()
        .filter(|r| !r.passed && !r.skipped && !known_failing.contains(r.endpoint.as_str()))
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
    fn future_size<F: std::future::Future>(_: impl FnOnce() -> F) -> usize {
        std::mem::size_of::<F>()
    }
    eprintln!(
        "organization-stack test-start create-auth-future-bytes={}",
        future_size(create_test_auth)
    );
    let auth = create_test_auth().await;
    eprintln!("organization-stack auth-created");
    let request = get_request("/");
    eprintln!(
        "organization-stack helper-futures handle={} send={} signup={}",
        future_size(|| auth.handle_request(request.clone())),
        future_size(|| send_request(&auth, request.clone())),
        future_size(|| signup_user(&auth, "unused@example.test", "unused", "Unused")),
    );
    let mut validator = SpecValidator::with_profile(OpenApiProfile::AlignedRs);
    eprintln!("organization-stack validator-created");

    let setup = member_lifecycle::create_membership(&auth);
    eprintln!(
        "organization-stack phase-future name=create-membership bytes={}",
        std::mem::size_of_val(&setup)
    );
    let membership = setup.await;

    let leave = member_lifecycle::update_role_and_leave(&auth, &mut validator, &membership);
    eprintln!(
        "organization-stack phase-future name=update-role-and-leave bytes={}",
        std::mem::size_of_val(&leave)
    );
    let org_id = leave.await;

    let remove =
        member_lifecycle::remove_invited_member(&auth, &mut validator, &membership.owner_token);
    eprintln!(
        "organization-stack phase-future name=remove-invited-member bytes={}",
        std::mem::size_of_val(&remove)
    );
    remove.await;

    let delete = member_lifecycle::delete_organization(
        &auth,
        &mut validator,
        &membership.owner_token,
        &org_id,
    );
    eprintln!(
        "organization-stack phase-future name=delete-organization bytes={}",
        std::mem::size_of_val(&delete)
    );
    delete.await;

    // Print report
    let report = validator.report();
    eprintln!("\n{}\n", report);

    // All spec mismatches have been fixed — no known failures expected.
    let known_failing: HashSet<&str> = HashSet::new();

    let unexpected: Vec<_> = validator
        .results
        .iter()
        .filter(|r| !r.passed && !r.skipped && !known_failing.contains(r.endpoint.as_str()))
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
    eprintln!("organization-stack test-body-complete");
}

#[tokio::test]
async fn test_custom_creator_role_protection() {
    let auth = create_test_auth_with_options(TestAuthOptions {
        creator_role: Some("founder".to_string()),
        ..Default::default()
    })
    .await;

    let (founder_token, _) =
        signup_user(&auth, "founder@example.com", "password123", "Founder").await;

    let (status, create_body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/create",
            serde_json::json!({
                "name": "Founder Org",
                "slug": "founder-org"
            }),
            &founder_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "create org failed: {}", create_body);

    let founder_member_id = create_body["members"][0]["id"]
        .as_str()
        .expect("founder member id")
        .to_string();
    assert_eq!(
        create_body["members"][0]["role"].as_str(),
        Some("founder"),
        "creator role should use custom founder role",
    );

    let (status, remove_body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/remove-member",
            serde_json::json!({
                "memberIdOrEmail": founder_member_id,
                "organizationId": create_body["id"].as_str().expect("org id"),
            }),
            &founder_token,
        ),
    )
    .await;
    assert_eq!(
        status, 400,
        "remove-member should reject removing last founder: {}",
        remove_body
    );

    let (status, leave_body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/leave",
            serde_json::json!({
                "organizationId": create_body["id"].as_str().expect("org id"),
            }),
            &founder_token,
        ),
    )
    .await;
    assert_eq!(
        status, 400,
        "leave should reject last founder: {}",
        leave_body
    );
}

#[tokio::test]
async fn test_invite_member_preserves_empty_roles_through_acceptance() {
    let auth = create_test_auth().await;
    let (owner_token, _) =
        signup_user(&auth, "role-owner@example.com", "password123", "Owner").await;

    let (status, create_body) = send_request(
        &auth,
        post_json_with_auth(
            "/organization/create",
            serde_json::json!({
                "name": "Role Org",
                "slug": "role-org"
            }),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "create org failed: {}", create_body);

    let org_id = create_body["id"].as_str().expect("org id");

    for (index, role) in [serde_json::json!(""), serde_json::json!([])]
        .into_iter()
        .enumerate()
    {
        let email = format!("role-invitee-{index}@example.com");
        let (invitee_token, _) = signup_user(&auth, &email, "password123", "Invitee").await;
        let (status, body) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/invite-member",
                serde_json::json!({"organizationId": org_id, "email": email, "role": role}),
                &owner_token,
            ),
        )
        .await;
        assert_eq!(status, 200, "empty role invitation failed: {body}");
        assert_eq!(body["role"], "");
        let (status, accepted) = send_request(
            &auth,
            post_json_with_auth(
                "/organization/accept-invitation",
                serde_json::json!({"invitationId": body["id"]}),
                &invitee_token,
            ),
        )
        .await;
        assert_eq!(status, 200, "empty role acceptance failed: {accepted}");
        assert_eq!(accepted["member"]["role"], "");
        assert_eq!(accepted["invitation"]["status"], "accepted");
    }
}
