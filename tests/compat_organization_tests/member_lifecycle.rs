use crate::compat::{helpers::*, validator::SpecValidator};

pub(super) struct Membership {
    pub(super) owner_token: String,
    member_token: String,
    member_id: String,
}

pub(super) async fn create_membership(auth: &TestAuth) -> Membership {
    eprintln!("organization-stack phase-start name=create-membership");
    // Set up: create owner, member, and org
    let (owner_token, _) = signup_user(auth, "mem_owner@example.com", "password123", "Owner").await;
    let (member_token, _) =
        signup_user(auth, "mem_user@example.com", "password123", "Member").await;

    // Create org
    let _ = send_request(
        auth,
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
    let _ = send_request(
        auth,
        post_json_with_auth(
            "/organization/set-active",
            serde_json::json!({ "organizationSlug": "member-test-org" }),
            &owner_token,
        ),
    )
    .await;

    // Invite and accept member
    let (_, inv_body) = send_request(
        auth,
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
    let inv_id = inv_body["id"].as_str().expect("invitation id").to_string();

    let _ = send_request(
        auth,
        post_json_with_auth(
            "/organization/accept-invitation",
            serde_json::json!({ "invitationId": inv_id }),
            &member_token,
        ),
    )
    .await;

    // Read the member ID before the role update.
    let (_, full_body) = send_request(
        auth,
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

    eprintln!("organization-stack phase-end name=create-membership");
    Membership {
        owner_token,
        member_token,
        member_id,
    }
}

pub(super) async fn update_role_and_leave(
    auth: &TestAuth,
    validator: &mut SpecValidator,
    membership: &Membership,
) -> String {
    eprintln!("organization-stack phase-start name=update-role-and-leave");
    let Membership {
        owner_token,
        member_token,
        member_id,
    } = membership;
    let (status, body) = send_request(
        auth,
        post_json_with_auth(
            "/organization/update-member-role",
            serde_json::json!({
                "memberId": member_id,
                "role": "admin"
            }),
            owner_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "update-member-role failed: {}", body);

    // --- POST /organization/leave (member leaves) ---
    // Set active org for member first
    let _ = send_request(
        auth,
        post_json_with_auth(
            "/organization/set-active",
            serde_json::json!({ "organizationSlug": "member-test-org" }),
            member_token,
        ),
    )
    .await;

    let (_, full_body2) = send_request(
        auth,
        get_with_auth_and_query(
            "/organization/get-full-organization",
            owner_token,
            vec![("organizationSlug", "member-test-org")],
        ),
    )
    .await;
    // Full organization output places organization fields at the top level,
    // so org fields are at the top level
    let org_id = full_body2["id"]
        .as_str()
        .expect("org id from flattened response")
        .to_string();

    let (status, body) = send_request(
        auth,
        post_json_with_auth(
            "/organization/leave",
            serde_json::json!({ "organizationId": org_id }),
            member_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "leave org failed: {}", body);
    eprintln!("organization-stack validation-start path=/organization/leave");
    validator.validate_endpoint("/organization/leave", "post", status, &body);
    eprintln!("organization-stack validation-end path=/organization/leave");

    eprintln!("organization-stack phase-end name=update-role-and-leave");
    org_id
}

pub(super) async fn remove_invited_member(
    auth: &TestAuth,
    validator: &mut SpecValidator,
    owner_token: &str,
) {
    eprintln!("organization-stack phase-start name=remove-invited-member");
    // --- POST /organization/remove-member (owner removes an invited member) ---
    // Re-invite member for remove test
    let (member2_token, _) = signup_user(auth, "mem2@example.com", "password123", "Member2").await;

    let (_, inv2_body) = send_request(
        auth,
        post_json_with_auth(
            "/organization/invite-member",
            serde_json::json!({
                "email": "mem2@example.com",
                "role": "member"
            }),
            owner_token,
        ),
    )
    .await;
    let inv2_id = inv2_body["id"].as_str().expect("invitation id").to_string();

    let _ = send_request(
        auth,
        post_json_with_auth(
            "/organization/accept-invitation",
            serde_json::json!({ "invitationId": inv2_id }),
            &member2_token,
        ),
    )
    .await;

    // Get member2's member_id
    let (_, full_body3) = send_request(
        auth,
        get_with_auth_and_query(
            "/organization/get-full-organization",
            owner_token,
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
        auth,
        post_json_with_auth(
            "/organization/remove-member",
            serde_json::json!({ "memberIdOrEmail": member2_id }),
            owner_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "remove-member failed: {}", body);
    eprintln!("organization-stack validation-start path=/organization/remove-member");
    validator.validate_endpoint("/organization/remove-member", "post", status, &body);
    eprintln!("organization-stack validation-end path=/organization/remove-member");

    eprintln!("organization-stack phase-end name=remove-invited-member");
}

pub(super) async fn delete_organization(
    auth: &TestAuth,
    validator: &mut SpecValidator,
    owner_token: &str,
    org_id: &str,
) {
    eprintln!("organization-stack phase-start name=delete-organization");
    // --- POST /organization/delete ---
    let (status, body) = send_request(
        auth,
        post_json_with_auth(
            "/organization/delete",
            serde_json::json!({ "organizationId": org_id }),
            owner_token,
        ),
    )
    .await;
    assert_eq!(status, 200, "delete org failed: {}", body);
    eprintln!("organization-stack validation-start path=/organization/delete");
    validator.validate_endpoint("/organization/delete", "post", status, &body);
    eprintln!("organization-stack validation-end path=/organization/delete");

    eprintln!("organization-stack phase-end name=delete-organization");
}
