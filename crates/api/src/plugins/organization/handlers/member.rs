use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthMember, AuthSession, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::types::{AuthRequest, AuthResponse};

use super::{require_session, resolve_organization_id};
use crate::plugins::organization::config::OrganizationConfig;
use crate::plugins::organization::rbac::{Action, Resource, has_permission_any};
use crate::plugins::organization::types::{
    ListMembersQuery, ListMembersResponse, MemberResponse, RemoveMemberRequest,
    UpdateMemberRoleRequest,
};

/// Handle get active member request
pub async fn handle_get_active_member<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;

    let org_id = session
        .active_organization_id()
        .ok_or_else(|| AuthError::bad_request("No active organization"))?;

    let member = ctx
        .database
        .get_member(org_id, user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    let member_response = MemberResponse::from_member_and_user(&member, &user);

    Ok(AuthResponse::json(200, &member_response)?)
}

/// Handle list members request
pub async fn handle_list_members<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;

    // Parse query parameters
    let query = parse_query::<ListMembersQuery>(&req.query);

    let org_id = resolve_organization_id(
        query.organization_id.as_deref(),
        query.organization_slug.as_deref(),
        &session,
        ctx,
    )
    .await?;

    // Check membership
    ctx.database
        .get_member(&org_id, user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    // Get all members
    let members_raw = ctx.database.list_organization_members(&org_id).await?;
    let total = members_raw.len();

    // Apply pagination
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(100);

    let members_page: Vec<_> = members_raw.into_iter().skip(offset).take(limit).collect();

    // Enrich with user info
    let mut members = Vec::with_capacity(members_page.len());
    for member in &members_page {
        if let Some(user_info) = ctx.database.get_user_by_id(member.user_id()).await? {
            members.push(MemberResponse::from_member_and_user(member, &user_info));
        }
    }

    let response = ListMembersResponse { members, total };

    Ok(AuthResponse::json(200, &response)?)
}

/// Handle remove member request
pub async fn handle_remove_member<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: RemoveMemberRequest = req
        .body_as_json()
        .map_err(|e| AuthError::bad_request(format!("Invalid request body: {}", e)))?;

    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, &session, ctx).await?;

    // Get the requester's membership
    let requester_member = ctx
        .database
        .get_member(&org_id, user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    // Determine target member
    let target_member_id: String;
    let target_member_org_id: String;
    let target_member_user_id: String;
    let target_member_role: String;

    if let Some(member_id) = &body.member_id {
        let target = ctx
            .database
            .get_member_by_id(member_id)
            .await?
            .ok_or_else(|| AuthError::not_found("Member not found"))?;
        target_member_id = target.id().to_string();
        target_member_org_id = target.organization_id().to_string();
        target_member_user_id = target.user_id().to_string();
        target_member_role = target.role().to_string();
    } else if let Some(email) = &body.email {
        // Find user by email first
        let target_user = ctx
            .database
            .get_user_by_email(email)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;
        // Get member
        let target = ctx
            .database
            .get_member(&org_id, target_user.id())
            .await?
            .ok_or_else(|| AuthError::not_found("Member not found"))?;
        target_member_id = target.id().to_string();
        target_member_org_id = target.organization_id().to_string();
        target_member_user_id = target.user_id().to_string();
        target_member_role = target.role().to_string();
    } else {
        return Err(AuthError::bad_request(
            "Either memberId or email must be provided",
        ));
    };

    // Verify target is in same organization
    if target_member_org_id != org_id {
        return Err(AuthError::bad_request("Member not in this organization"));
    }

    // Check if user is trying to remove themselves (allowed without permission)
    let is_self_removal = target_member_user_id == user.id();

    if !is_self_removal {
        // Check permission for removing others
        if !has_permission_any(
            requester_member.role(),
            &Resource::Member,
            &Action::Delete,
            &config.roles,
        ) {
            return Err(AuthError::forbidden(
                "You don't have permission to remove members",
            ));
        }
    }

    // Check if removing the last owner
    if target_member_role.contains("owner") {
        let all_members = ctx.database.list_organization_members(&org_id).await?;
        let owner_count = all_members
            .iter()
            .filter(|m| m.role().contains("owner"))
            .count();

        if owner_count <= 1 {
            return Err(AuthError::bad_request(
                "Cannot remove the last owner from an organization",
            ));
        }
    }

    // Build member response before deleting (spec expects {member: ...})
    let removed_member = serde_json::json!({
        "member": {
            "id": target_member_id,
            "userId": target_member_user_id,
            "organizationId": target_member_org_id,
            "role": target_member_role,
        }
    });

    // Delete member by member_id
    ctx.database.delete_member(&target_member_id).await?;

    Ok(AuthResponse::json(200, &removed_member)?)
}

/// Handle update member role request
pub async fn handle_update_member_role<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: UpdateMemberRoleRequest = req
        .body_as_json()
        .map_err(|e| AuthError::bad_request(format!("Invalid request body: {}", e)))?;

    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, &session, ctx).await?;

    // Get requester's membership
    let requester_member = ctx
        .database
        .get_member(&org_id, user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    // Check permission
    if !has_permission_any(
        requester_member.role(),
        &Resource::Member,
        &Action::Update,
        &config.roles,
    ) {
        return Err(AuthError::forbidden(
            "You don't have permission to update member roles",
        ));
    }

    // Get target member
    let target_member = ctx
        .database
        .get_member_by_id(&body.member_id)
        .await?
        .ok_or_else(|| AuthError::not_found("Member not found"))?;

    // Verify target is in same organization
    if target_member.organization_id() != org_id {
        return Err(AuthError::bad_request("Member not in this organization"));
    }

    // Prevent demoting the last owner
    if target_member.role().contains("owner") && !body.role.contains("owner") {
        let all_members = ctx.database.list_organization_members(&org_id).await?;
        let owner_count = all_members
            .iter()
            .filter(|m| m.role().contains("owner"))
            .count();

        if owner_count <= 1 {
            return Err(AuthError::bad_request(
                "Cannot demote the last owner. Transfer ownership first.",
            ));
        }
    }

    // Update role
    let updated = ctx
        .database
        .update_member_role(&body.member_id, &body.role)
        .await?;

    // Return updated member wrapped in {member: ...} per spec
    if let Some(user_info) = ctx.database.get_user_by_id(updated.user_id()).await? {
        let member_response = MemberResponse::from_member_and_user(&updated, &user_info);
        let wrapped = serde_json::json!({ "member": member_response });
        return Ok(AuthResponse::json(200, &wrapped)?);
    }

    let wrapped = serde_json::json!({ "member": updated });
    Ok(AuthResponse::json(200, &wrapped)?)
}

/// Helper function to parse query parameters into a struct
fn parse_query<T: Default + serde::de::DeserializeOwned>(
    query: &std::collections::HashMap<String, String>,
) -> T {
    let json_value =
        serde_json::to_value(query).unwrap_or(serde_json::Value::Object(Default::default()));
    serde_json::from_value(json_value).unwrap_or_default()
}
