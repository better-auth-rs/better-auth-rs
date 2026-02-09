use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::types::{AuthRequest, AuthResponse, MemberWithUser};

use super::{require_session, resolve_organization_id};
use crate::plugins::organization::config::OrganizationConfig;
use crate::plugins::organization::rbac::{Action, Resource, has_permission_any};
use crate::plugins::organization::types::{
    ListMembersQuery, ListMembersResponse, RemoveMemberRequest, SuccessResponse,
    UpdateMemberRoleRequest,
};

/// Handle get active member request
pub async fn handle_get_active_member(
    req: &AuthRequest,
    ctx: &AuthContext,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;

    let org_id = session
        .active_organization_id
        .as_ref()
        .ok_or_else(|| AuthError::bad_request("No active organization"))?;

    let member = ctx
        .database
        .get_member(org_id, &user.id)
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    let member_with_user = MemberWithUser {
        id: member.id,
        organization_id: member.organization_id,
        user_id: member.user_id,
        role: member.role,
        created_at: member.created_at,
        user: better_auth_core::types::MemberUser {
            id: user.id.clone(),
            name: user.name.clone(),
            email: user.email.clone(),
            image: user.image.clone(),
        },
    };

    Ok(AuthResponse::json(200, &member_with_user)?)
}

/// Handle list members request
pub async fn handle_list_members(req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
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
        .get_member(&org_id, &user.id)
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
    for member in members_page {
        if let Some(user_info) = ctx.database.get_user_by_id(&member.user_id).await? {
            members.push(MemberWithUser {
                id: member.id,
                organization_id: member.organization_id,
                user_id: member.user_id,
                role: member.role,
                created_at: member.created_at,
                user: better_auth_core::types::MemberUser {
                    id: user_info.id,
                    name: user_info.name,
                    email: user_info.email,
                    image: user_info.image,
                },
            });
        }
    }

    let response = ListMembersResponse { members, total };

    Ok(AuthResponse::json(200, &response)?)
}

/// Handle remove member request
pub async fn handle_remove_member(
    req: &AuthRequest,
    ctx: &AuthContext,
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
        .get_member(&org_id, &user.id)
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    // Determine target member
    let target_member = if let Some(member_id) = &body.member_id {
        ctx.database
            .get_member_by_id(member_id)
            .await?
            .ok_or_else(|| AuthError::not_found("Member not found"))?
    } else if let Some(email) = &body.email {
        // Find user by email first
        let target_user = ctx
            .database
            .get_user_by_email(email)
            .await?
            .ok_or_else(|| AuthError::not_found("User not found"))?;
        // Get member
        let member = ctx
            .database
            .get_member(&org_id, &target_user.id)
            .await?
            .ok_or_else(|| AuthError::not_found("Member not found"))?;
        // Convert to MemberWithUser
        MemberWithUser {
            id: member.id,
            organization_id: member.organization_id,
            user_id: member.user_id.clone(),
            role: member.role,
            created_at: member.created_at,
            user: better_auth_core::types::MemberUser {
                id: target_user.id,
                name: target_user.name,
                email: target_user.email,
                image: target_user.image,
            },
        }
    } else {
        return Err(AuthError::bad_request(
            "Either memberId or email must be provided",
        ));
    };

    // Verify target is in same organization
    if target_member.organization_id != org_id {
        return Err(AuthError::bad_request("Member not in this organization"));
    }

    // Check if user is trying to remove themselves (allowed without permission)
    let is_self_removal = target_member.user_id == user.id;

    if !is_self_removal {
        // Check permission for removing others
        if !has_permission_any(
            &requester_member.role,
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
    if target_member.role.contains("owner") {
        let all_members = ctx.database.list_organization_members(&org_id).await?;
        let owner_count = all_members
            .iter()
            .filter(|m| m.role.contains("owner"))
            .count();

        if owner_count <= 1 {
            return Err(AuthError::bad_request(
                "Cannot remove the last owner from an organization",
            ));
        }
    }

    // Delete member by member_id
    ctx.database.delete_member(&target_member.id).await?;

    Ok(AuthResponse::json(200, &SuccessResponse { success: true })?)
}

/// Handle update member role request
pub async fn handle_update_member_role(
    req: &AuthRequest,
    ctx: &AuthContext,
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
        .get_member(&org_id, &user.id)
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    // Check permission
    if !has_permission_any(
        &requester_member.role,
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
    if target_member.organization_id != org_id {
        return Err(AuthError::bad_request("Member not in this organization"));
    }

    // Prevent demoting the last owner
    if target_member.role.contains("owner") && !body.role.contains("owner") {
        let all_members = ctx.database.list_organization_members(&org_id).await?;
        let owner_count = all_members
            .iter()
            .filter(|m| m.role.contains("owner"))
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

    // Return updated member with user info
    if let Some(user_info) = ctx.database.get_user_by_id(&updated.user_id).await? {
        let member_with_user = MemberWithUser {
            id: updated.id,
            organization_id: updated.organization_id,
            user_id: updated.user_id,
            role: updated.role,
            created_at: updated.created_at,
            user: better_auth_core::types::MemberUser {
                id: user_info.id,
                name: user_info.name,
                email: user_info.email,
                image: user_info.image,
            },
        };

        return Ok(AuthResponse::json(200, &member_with_user)?);
    }

    Ok(AuthResponse::json(200, &updated)?)
}

/// Helper function to parse query parameters into a struct
fn parse_query<T: Default + serde::de::DeserializeOwned>(
    query: &std::collections::HashMap<String, String>,
) -> T {
    let json_value =
        serde_json::to_value(query).unwrap_or(serde_json::Value::Object(Default::default()));
    serde_json::from_value(json_value).unwrap_or_default()
}
