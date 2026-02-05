use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::types::{
    AuthRequest, AuthResponse, CreateMember, CreateOrganization, FullOrganization,
    MemberWithUser, UpdateOrganization,
};

use super::{require_session, resolve_organization_id};
use crate::plugins::organization::config::OrganizationConfig;
use crate::plugins::organization::rbac::{has_permission_any, Action, Resource};
use crate::plugins::organization::types::{
    CheckSlugRequest, CheckSlugResponse, CreateOrganizationRequest, CreateOrganizationResponse,
    DeleteOrganizationRequest, GetFullOrganizationQuery, LeaveOrganizationRequest,
    SetActiveOrganizationRequest, SuccessResponse, UpdateOrganizationRequest,
};

/// Handle create organization request
pub async fn handle_create_organization(
    req: &AuthRequest,
    ctx: &AuthContext,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: CreateOrganizationRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };

    // Check if user can create organizations
    if !config.allow_user_to_create_organization {
        return Err(AuthError::forbidden(
            "Organization creation is not allowed",
        ));
    }

    // Check organization limit
    if let Some(limit) = config.organization_limit {
        let user_orgs = ctx.database.list_user_organizations(&user.id).await?;
        if user_orgs.len() >= limit {
            return Err(AuthError::bad_request(&format!(
                "Organization limit of {} reached",
                limit
            )));
        }
    }

    // Check if slug is available
    if ctx
        .database
        .get_organization_by_slug(&body.slug)
        .await?
        .is_some()
    {
        return Err(AuthError::bad_request("Slug is already taken"));
    }

    // Create organization
    let org_data = CreateOrganization {
        id: None,
        name: body.name,
        slug: body.slug,
        logo: body.logo,
        metadata: body.metadata,
    };

    let organization = ctx.database.create_organization(org_data).await?;

    // Add creator as first member with creator role
    let member_data = CreateMember {
        organization_id: organization.id.clone(),
        user_id: user.id.clone(),
        role: config.creator_role.clone(),
    };

    let member = ctx.database.create_member(member_data).await?;

    // Create MemberWithUser for response
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

    let response = CreateOrganizationResponse {
        organization,
        members: vec![member_with_user],
    };

    Ok(AuthResponse::json(200, &response)?)
}

/// Handle update organization request
pub async fn handle_update_organization(
    req: &AuthRequest,
    ctx: &AuthContext,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: UpdateOrganizationRequest = req.body_as_json().map_err(|e| {
        AuthError::bad_request(&format!("Invalid request body: {}", e))
    })?;

    let org_id = resolve_organization_id(
        body.organization_id.as_deref(),
        None,
        &session,
        ctx,
    )
    .await?;

    // Check permission
    let member = ctx
        .database
        .get_member(&org_id, &user.id)
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    if !has_permission_any(
        &member.role,
        &Resource::Organization,
        &Action::Update,
        &config.roles,
    ) {
        return Err(AuthError::forbidden(
            "You don't have permission to update this organization",
        ));
    }

    // Check if new slug is available (if changing)
    if let Some(ref new_slug) = body.slug {
        if let Some(existing) = ctx.database.get_organization_by_slug(new_slug).await? {
            if existing.id != org_id {
                return Err(AuthError::bad_request("Slug is already taken"));
            }
        }
    }

    // Update organization
    let update_data = UpdateOrganization {
        name: body.name,
        slug: body.slug,
        logo: body.logo,
        metadata: body.metadata,
    };

    let updated = ctx
        .database
        .update_organization(&org_id, update_data)
        .await?;

    Ok(AuthResponse::json(200, &updated)?)
}

/// Handle delete organization request
pub async fn handle_delete_organization(
    req: &AuthRequest,
    ctx: &AuthContext,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: DeleteOrganizationRequest = req.body_as_json().map_err(|e| {
        AuthError::bad_request(&format!("Invalid request body: {}", e))
    })?;

    // Check if deletion is allowed
    if config.disable_organization_deletion {
        return Err(AuthError::forbidden("Organization deletion is disabled"));
    }

    // Check permission
    let member = ctx
        .database
        .get_member(&body.organization_id, &user.id)
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    if !has_permission_any(
        &member.role,
        &Resource::Organization,
        &Action::Delete,
        &config.roles,
    ) {
        return Err(AuthError::forbidden(
            "You don't have permission to delete this organization",
        ));
    }

    // Delete organization (cascade deletes members and invitations)
    ctx.database
        .delete_organization(&body.organization_id)
        .await?;

    Ok(AuthResponse::json(200, &SuccessResponse { success: true })?)
}

/// Handle list organizations request
pub async fn handle_list_organizations(
    req: &AuthRequest,
    ctx: &AuthContext,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;

    let organizations = ctx.database.list_user_organizations(&user.id).await?;

    Ok(AuthResponse::json(200, &organizations)?)
}

/// Handle get full organization request
pub async fn handle_get_full_organization(
    req: &AuthRequest,
    ctx: &AuthContext,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;

    // Parse query parameters
    let query = parse_query::<GetFullOrganizationQuery>(&req.query);

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

    // Get organization
    let organization = ctx
        .database
        .get_organization_by_id(&org_id)
        .await?
        .ok_or_else(|| AuthError::not_found("Organization not found"))?;

    // Get all members with user info
    let members_raw = ctx.database.list_organization_members(&org_id).await?;
    let mut members = Vec::with_capacity(members_raw.len());

    for member in members_raw {
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

    // Get invitations
    let invitations = ctx.database.list_organization_invitations(&org_id).await?;

    let response = FullOrganization {
        organization,
        members,
        invitations,
    };

    Ok(AuthResponse::json(200, &response)?)
}

/// Handle check slug request
pub async fn handle_check_slug(req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
    let _session = require_session(req, ctx).await?;
    let body: CheckSlugRequest = req.body_as_json().map_err(|e| {
        AuthError::bad_request(&format!("Invalid request body: {}", e))
    })?;

    let exists = ctx
        .database
        .get_organization_by_slug(&body.slug)
        .await?
        .is_some();

    let response = CheckSlugResponse { status: !exists };

    Ok(AuthResponse::json(200, &response)?)
}

/// Handle set active organization request
pub async fn handle_set_active_organization(
    req: &AuthRequest,
    ctx: &AuthContext,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: SetActiveOrganizationRequest = req.body_as_json().map_err(|e| {
        AuthError::bad_request(&format!("Invalid request body: {}", e))
    })?;

    // Resolve organization
    let org_id = if body.organization_id.is_some() || body.organization_slug.is_some() {
        Some(
            resolve_organization_id(
                body.organization_id.as_deref(),
                body.organization_slug.as_deref(),
                &session,
                ctx,
            )
            .await?,
        )
    } else {
        None
    };

    // If org_id is provided, verify membership
    if let Some(ref oid) = org_id {
        ctx.database
            .get_member(oid, &user.id)
            .await?
            .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;
    }

    // Update session with new active organization
    let updated_session = ctx
        .database
        .update_session_active_organization(&session.token, org_id.as_deref())
        .await?;

    Ok(AuthResponse::json(200, &updated_session)?)
}

/// Handle leave organization request
pub async fn handle_leave_organization(
    req: &AuthRequest,
    ctx: &AuthContext,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: LeaveOrganizationRequest = req.body_as_json().map_err(|e| {
        AuthError::bad_request(&format!("Invalid request body: {}", e))
    })?;

    // Check membership
    let member = ctx
        .database
        .get_member(&body.organization_id, &user.id)
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    // Check if user is the last owner
    if member.role.contains("owner") {
        let all_members = ctx
            .database
            .list_organization_members(&body.organization_id)
            .await?;
        let owner_count = all_members
            .iter()
            .filter(|m| m.role.contains("owner"))
            .count();

        if owner_count <= 1 {
            return Err(AuthError::bad_request(
                "Cannot leave organization as the last owner. Delete the organization or transfer ownership first.",
            ));
        }
    }

    // Remove member by member_id
    ctx.database.delete_member(&member.id).await?;

    // Clear active organization if it was the one being left
    if session.active_organization_id.as_deref() == Some(&body.organization_id) {
        ctx.database
            .update_session_active_organization(&session.token, None)
            .await?;
    }

    Ok(AuthResponse::json(200, &SuccessResponse { success: true })?)
}

/// Helper function to parse query parameters into a struct
fn parse_query<T: Default + serde::de::DeserializeOwned>(
    query: &std::collections::HashMap<String, String>,
) -> T {
    // Convert HashMap<String, String> to serde_json::Value for deserialization
    let json_value = serde_json::to_value(query).unwrap_or(serde_json::Value::Object(Default::default()));
    serde_json::from_value(json_value).unwrap_or_default()
}

impl Default for GetFullOrganizationQuery {
    fn default() -> Self {
        Self {
            organization_id: None,
            organization_slug: None,
        }
    }
}
