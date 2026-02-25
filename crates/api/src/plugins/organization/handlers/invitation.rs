use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{
    AuthInvitation, AuthMember, AuthOrganization, AuthSession, AuthUser,
};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::types::{
    AuthRequest, AuthResponse, CreateInvitation, CreateMember, InvitationStatus,
};

use super::{require_session, resolve_organization_id};
use crate::plugins::organization::config::OrganizationConfig;
use crate::plugins::organization::rbac::{Action, Resource, has_permission_any};
use crate::plugins::organization::types::{
    AcceptInvitationRequest, AcceptInvitationResponse, CancelInvitationRequest, GetInvitationQuery,
    GetInvitationResponse, InviteMemberRequest, ListInvitationsQuery, MemberResponse,
    RejectInvitationRequest, SuccessResponse,
};

/// Handle invite member request
pub async fn handle_invite_member<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: InviteMemberRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };

    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, &session, ctx).await?;

    // Check permission
    let member = ctx
        .database
        .get_member(&org_id, user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    if !has_permission_any(
        member.role(),
        &Resource::Invitation,
        &Action::Create,
        &config.roles,
    ) {
        return Err(AuthError::forbidden(
            "You don't have permission to invite members",
        ));
    }

    // Check membership limit
    if let Some(limit) = config.membership_limit {
        let members = ctx.database.list_organization_members(&org_id).await?;
        if members.len() >= limit {
            return Err(AuthError::bad_request(format!(
                "Membership limit of {} reached",
                limit
            )));
        }
    }

    // Check invitation limit
    if let Some(limit) = config.invitation_limit {
        let invitations = ctx.database.list_organization_invitations(&org_id).await?;
        let pending_count = invitations.iter().filter(|i| i.is_pending()).count();
        if pending_count >= limit {
            return Err(AuthError::bad_request(format!(
                "Pending invitation limit of {} reached",
                limit
            )));
        }
    }

    // Check if user is already a member
    if let Some(existing_user) = ctx.database.get_user_by_email(&body.email).await?
        && ctx
            .database
            .get_member(&org_id, existing_user.id())
            .await?
            .is_some()
    {
        return Err(AuthError::bad_request("User is already a member"));
    }

    // Check for existing pending invitation
    if let Some(existing) = ctx
        .database
        .get_pending_invitation(&org_id, &body.email)
        .await?
    {
        // Return existing invitation (flat, per spec)
        return Ok(AuthResponse::json(200, &existing)?);
    }

    // Calculate expiration
    let expires_at =
        chrono::Utc::now() + chrono::Duration::seconds(config.invitation_expires_in as i64);

    // Create invitation
    let invitation_data = CreateInvitation {
        organization_id: org_id.clone(),
        email: body.email,
        role: body.role,
        inviter_id: user.id().to_string(),
        expires_at,
    };

    let invitation = ctx.database.create_invitation(invitation_data).await?;

    // Return flat invitation object per spec
    Ok(AuthResponse::json(200, &invitation)?)
}

/// Handle get invitation request
pub async fn handle_get_invitation<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    // This endpoint can be accessed without authentication (for invitation links)
    let query = parse_query::<GetInvitationQuery>(&req.query);

    if query.id.is_empty() {
        return Err(AuthError::bad_request("Missing invitation id"));
    }

    let invitation = ctx
        .database
        .get_invitation_by_id(&query.id)
        .await?
        .ok_or_else(|| AuthError::not_found("Invitation not found"))?;

    // Get organization info
    let organization = ctx
        .database
        .get_organization_by_id(invitation.organization_id())
        .await?
        .ok_or_else(|| AuthError::not_found("Organization not found"))?;

    // Get inviter info
    let inviter_email =
        if let Some(inviter) = ctx.database.get_user_by_id(invitation.inviter_id()).await? {
            inviter.email().map(|s| s.to_string())
        } else {
            None
        };

    let response = GetInvitationResponse {
        invitation,
        organization_name: organization.name().to_string(),
        organization_slug: organization.slug().to_string(),
        inviter_email,
    };

    Ok(AuthResponse::json(200, &response)?)
}

/// Handle list invitations request
pub async fn handle_list_invitations<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;

    let query = parse_query::<ListInvitationsQuery>(&req.query);

    let org_id =
        resolve_organization_id(query.organization_id.as_deref(), None, &session, ctx).await?;

    // Check membership
    ctx.database
        .get_member(&org_id, user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    let invitations = ctx.database.list_organization_invitations(&org_id).await?;

    Ok(AuthResponse::json(200, &invitations)?)
}

/// Handle list user invitations request (invitations for the current user's email)
pub async fn handle_list_user_invitations<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;

    let user_email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User has no email"))?;

    // Get all pending invitations for user's email
    let all_invitations = ctx.database.list_user_invitations(user_email).await?;

    // Filter only pending and non-expired
    let pending: Vec<_> = all_invitations
        .into_iter()
        .filter(|i| i.is_pending() && !i.is_expired())
        .collect();

    Ok(AuthResponse::json(200, &pending)?)
}

/// Handle accept invitation request
pub async fn handle_accept_invitation<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: AcceptInvitationRequest = req
        .body_as_json()
        .map_err(|e| AuthError::bad_request(format!("Invalid request body: {}", e)))?;

    let invitation = ctx
        .database
        .get_invitation_by_id(&body.invitation_id)
        .await?
        .ok_or_else(|| AuthError::not_found("Invitation not found"))?;

    let user_email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User has no email"))?;

    // Verify invitation is for this user
    if invitation.email().to_lowercase() != user_email.to_lowercase() {
        return Err(AuthError::forbidden("This invitation is not for you"));
    }

    // Check if invitation is still pending
    if !invitation.is_pending() {
        return Err(AuthError::bad_request(format!(
            "Invitation is {:?}",
            invitation.status()
        )));
    }

    // Check if invitation has expired
    if invitation.is_expired() {
        return Err(AuthError::bad_request("Invitation has expired"));
    }

    // Check membership limit
    if let Some(limit) = config.membership_limit {
        let members = ctx
            .database
            .list_organization_members(invitation.organization_id())
            .await?;
        if members.len() >= limit {
            return Err(AuthError::bad_request(
                "Organization membership limit reached",
            ));
        }
    }

    // Check if already a member
    if ctx
        .database
        .get_member(invitation.organization_id(), user.id())
        .await?
        .is_some()
    {
        // Already a member, just update invitation status
        ctx.database
            .update_invitation_status(invitation.id(), InvitationStatus::Accepted)
            .await?;
        return Err(AuthError::bad_request(
            "Already a member of this organization",
        ));
    }

    // Create member
    let member_data = CreateMember {
        organization_id: invitation.organization_id().to_string(),
        user_id: user.id().to_string(),
        role: invitation.role().to_string(),
    };

    let member = ctx.database.create_member(member_data).await?;

    // Update invitation status
    let updated_invitation = ctx
        .database
        .update_invitation_status(invitation.id(), InvitationStatus::Accepted)
        .await?;

    // Set as active organization
    ctx.database
        .update_session_active_organization(session.token(), Some(invitation.organization_id()))
        .await?;

    let member_response = MemberResponse::from_member_and_user(&member, &user);

    let response = AcceptInvitationResponse {
        invitation: updated_invitation,
        member: member_response,
    };

    Ok(AuthResponse::json(200, &response)?)
}

/// Handle reject invitation request
pub async fn handle_reject_invitation<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: RejectInvitationRequest = req
        .body_as_json()
        .map_err(|e| AuthError::bad_request(format!("Invalid request body: {}", e)))?;

    let invitation = ctx
        .database
        .get_invitation_by_id(&body.invitation_id)
        .await?
        .ok_or_else(|| AuthError::not_found("Invitation not found"))?;

    let user_email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User has no email"))?;

    // Verify invitation is for this user
    if invitation.email().to_lowercase() != user_email.to_lowercase() {
        return Err(AuthError::forbidden("This invitation is not for you"));
    }

    // Check if invitation is still pending
    if !invitation.is_pending() {
        return Err(AuthError::bad_request(format!(
            "Invitation is already {:?}",
            invitation.status()
        )));
    }

    // Update status
    ctx.database
        .update_invitation_status(invitation.id(), InvitationStatus::Rejected)
        .await?;

    Ok(AuthResponse::json(200, &SuccessResponse { success: true })?)
}

/// Handle cancel invitation request
pub async fn handle_cancel_invitation<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: CancelInvitationRequest = req
        .body_as_json()
        .map_err(|e| AuthError::bad_request(format!("Invalid request body: {}", e)))?;

    let invitation = ctx
        .database
        .get_invitation_by_id(&body.invitation_id)
        .await?
        .ok_or_else(|| AuthError::not_found("Invitation not found"))?;

    // Check permission
    let member = ctx
        .database
        .get_member(invitation.organization_id(), user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    if !has_permission_any(
        member.role(),
        &Resource::Invitation,
        &Action::Cancel,
        &config.roles,
    ) {
        return Err(AuthError::forbidden(
            "You don't have permission to cancel invitations",
        ));
    }

    // Check if invitation is still pending
    if !invitation.is_pending() {
        return Err(AuthError::bad_request(format!(
            "Invitation is already {:?}",
            invitation.status()
        )));
    }

    // Update status
    ctx.database
        .update_invitation_status(invitation.id(), InvitationStatus::Canceled)
        .await?;

    Ok(AuthResponse::json(200, &SuccessResponse { success: true })?)
}

/// Helper function to parse query parameters into a struct
fn parse_query<T: Default + serde::de::DeserializeOwned>(
    query: &std::collections::HashMap<String, String>,
) -> T {
    let json_value =
        serde_json::to_value(query).unwrap_or(serde_json::Value::Object(Default::default()));
    serde_json::from_value(json_value).unwrap_or_default()
}
