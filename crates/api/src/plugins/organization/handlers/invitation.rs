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

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

pub(crate) async fn invite_member_core<DB: DatabaseAdapter>(
    body: &InviteMemberRequest,
    user: &DB::User,
    session: &DB::Session,
    config: &OrganizationConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<DB::Invitation> {
    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, session, ctx).await?;

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

    if let Some(limit) = config.membership_limit {
        let members = ctx.database.list_organization_members(&org_id).await?;
        if members.len() >= limit {
            return Err(AuthError::bad_request(format!(
                "Membership limit of {} reached",
                limit
            )));
        }
    }

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

    if let Some(existing_user) = ctx.database.get_user_by_email(&body.email).await?
        && ctx
            .database
            .get_member(&org_id, existing_user.id())
            .await?
            .is_some()
    {
        return Err(AuthError::bad_request("User is already a member"));
    }

    // Return existing pending invitation if one exists
    if let Some(existing) = ctx
        .database
        .get_pending_invitation(&org_id, &body.email)
        .await?
    {
        return Ok(existing);
    }

    let expires_at =
        chrono::Utc::now() + chrono::Duration::seconds(config.invitation_expires_in as i64);

    let invitation_data = CreateInvitation {
        organization_id: org_id.clone(),
        email: body.email.clone(),
        role: body.role.clone(),
        inviter_id: user.id().to_string(),
        expires_at,
    };

    let invitation = ctx.database.create_invitation(invitation_data).await?;

    Ok(invitation)
}

pub(crate) async fn get_invitation_core<DB: DatabaseAdapter>(
    query: &GetInvitationQuery,
    ctx: &AuthContext<DB>,
) -> AuthResult<GetInvitationResponse<DB::Invitation>> {
    if query.id.is_empty() {
        return Err(AuthError::bad_request("Missing invitation id"));
    }

    let invitation = ctx
        .database
        .get_invitation_by_id(&query.id)
        .await?
        .ok_or_else(|| AuthError::not_found("Invitation not found"))?;

    let organization = ctx
        .database
        .get_organization_by_id(invitation.organization_id())
        .await?
        .ok_or_else(|| AuthError::not_found("Organization not found"))?;

    let inviter_email =
        if let Some(inviter) = ctx.database.get_user_by_id(invitation.inviter_id()).await? {
            inviter.email().map(|s| s.to_string())
        } else {
            None
        };

    Ok(GetInvitationResponse {
        invitation,
        organization_name: organization.name().to_string(),
        organization_slug: organization.slug().to_string(),
        inviter_email,
    })
}

pub(crate) async fn list_invitations_core<DB: DatabaseAdapter>(
    query: &ListInvitationsQuery,
    user: &DB::User,
    session: &DB::Session,
    ctx: &AuthContext<DB>,
) -> AuthResult<Vec<DB::Invitation>> {
    let org_id =
        resolve_organization_id(query.organization_id.as_deref(), None, session, ctx).await?;

    ctx.database
        .get_member(&org_id, user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    let invitations = ctx.database.list_organization_invitations(&org_id).await?;

    Ok(invitations)
}

pub(crate) async fn list_user_invitations_core<DB: DatabaseAdapter>(
    user: &DB::User,
    ctx: &AuthContext<DB>,
) -> AuthResult<Vec<DB::Invitation>> {
    let user_email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User has no email"))?;

    let all_invitations = ctx.database.list_user_invitations(user_email).await?;

    let pending: Vec<_> = all_invitations
        .into_iter()
        .filter(|i| i.is_pending() && !i.is_expired())
        .collect();

    Ok(pending)
}

pub(crate) async fn accept_invitation_core<DB: DatabaseAdapter>(
    body: &AcceptInvitationRequest,
    user: &DB::User,
    session: &DB::Session,
    config: &OrganizationConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<AcceptInvitationResponse<DB::Invitation>> {
    let invitation = ctx
        .database
        .get_invitation_by_id(&body.invitation_id)
        .await?
        .ok_or_else(|| AuthError::not_found("Invitation not found"))?;

    let user_email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User has no email"))?;

    if invitation.email().to_lowercase() != user_email.to_lowercase() {
        return Err(AuthError::forbidden("This invitation is not for you"));
    }

    if !invitation.is_pending() {
        return Err(AuthError::bad_request(format!(
            "Invitation is {:?}",
            invitation.status()
        )));
    }

    if invitation.is_expired() {
        return Err(AuthError::bad_request("Invitation has expired"));
    }

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

    if ctx
        .database
        .get_member(invitation.organization_id(), user.id())
        .await?
        .is_some()
    {
        ctx.database
            .update_invitation_status(invitation.id(), InvitationStatus::Accepted)
            .await?;
        return Err(AuthError::bad_request(
            "Already a member of this organization",
        ));
    }

    let member_data = CreateMember {
        organization_id: invitation.organization_id().to_string(),
        user_id: user.id().to_string(),
        role: invitation.role().to_string(),
    };

    let member = ctx.database.create_member(member_data).await?;

    let updated_invitation = ctx
        .database
        .update_invitation_status(invitation.id(), InvitationStatus::Accepted)
        .await?;

    ctx.database
        .update_session_active_organization(session.token(), Some(invitation.organization_id()))
        .await?;

    let member_response = MemberResponse::from_member_and_user(&member, user);

    Ok(AcceptInvitationResponse {
        invitation: updated_invitation,
        member: member_response,
    })
}

pub(crate) async fn reject_invitation_core<DB: DatabaseAdapter>(
    body: &RejectInvitationRequest,
    user: &DB::User,
    ctx: &AuthContext<DB>,
) -> AuthResult<SuccessResponse> {
    let invitation = ctx
        .database
        .get_invitation_by_id(&body.invitation_id)
        .await?
        .ok_or_else(|| AuthError::not_found("Invitation not found"))?;

    let user_email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User has no email"))?;

    if invitation.email().to_lowercase() != user_email.to_lowercase() {
        return Err(AuthError::forbidden("This invitation is not for you"));
    }

    if !invitation.is_pending() {
        return Err(AuthError::bad_request(format!(
            "Invitation is already {:?}",
            invitation.status()
        )));
    }

    ctx.database
        .update_invitation_status(invitation.id(), InvitationStatus::Rejected)
        .await?;

    Ok(SuccessResponse { success: true })
}

pub(crate) async fn cancel_invitation_core<DB: DatabaseAdapter>(
    body: &CancelInvitationRequest,
    user: &DB::User,
    config: &OrganizationConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<SuccessResponse> {
    let invitation = ctx
        .database
        .get_invitation_by_id(&body.invitation_id)
        .await?
        .ok_or_else(|| AuthError::not_found("Invitation not found"))?;

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

    if !invitation.is_pending() {
        return Err(AuthError::bad_request(format!(
            "Invitation is already {:?}",
            invitation.status()
        )));
    }

    ctx.database
        .update_invitation_status(invitation.id(), InvitationStatus::Canceled)
        .await?;

    Ok(SuccessResponse { success: true })
}

// ---------------------------------------------------------------------------
// Old handlers (rewritten to call core)
// ---------------------------------------------------------------------------

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
    let invitation = invite_member_core(&body, &user, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &invitation)?)
}

/// Handle get invitation request
pub async fn handle_get_invitation<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let query = parse_query::<GetInvitationQuery>(&req.query);
    let response = get_invitation_core(&query, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle list invitations request
pub async fn handle_list_invitations<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let query = parse_query::<ListInvitationsQuery>(&req.query);
    let invitations = list_invitations_core(&query, &user, &session, ctx).await?;
    Ok(AuthResponse::json(200, &invitations)?)
}

/// Handle list user invitations request
pub async fn handle_list_user_invitations<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let pending = list_user_invitations_core(&user, ctx).await?;
    Ok(AuthResponse::json(200, &pending)?)
}

/// Handle accept invitation request
pub async fn handle_accept_invitation<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: AcceptInvitationRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let response = accept_invitation_core(&body, &user, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle reject invitation request
pub async fn handle_reject_invitation<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: RejectInvitationRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let response = reject_invitation_core(&body, &user, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle cancel invitation request
pub async fn handle_cancel_invitation<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: CancelInvitationRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let response = cancel_invitation_core(&body, &user, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Helper function to parse query parameters into a struct
fn parse_query<T: Default + serde::de::DeserializeOwned>(
    query: &std::collections::HashMap<String, String>,
) -> T {
    let json_value =
        serde_json::to_value(query).unwrap_or(serde_json::Value::Object(Default::default()));
    serde_json::from_value(json_value).unwrap_or_default()
}
