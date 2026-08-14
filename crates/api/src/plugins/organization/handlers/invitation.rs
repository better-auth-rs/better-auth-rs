use better_auth_core::entity::{
    AuthInvitation, AuthMember, AuthOrganization, AuthSession, AuthUser,
};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::types::{
    AuthRequest, AuthResponse, CreateInvitation, CreateMember, InvitationStatus,
};
use better_auth_core::wire::InvitationView;
use std::collections::HashMap;

use super::{require_session, resolve_organization_id};
use crate::plugins::organization::OrganizationConfig;
use crate::plugins::organization::rbac::{Action, Resource, has_permission_any};
use crate::plugins::organization::types::{
    AcceptInvitationRequest, AcceptInvitationResponse, BasicMemberResponse,
    CancelInvitationRequest, GetInvitationQuery, GetInvitationResponse, InviteMemberRequest,
    ListInvitationsQuery, RejectInvitationRequest, UserInvitationResponse,
};

fn normalized_roles(input: &crate::plugins::organization::types::RoleInput) -> String {
    input.joined()
}

fn requested_roles(input: &crate::plugins::organization::types::RoleInput) -> Vec<&str> {
    input.roles()
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

pub(crate) async fn invite_member_core(
    body: &InviteMemberRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<InvitationView> {
    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, session, ctx).await?;

    let member = ctx
        .database
        .get_member(&org_id, &user.id())
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

    let roles = requested_roles(&body.role);
    if roles.is_empty() {
        return Err(AuthError::bad_request("Role is required"));
    }

    let mut valid_roles = vec![config.creator_role.as_str(), "admin", "member"];
    valid_roles.extend(config.roles.keys().map(String::as_str));

    let unknown_roles: Vec<_> = roles
        .iter()
        .copied()
        .filter(|role| !valid_roles.contains(role))
        .collect();

    if !unknown_roles.is_empty() {
        return Err(AuthError::bad_request(format!(
            "Role not found: {}",
            unknown_roles.join(", ")
        )));
    }

    let member_is_creator = member
        .role()
        .split(',')
        .map(str::trim)
        .any(|role| role == config.creator_role);
    let invites_creator_role = roles.iter().any(|role| *role == config.creator_role);

    if invites_creator_role && !member_is_creator {
        return Err(AuthError::forbidden(
            "You are not allowed to invite a user with this role",
        ));
    }

    if let Some(limit) = config.membership_limit {
        let members = ctx.database.count_organization_members(&org_id).await? as usize;
        if members >= limit {
            return Err(AuthError::bad_request(format!(
                "Membership limit of {} reached",
                limit
            )));
        }
    }

    if let Some(limit) = config.invitation_limit {
        let pending_count = ctx
            .database
            .count_pending_organization_invitations(&org_id)
            .await? as usize;
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
            .get_member(&org_id, &existing_user.id())
            .await?
            .is_some()
    {
        return Err(AuthError::bad_request(
            "User is already a member of this organization",
        ));
    }

    if let Some(existing) = ctx
        .database
        .get_pending_invitation(&org_id, &body.email)
        .await?
    {
        return Ok(InvitationView::from(&existing));
    }

    let expires_at =
        chrono::Utc::now() + chrono::Duration::seconds(config.invitation_expires_in as i64);

    let invitation_data = CreateInvitation {
        organization_id: org_id,
        email: body.email.to_lowercase(),
        role: normalized_roles(&body.role),
        inviter_id: user.id().to_string(),
        expires_at,
    };

    let invitation = ctx.database.create_invitation(invitation_data).await?;
    Ok(InvitationView::from(&invitation))
}

pub(crate) async fn get_invitation_core(
    query: &GetInvitationQuery,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<GetInvitationResponse<InvitationView>> {
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
        .get_organization_by_id(&invitation.organization_id())
        .await?
        .ok_or_else(|| AuthError::not_found("Organization not found"))?;

    let inviter_email = if let Some(inviter) = ctx
        .database
        .get_user_by_id(&invitation.inviter_id())
        .await?
    {
        inviter.email().map(str::to_owned)
    } else {
        None
    };

    Ok(GetInvitationResponse {
        invitation: InvitationView::from(&invitation),
        organization_name: organization.name().to_string(),
        organization_slug: organization.slug().to_string(),
        inviter_email,
    })
}

pub(crate) async fn list_invitations_core(
    query: &ListInvitationsQuery,
    user: &impl AuthUser,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<InvitationView>> {
    let org_id =
        resolve_organization_id(query.organization_id.as_deref(), None, session, ctx).await?;

    let _ = ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    let invitations = ctx.database.list_organization_invitations(&org_id).await?;
    Ok(invitations.iter().map(InvitationView::from).collect())
}

pub(crate) async fn list_user_invitations_core(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<UserInvitationResponse<InvitationView>>> {
    let user_email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User has no email"))?;

    let all_invitations = ctx.database.list_user_invitations(user_email).await?;
    let organization_ids = all_invitations
        .iter()
        .map(|invitation| invitation.organization_id().into_owned())
        .collect::<Vec<_>>();
    let organizations_by_id = ctx
        .database
        .list_organizations_by_ids(&organization_ids)
        .await?
        .into_iter()
        .map(|organization| {
            let organization_id = organization.id.clone();
            (organization_id, organization)
        })
        .collect::<HashMap<_, _>>();
    let mut pending = Vec::with_capacity(all_invitations.len());

    for invitation in all_invitations.iter() {
        let organization = organizations_by_id
            .get(invitation.organization_id().as_ref())
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;

        pending.push(UserInvitationResponse {
            invitation: InvitationView::from(invitation),
            organization_name: organization.name().to_string(),
        });
    }

    Ok(pending)
}

pub(crate) async fn accept_invitation_core(
    body: &AcceptInvitationRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AcceptInvitationResponse<InvitationView, BasicMemberResponse>> {
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

    if !invitation.is_pending() || invitation.is_expired() {
        return Err(AuthError::bad_request("Invitation not found"));
    }

    if let Some(limit) = config.membership_limit {
        let members = ctx
            .database
            .list_organization_members(invitation.organization_id().as_ref())
            .await?;
        if members.len() >= limit {
            return Err(AuthError::bad_request(
                "Organization membership limit reached",
            ));
        }
    }

    if ctx
        .database
        .get_member(invitation.organization_id().as_ref(), &user.id())
        .await?
        .is_some()
    {
        let _ = ctx
            .database
            .update_invitation_status(&invitation.id(), InvitationStatus::Accepted)
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
        .update_invitation_status(&invitation.id(), InvitationStatus::Accepted)
        .await?;

    let _ = ctx
        .database
        .update_session_active_organization(
            session.token(),
            Some(invitation.organization_id().as_ref()),
        )
        .await?;

    Ok(AcceptInvitationResponse {
        invitation: InvitationView::from(&updated_invitation),
        member: BasicMemberResponse::from_member(&member),
    })
}

pub(crate) async fn reject_invitation_core(
    body: &RejectInvitationRequest,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AcceptInvitationResponse<InvitationView, Option<BasicMemberResponse>>> {
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
        return Err(AuthError::bad_request("Invitation not found"));
    }

    let updated_invitation = ctx
        .database
        .update_invitation_status(&invitation.id(), InvitationStatus::Rejected)
        .await?;

    Ok(AcceptInvitationResponse {
        invitation: InvitationView::from(&updated_invitation),
        member: None,
    })
}

pub(crate) async fn cancel_invitation_core(
    body: &CancelInvitationRequest,
    user: &impl AuthUser,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<InvitationView> {
    let invitation = ctx
        .database
        .get_invitation_by_id(&body.invitation_id)
        .await?
        .ok_or_else(|| AuthError::not_found("Invitation not found"))?;

    let member = ctx
        .database
        .get_member(invitation.organization_id().as_ref(), &user.id())
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
        return Err(AuthError::bad_request("Invitation not found"));
    }

    let updated_invitation = ctx
        .database
        .update_invitation_status(&invitation.id(), InvitationStatus::Canceled)
        .await?;

    Ok(InvitationView::from(&updated_invitation))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn handle_invite_member(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: InviteMemberRequest = match better_auth_core::validate_request_body(req) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let invitation = invite_member_core(&body, &user, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &invitation)?)
}

pub async fn handle_get_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let query = parse_query::<GetInvitationQuery>(&req.query);
    let response = get_invitation_core(&query, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

pub async fn handle_list_invitations(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let query = parse_query::<ListInvitationsQuery>(&req.query);
    let invitations = list_invitations_core(&query, &user, &session, ctx).await?;
    Ok(AuthResponse::json(200, &invitations)?)
}

pub async fn handle_list_user_invitations(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let invitations = list_user_invitations_core(&user, ctx).await?;
    Ok(AuthResponse::json(200, &invitations)?)
}

pub async fn handle_accept_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: AcceptInvitationRequest = match better_auth_core::validate_request_body(req) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let response = accept_invitation_core(&body, &user, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

pub async fn handle_reject_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: RejectInvitationRequest = match better_auth_core::validate_request_body(req) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let response = reject_invitation_core(&body, &user, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

pub async fn handle_cancel_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: CancelInvitationRequest = match better_auth_core::validate_request_body(req) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let response = cancel_invitation_core(&body, &user, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

fn parse_query<T: Default + serde::de::DeserializeOwned>(
    query: &std::collections::HashMap<String, String>,
) -> T {
    let json_value =
        serde_json::to_value(query).unwrap_or(serde_json::Value::Object(Default::default()));
    serde_json::from_value(json_value).unwrap_or_default()
}
