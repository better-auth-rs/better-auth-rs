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
use crate::plugins::organization::rbac::check_permission;
use crate::plugins::organization::types::{
    AcceptInvitationRequest, AcceptInvitationResponse, BasicMemberResponse,
    CancelInvitationRequest, GetInvitationQuery, GetInvitationResponse, InviteMemberRequest,
    ListInvitationsQuery, RejectInvitationRequest, UserInvitationResponse,
};
use crate::plugins::organization::{InvitationEmail, OrganizationConfig};

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

    if !check_permission(
        member.role(),
        &org_id,
        "invitation",
        &["create"],
        config,
        ctx,
    )
    .await?
    {
        return Err(AuthError::forbidden(
            "You don't have permission to invite members",
        ));
    }

    let roles = requested_roles(&body.role);
    if roles.is_empty() {
        return Err(AuthError::bad_request("Role is required"));
    }

    let dynamic_roles = if config.dynamic_access_control {
        ctx.database.list_organization_roles(&org_id).await?
    } else {
        Vec::new()
    };
    let mut valid_roles: Vec<&str> = vec!["owner", "admin", "member"];
    valid_roles.extend(config.roles.keys().map(String::as_str));
    valid_roles.extend(dynamic_roles.iter().map(|role| role.role.as_str()));

    let unknown_roles: Vec<_> = roles
        .iter()
        .copied()
        .filter(|role| !valid_roles.contains(role))
        .collect();

    if !unknown_roles.is_empty() {
        // Upstream's invite path throws `new APIError` with the code inlined in
        // the message and no `code` field — unlike the member path, which sets
        // both. See organization/routes/crud-invites.ts.
        return Err(AuthError::bad_request(format!(
            "ROLE_NOT_FOUND: {}",
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

    let existing = ctx
        .database
        .get_pending_invitation(&org_id, &body.email)
        .await?;
    if existing.is_some() && !body.resend {
        return Err(AuthError::bad_request(
            "User is already invited to this organization",
        ));
    }
    let organization = ctx
        .database
        .get_organization_by_id(&org_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let expires_at =
        chrono::Utc::now() + chrono::Duration::seconds(config.invitation_expires_in as i64);
    let invitation = if let Some(existing) = existing {
        ctx.database
            .update_invitation_expiry(&existing.id(), expires_at)
            .await?
    } else {
        if let Some(limit) = config.invitation_limit {
            let count = ctx
                .database
                .count_pending_organization_invitations(&org_id)
                .await? as usize;
            if count >= limit {
                return Err(AuthError::forbidden("Invitation limit reached"));
            }
        }
        let team_ids: Vec<&str> = match &body.team_id {
            Some(crate::plugins::organization::types::RoleInput::One(id)) => vec![id],
            Some(crate::plugins::organization::types::RoleInput::Many(ids)) => {
                ids.iter().map(String::as_str).collect()
            }
            None => Vec::new(),
        };
        if config.teams.enabled {
            for team_id in &team_ids {
                if team_id.contains(',') {
                    return Err(AuthError::bad_request(
                        "Team id contains a reserved character",
                    ));
                }
                let _ = super::team::find_team(team_id, &org_id, ctx).await?;
                if let Some(limit) = config.teams.maximum_members_per_team
                    && ctx.database.list_team_members(team_id).await?.len() >= limit
                {
                    return Err(AuthError::forbidden("Team member limit reached"));
                }
            }
        }
        ctx.database
            .create_invitation(CreateInvitation {
                team_id: if team_ids.is_empty() {
                    None
                } else {
                    Some(team_ids.join(","))
                },
                organization_id: org_id,
                email: body.email.to_lowercase(),
                role: normalized_roles(&body.role),
                inviter_id: user.id().to_string(),
                expires_at,
            })
            .await?
    };
    let invitation = InvitationView::from(&invitation);
    if let Some(sender) = &config.send_invitation_email
        && let Err(error) = sender
            .send(&InvitationEmail {
                invitation: invitation.clone(),
                organization: better_auth_core::wire::OrganizationView::from(&organization),
                member,
                inviter: ctx.user_view(user)?,
            })
            .await
    {
        // Upstream runInBackgroundOrAwait logs delivery failures and preserves success.
        tracing::error!(%error, "Failed to send organization invitation email");
    }
    Ok(invitation)
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
    // Upstream refuses to list invitations for a session whose email is not
    // verified, so an unverified address cannot enumerate what it was invited to.
    if !user.email_verified() {
        return Err(AuthError::forbidden(
            "Email verification required to view or list invitations for the session email",
        ));
    }

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
) -> AuthResult<(
    AcceptInvitationResponse<InvitationView, BasicMemberResponse>,
    Option<better_auth_core::wire::SessionView>,
)> {
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

    if config.teams.enabled {
        let (member, snapshot) = ctx
            .database
            .accept_invitation_with_teams(
                &invitation.id(),
                &user.id(),
                session.token(),
                config.teams.maximum_members_per_team,
            )
            .await?;
        let mut accepted = InvitationView::from(&invitation);
        accepted.status = InvitationStatus::Accepted;
        let snapshot = snapshot
            .as_ref()
            .map(|session| {
                better_auth_core::wire::SessionView::with_fields(session, &ctx.config.session)
            })
            .transpose()?;
        return Ok((
            AcceptInvitationResponse {
                invitation: accepted,
                member: BasicMemberResponse::from_member(&member),
            },
            snapshot,
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

    Ok((
        AcceptInvitationResponse {
            invitation: InvitationView::from(&updated_invitation),
            member: BasicMemberResponse::from_member(&member),
        },
        None,
    ))
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

    if !check_permission(
        member.role(),
        invitation.organization_id().as_ref(),
        "invitation",
        &["cancel"],
        config,
        ctx,
    )
    .await?
    {
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
    let (response, snapshot) = accept_invitation_core(&body, &user, &session, config, ctx).await?;
    let mut response = AuthResponse::json(200, &response)?;
    if let Some(snapshot) = snapshot {
        response = super::team::with_session_cookie(response, req, session.token(), ctx);
        let manager = ctx.session_manager();
        // Upstream writes the team cookie before updating the active organization in the transaction.
        manager
            .write_cache(
                req,
                &better_auth_core::session::SessionData {
                    session: snapshot,
                    user,
                },
                manager.dont_remember(req),
            )
            .await?;
        // Preserve the explicit snapshot when response finalization processes the credential cookie.
        for (name, value) in req.take_response_headers()? {
            response.headers.append(name, value);
        }
    }
    Ok(response)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers::{create_test_context, create_user_and_session};
    use better_auth_core::{CreateOrganization, CreateUser};
    use chrono::Duration;

    #[tokio::test]
    async fn resend_renews_existing_invitation_when_pending_limit_is_reached() {
        let ctx = create_test_context().await;
        let (user, session) = create_user_and_session(
            &ctx,
            CreateUser {
                email: Some("owner@example.com".into()),
                ..Default::default()
            },
            Duration::hours(1),
        )
        .await;
        let organization = ctx
            .database
            .create_organization(CreateOrganization {
                id: None,
                name: "Organization".into(),
                slug: "resend-limit".into(),
                logo: None,
                metadata: None,
            })
            .await
            .unwrap();
        ctx.database
            .create_member(CreateMember {
                organization_id: organization.id.clone(),
                user_id: user.id.clone(),
                role: "owner".into(),
            })
            .await
            .unwrap();
        let config = OrganizationConfig {
            invitation_limit: Some(1),
            ..Default::default()
        };
        let mut body: InviteMemberRequest = serde_json::from_value(serde_json::json!({
            "organizationId": organization.id, "email": "invitee@example.com", "role": "member",
        }))
        .unwrap();
        let first = invite_member_core(&body, &user, &session, &config, &ctx)
            .await
            .unwrap();
        let shortened = first.expires_at - Duration::hours(1);
        ctx.database
            .update_invitation_expiry(&first.id, shortened)
            .await
            .unwrap();
        body.resend = true;
        let resent = invite_member_core(&body, &user, &session, &config, &ctx)
            .await
            .unwrap();
        assert_eq!(resent.id, first.id);
        assert!(resent.expires_at > shortened);
        assert_eq!(
            ctx.database
                .get_invitation_by_id(&first.id)
                .await
                .unwrap()
                .unwrap()
                .expires_at,
            resent.expires_at
        );
        body.email = "another@example.com".into();
        let error = invite_member_core(&body, &user, &session, &config, &ctx)
            .await
            .unwrap_err();
        assert_eq!(error.status_code(), 403);
        assert!(error.to_string().contains("Invitation limit reached"));
    }
}
