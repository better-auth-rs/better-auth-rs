use better_auth_core::entity::{
    AuthInvitation, AuthMember, AuthOrganization, AuthSession, AuthUser,
};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::types::{AuthRequest, AuthResponse, InvitationStatus};
use better_auth_core::wire::InvitationView;
use std::collections::HashMap;

use super::{require_session, resolve_organization_id};
use crate::plugins::organization::rbac::check_permission;
use crate::plugins::organization::types::{
    AcceptInvitationRequest, AcceptInvitationResponse, BasicMemberResponse,
    CancelInvitationRequest, GetInvitationQuery, GetInvitationResponse, InviteMemberRequest,
    ListInvitationsQuery, RejectInvitationRequest, UserInvitationResponse,
};
use crate::plugins::organization::{InvitationEmail, OrganizationConfig, hooks::*};

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
    request: Option<&AuthRequest>,
) -> AuthResult<InvitationView> {
    let org_value = body
        .organization_id
        .json()?
        .filter(better_auth_core::user_fields::is_truthy)
        .or_else(|| {
            session
                .active_organization_id()
                .map(|id| serde_json::json!(id))
        })
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let email = crate::plugins::organization::input::string_operation(
        &body.email,
        "invitation email.toLowerCase",
    )?
    .to_lowercase();
    if !validator::ValidateEmail::validate_email(&email) {
        return Err(AuthError::bad_request("Invalid email"));
    }
    let resend = body
        .resend
        .json()?
        .as_ref()
        .is_some_and(better_auth_core::user_fields::is_truthy);

    let member = ctx
        .database
        .get_member_value(&org_value, &serde_json::json!(user.id()))
        .await?
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    let org_id = member.organization_id.typed()?.clone();

    if !check_permission(
        member.role().typed()?,
        &org_id,
        "invitation",
        &["create"],
        config,
        ctx,
    )
    .await?
    {
        return Err(AuthError::forbidden(
            "You are not allowed to invite users to this organization",
        ));
    }

    let normalized_role = crate::plugins::organization::input::parse_roles(&body.role)?;
    let normalized_role = crate::plugins::organization::input::string_operation(
        &normalized_role,
        "invitation role.split",
    )?;
    let role_input =
        crate::plugins::organization::types::RoleInput::One(normalized_role.to_owned());
    let roles = requested_roles(&role_input);

    let dynamic_roles = if config.dynamic_access_control {
        ctx.database.list_organization_roles(&org_id).await?
    } else {
        Vec::new()
    };
    let mut valid_roles: Vec<&str> = vec!["owner", "admin", "member"];
    valid_roles.extend(
        config
            .roles
            .iter()
            .flat_map(|roles| roles.keys())
            .map(String::as_str),
    );
    for role in &dynamic_roles {
        valid_roles.push(role.role.typed()?.as_str());
    }

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
        .typed()?
        .split(',')
        .map(str::trim)
        .any(|role| role == config.creator_role);
    let invites_creator_role = roles.iter().any(|role| *role == config.creator_role);

    if invites_creator_role && !member_is_creator {
        return Err(AuthError::forbidden(
            "You are not allowed to invite a user with this role",
        ));
    }

    if let Some(existing_user) = ctx.database.get_user_by_email(&email).await?
        && ctx
            .database
            .get_member(&org_id, existing_user.id().typed()?)
            .await?
            .is_some()
    {
        return Err(AuthError::bad_request(
            "User is already a member of this organization",
        ));
    }

    let existing = ctx.database.get_pending_invitation(&org_id, &email).await?;
    if existing.is_some() && !resend && !config.cancel_pending_invitations_on_re_invite {
        return Err(AuthError::bad_request(
            "User is already invited to this organization",
        ));
    }
    let organization = ctx
        .database
        .get_organization_by_id(&org_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = crate::plugins::organization::fields::organization(&organization, ctx);
    let expires_at =
        chrono::Utc::now() + chrono::Duration::seconds(config.invitation_lifetime() as i64);
    let user_view = ctx.user_view(user)?;
    let session_view = ctx.session_view(session).await?;
    let is_resend = existing.is_some() && resend;
    let invitation = if let Some(existing) = existing.as_ref().filter(|_| resend) {
        let _ = ctx
            .database
            .update_invitation_expiry(existing.id().typed()?, expires_at)
            .await?;
        let mut response = existing.clone();
        response.expires_at = expires_at.into();
        response
    } else {
        if let Some(existing) = existing {
            let _ = ctx
                .database
                .update_invitation_status(existing.id().typed()?, InvitationStatus::Canceled)
                .await?;
        }
        {
            let limit = config
                .pending_invitation_limit(
                    OrganizationMemberEvent {
                        member: &member,
                        user: &user_view,
                        organization: &organization_view,
                    },
                    OrganizationEndpoint::new(ctx, request),
                )
                .await?;
            let count = ctx
                .database
                .count_pending_organization_invitations(&org_id)
                .await? as usize;
            if count >= limit {
                return Err(AuthError::forbidden("Invitation limit reached"));
            }
        }
        let team_ids_value = body.team_id.json()?;
        let check_teams = config.teams.enabled
            && team_ids_value
                .as_ref()
                .is_some_and(better_auth_core::user_fields::is_truthy);
        let team_ids = crate::plugins::organization::input::invitation_team_ids(team_ids_value);
        if check_teams {
            let raw = team_ids
                .json()?
                .ok_or_else(|| AuthError::from(AuthResponse::new(500)))?;
            let requested = raw
                .as_array()
                .ok_or_else(|| AuthError::from(AuthResponse::new(500)))?;
            for team_id in requested {
                let reserved = match team_id {
                    serde_json::Value::String(id) => id.contains(','),
                    serde_json::Value::Array(ids) => ids.iter().any(|id| id == ","),
                    _ => return Err(AuthResponse::new(500).into()),
                };
                if reserved {
                    return Err(AuthError::bad_request(
                        "Team id contains a reserved character",
                    ));
                }
            }
            let mut teams = Vec::with_capacity(requested.len());
            for team_id in requested {
                let team = ctx
                    .database
                    .get_team_value(team_id)
                    .await?
                    .filter(|team| team.organization_id == org_id)
                    .ok_or_else(|| AuthError::bad_request("Team not found"))?;
                teams.push(team);
            }
            for team in &teams {
                let team_id = team.id.typed()?;
                let limit = config
                    .team_member_limit(OrganizationTeamMemberLimit {
                        organization_id: &org_id,
                        team_id,
                        session: OrganizationSession {
                            user: &user_view,
                            session: &session_view,
                        },
                    })
                    .await?;
                if let Some(limit) = limit
                    && ctx.database.list_team_members(team_id).await?.len() >= limit
                {
                    return Err(AuthError::forbidden("Team member limit reached"));
                }
            }
        }
        let mut draft = OrganizationInvitationDraft {
            additional_fields: body.additional_fields.clone(),
            team_id: crate::plugins::organization::input::invitation_team_alias(&team_ids)?,
            id: body
                .additional_fields
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            created_at: body
                .additional_fields
                .get("createdAt")
                .cloned()
                .map(better_auth_core::SchemaValue::Dynamic)
                .unwrap_or_default(),
            status: body
                .additional_fields
                .get("status")
                .cloned()
                .map(better_auth_core::SchemaValue::Dynamic)
                .unwrap_or_default(),
            organization_id: org_id,
            email: email.clone(),
            role: normalized_roles(&role_input),
            inviter_id: user.id().typed()?.to_string(),
            expires_at: body
                .additional_fields
                .get("expiresAt")
                .cloned()
                .map(better_auth_core::SchemaValue::Dynamic)
                .unwrap_or_default(),
            team_ids,
        };
        if let Some(hooks) = &config.hooks {
            hooks
                .before_create_invitation(
                    &mut draft,
                    OrganizationUser {
                        organization: &organization_view,
                        user: &user_view,
                    },
                )
                .await?;
        }
        let expires_at =
            chrono::Utc::now() + chrono::Duration::seconds(config.invitation_lifetime() as i64);
        ctx.database
            .create_invitation(draft.into_create(expires_at, user.id().typed()?)?)
            .await?
    };
    let invitation_view = InvitationView::from(&invitation);
    if let Some(sender) = &config.send_invitation_email
        && let Err(error) = sender
            .send(&InvitationEmail {
                invitation: invitation_view.clone(),
                organization: organization_view.clone(),
                member,
                inviter: user_view.clone(),
                request: request.cloned(),
            })
            .await
    {
        // Upstream runInBackgroundOrAwait logs delivery failures and preserves success.
        better_auth_core::observability::logger::current().error(
            "Failed to send organization invitation email",
            &[better_auth_core::observability::LogArgument::Error(&error)],
        );
    }
    if !is_resend && let Some(hooks) = &config.hooks {
        hooks
            .after_create_invitation(OrganizationInvitationEvent {
                invitation: &invitation,
                user: &user_view,
                organization: &organization_view,
            })
            .await?;
    }
    Ok(invitation_view)
}

pub(crate) async fn get_invitation_core(
    query: &GetInvitationQuery,
    user: &impl AuthUser,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Option<GetInvitationResponse<InvitationView>>> {
    if query.id.is_empty() {
        return Err(AuthError::bad_request("Missing invitation id"));
    }

    let Some(invitation) = ctx.database.get_invitation_by_id(&query.id).await? else {
        return Ok(None);
    };
    if !invitation.is_pending() || invitation.is_expired()? {
        return Ok(None);
    }

    let recipient = invitation.email().typed()?;
    if !user
        .email()
        .is_some_and(|email| recipient.eq_ignore_ascii_case(email))
    {
        return Err(AuthError::forbidden(
            "You are not the recipient of the invitation",
        ));
    }
    if config.require_email_verification_on_invitation && !user.email_verified() {
        return Err(AuthError::forbidden(
            "Email verification required to view or list invitations for the session email",
        ));
    }

    let organization = ctx
        .database
        .get_organization_by_id(invitation.organization_id.typed()?)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;

    if ctx
        .database
        .get_member(
            invitation.organization_id().typed()?.as_str(),
            invitation.inviter_id().typed()?.as_str(),
        )
        .await?
        .is_none()
    {
        return Err(AuthError::bad_request(
            "Inviter is no longer a member of the organization",
        ));
    }

    let inviter_email = if let Some(inviter) = ctx
        .database
        .get_user_by_id(invitation.inviter_id.typed()?)
        .await?
    {
        inviter.email().map(str::to_owned)
    } else {
        None
    };

    Ok(Some(GetInvitationResponse {
        invitation: InvitationView::from(&invitation),
        organization_name: organization.name().clone(),
        organization_slug: organization.slug().clone(),
        inviter_email,
    }))
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
        .get_member(&org_id, user.id().typed()?)
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
        .map(|invitation| invitation.organization_id().typed().cloned())
        .collect::<AuthResult<Vec<_>>>()?;
    let organizations_by_id = ctx
        .database
        .list_organizations_by_ids(&organization_ids)
        .await?
        .into_iter()
        .map(|organization| {
            let organization_id = organization.id.as_str().map(str::to_owned);
            (organization_id, organization)
        })
        .collect::<HashMap<_, _>>();
    let mut pending = Vec::with_capacity(all_invitations.len());

    for invitation in all_invitations.iter() {
        let organization = organizations_by_id
            .get(&Some(invitation.organization_id().typed()?.clone()))
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;

        pending.push(UserInvitationResponse {
            invitation: InvitationView::from(invitation),
            organization_name: organization.name().clone(),
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
        .ok_or_else(|| AuthError::bad_request("Invitation not found"))?;
    if !invitation.is_pending() || invitation.is_expired()? {
        return Err(AuthError::bad_request("Invitation not found"));
    }

    let user_email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User has no email"))?;

    if invitation.email().typed()?.to_lowercase() != user_email.to_lowercase() {
        return Err(AuthError::forbidden(
            "You are not the recipient of the invitation",
        ));
    }

    if config.require_email_verification_on_invitation && !user.email_verified() {
        return Err(AuthError::forbidden(
            "Email verification required before accepting or rejecting invitation",
        ));
    }

    let count = ctx
        .database
        .list_organization_members(invitation.organization_id.typed()?)
        .await?
        .len();
    let organization = ctx
        .database
        .get_organization_by_id(invitation.organization_id.typed()?)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = crate::plugins::organization::fields::organization(&organization, ctx);
    let user_view = ctx.user_view(user)?;
    let limit = config
        .member_limit(OrganizationUser {
            organization: &organization_view,
            user: &user_view,
        })
        .await?;
    if count >= limit {
        return Err(AuthError::Upstream {
            status: 403,
            code: "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
            message: "Organization membership limit reached",
        });
    }
    let event = OrganizationInvitationEvent {
        invitation: &invitation,
        user: &user_view,
        organization: &organization_view,
    };
    if let Some(hooks) = &config.hooks {
        hooks.before_accept_invitation(event).await?;
    }

    let session_view = ctx.session_view(session).await?;
    let resolver = InvitationTeamLimits {
        config,
        organization_id: invitation.organization_id.typed()?,
        session: OrganizationSession {
            user: &user_view,
            session: &session_view,
        },
    };
    let (member, accepted, snapshot) = ctx
        .database
        .accept_invitation_with_teams(
            invitation.id().typed()?,
            user.id().typed()?,
            Some(session.token()),
            config.teams.enabled,
            better_auth_core::store::TeamMemberLimits::Resolver(&resolver),
        )
        .await?;
    if let Some(hooks) = &config.hooks {
        hooks
            .after_accept_invitation(
                &member,
                OrganizationInvitationEvent {
                    invitation: &accepted,
                    ..event
                },
            )
            .await?;
    }
    let snapshot = if let Some(session) = snapshot.as_ref() {
        Some(ctx.session_view(session).await?)
    } else {
        None
    };
    Ok((
        AcceptInvitationResponse {
            invitation: InvitationView::from(&accepted),
            member: BasicMemberResponse::from_member(&member),
        },
        snapshot,
    ))
}

pub(crate) async fn reject_invitation_core(
    body: &RejectInvitationRequest,
    user: &impl AuthUser,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AcceptInvitationResponse<InvitationView, Option<BasicMemberResponse>>> {
    let invitation = ctx
        .database
        .get_invitation_by_id(&body.invitation_id)
        .await?
        .filter(|invitation| invitation.is_pending())
        .ok_or_else(|| AuthError::bad_request("Invitation not found!"))?;

    let user_email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User has no email"))?;

    if invitation.email().typed()?.to_lowercase() != user_email.to_lowercase() {
        return Err(AuthError::forbidden(
            "You are not the recipient of the invitation",
        ));
    }

    if config.require_email_verification_on_invitation && !user.email_verified() {
        return Err(AuthError::forbidden(
            "Email verification required before accepting or rejecting invitation",
        ));
    }

    let organization = ctx
        .database
        .get_organization_by_id(invitation.organization_id.typed()?)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = crate::plugins::organization::fields::organization(&organization, ctx);
    let user_view = ctx.user_view(user)?;
    let event = OrganizationInvitationEvent {
        invitation: &invitation,
        user: &user_view,
        organization: &organization_view,
    };
    if let Some(hooks) = &config.hooks {
        hooks.before_reject_invitation(event).await?;
    }
    let updated_invitation = ctx
        .database
        .update_invitation_status(invitation.id().typed()?, InvitationStatus::Rejected)
        .await?;

    if let Some(hooks) = &config.hooks {
        hooks
            .after_reject_invitation(OrganizationInvitationEvent {
                invitation: &updated_invitation,
                ..event
            })
            .await?;
    }
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
        .get_member(
            invitation.organization_id().typed()?.as_str(),
            user.id().typed()?,
        )
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    if !check_permission(
        member.role().typed()?,
        invitation.organization_id().typed()?.as_str(),
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

    let organization = ctx
        .database
        .get_organization_by_id(invitation.organization_id.typed()?)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = crate::plugins::organization::fields::organization(&organization, ctx);
    let user_view = ctx.user_view(user)?;
    let event = OrganizationInvitationEvent {
        invitation: &invitation,
        user: &user_view,
        organization: &organization_view,
    };
    if let Some(hooks) = &config.hooks {
        hooks.before_cancel_invitation(event).await?;
    }
    let updated_invitation = ctx
        .database
        .update_invitation_status(invitation.id().typed()?, InvitationStatus::Canceled)
        .await?;

    if let Some(hooks) = &config.hooks {
        hooks
            .after_cancel_invitation(OrganizationInvitationEvent {
                invitation: &updated_invitation,
                ..event
            })
            .await?;
    }
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
    let body: InviteMemberRequest = super::super::request::read(req, &config.schema)?;
    let invitation = invite_member_core(&body, &user, &session, config, ctx, Some(req)).await?;
    Ok(AuthResponse::json(200, &invitation)?)
}

pub async fn handle_get_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, _) = ctx
        .require_session(req)
        .await
        .map_err(|error| match error {
            AuthError::Unauthenticated => AuthError::authentication_failed("Not authenticated"),
            error => error,
        })?;
    let query = crate::plugins::query_input::parse::<GetInvitationQuery>(&req.query)?;
    match get_invitation_core(&query, &user, config, ctx).await? {
        Some(response) => Ok(AuthResponse::json(200, &response)?),
        None => Ok(AuthResponse::json(
            400,
            &serde_json::json!({ "message": "Invitation not found!" }),
        )?),
    }
}

pub async fn handle_list_invitations(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let query = crate::plugins::query_input::parse::<ListInvitationsQuery>(&req.query)?;
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
    let body: AcceptInvitationRequest = super::super::request::read(req, &config.schema)?;
    let (response, snapshot) = accept_invitation_core(&body, &user, &session, config, ctx).await?;
    let response = AuthResponse::json(200, &response)?;
    if let Some(snapshot) = snapshot {
        let manager = ctx.session_manager();
        // Upstream writes the team cookie before updating the active organization in the transaction.
        manager
            .set_session_cookie(
                req,
                better_auth_core::session::SessionData {
                    session: snapshot,
                    user,
                },
                None,
            )
            .await?;
    }
    Ok(response)
}

pub async fn handle_reject_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: RejectInvitationRequest = super::super::request::read(req, &config.schema)?;
    let response = reject_invitation_core(&body, &user, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

pub async fn handle_cancel_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: CancelInvitationRequest = super::super::request::read(req, &config.schema)?;
    let response = cancel_invitation_core(&body, &user, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers::{create_test_context, create_user_and_session};
    use better_auth_core::{CreateMember, CreateOrganization, CreateUser};
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
                additional_fields: Default::default(),
                id: None,
                name: "Organization".into(),
                slug: "resend-limit".into(),
                logo: None.into(),
                metadata: None.into(),
            })
            .await
            .unwrap();
        ctx.database
            .create_member(CreateMember {
                additional_fields: Default::default(),
                organization_id: organization.id.typed().unwrap().clone().into(),
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
        let first = invite_member_core(&body, &user, &session, &config, &ctx, None)
            .await
            .unwrap();
        let shortened = *first.expires_at.typed().unwrap() - Duration::hours(1);
        ctx.database
            .update_invitation_expiry(first.id.typed().unwrap(), shortened)
            .await
            .unwrap();
        body.resend = true.into();
        let resent = invite_member_core(&body, &user, &session, &config, &ctx, None)
            .await
            .unwrap();
        assert_eq!(resent.id, first.id);
        assert!(*resent.expires_at.typed().unwrap() > shortened);
        assert_eq!(
            ctx.database
                .get_invitation_by_id(first.id.typed().unwrap())
                .await
                .unwrap()
                .unwrap()
                .expires_at,
            resent.expires_at
        );
        body.email = "another@example.com".into();
        let error = invite_member_core(&body, &user, &session, &config, &ctx, None)
            .await
            .unwrap_err();
        assert_eq!(error.status_code(), 403);
        assert!(error.to_string().contains("Invitation limit reached"));
    }
}

struct InvitationTeamLimits<'a> {
    config: &'a OrganizationConfig,
    organization_id: &'a str,
    session: OrganizationSession<'a>,
}
#[async_trait::async_trait]
impl better_auth_core::store::TeamMemberLimitResolver for InvitationTeamLimits<'_> {
    async fn maximum(&self, team_id: &str) -> AuthResult<Option<usize>> {
        self.config
            .team_member_limit(OrganizationTeamMemberLimit {
                organization_id: self.organization_id,
                team_id,
                session: self.session,
            })
            .await
    }
}
