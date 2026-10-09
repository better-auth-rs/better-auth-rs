use better_auth_core::entity::{AuthInvitation, AuthMember, AuthOrganization, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::session::NativeSessionData;
use better_auth_core::types::{AuthRequest, AuthResponse, InvitationStatus};
use better_auth_core::wire::InvitationView;

use super::{require_native_session, resolve_organization_id};
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
    session: &NativeSessionData,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: Option<&AuthRequest>,
) -> AuthResult<InvitationView> {
    let org_value = body.organization_id.field_value();
    let org_value = org_value
        .is_truthy()
        .then_some(org_value)
        .or_else(|| {
            let id = session.session.active_organization_id.field_value();
            id.is_truthy().then_some(id)
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
    let resend = body.resend.is_truthy()?;

    let member = ctx
        .database
        .get_member_with_user_value(&org_value, session.user_property("id")?)
        .await?
        .map(|joined| joined.member)
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    let org_id = org_value;

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
        ctx.database
            .query_organization_roles_value(
                &org_id,
                &roles
                    .iter()
                    .map(|role| (*role).to_owned())
                    .collect::<Vec<_>>(),
            )
            .await?
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
            .get_member_value(&org_id, &existing_user.id().field_value())
            .await?
            .is_some()
    {
        return Err(AuthError::bad_request(
            "User is already a member of this organization",
        ));
    }

    let existing = ctx
        .database
        .get_pending_invitation_value(&org_id, &email)
        .await?;
    if existing.is_some() && !resend && !config.cancel_pending_invitations_on_re_invite {
        return Err(AuthError::bad_request(
            "User is already invited to this organization",
        ));
    }
    let organization = ctx
        .database
        .get_organization_by_id_value(&org_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = crate::plugins::organization::fields::organization(&organization, ctx);
    let expires_at = config.invitation_expires_at(chrono::Utc::now())?;
    let is_resend = existing.is_some() && resend;
    let invitation = if let Some(existing) = existing.as_ref().filter(|_| resend) {
        let _ = ctx
            .database
            .update_invitation_expiry_value(&existing.id().field_value(), expires_at)
            .await?;
        let mut response = existing.clone();
        response.expires_at = expires_at.into();
        response
    } else {
        if let Some(existing) = existing {
            let _ = ctx
                .database
                .update_invitation_status_value(
                    &existing.id().field_value(),
                    InvitationStatus::Canceled,
                )
                .await?;
        }
        {
            let limit = config
                .pending_invitation_limit(
                    OrganizationMemberEvent {
                        member: &member,
                        user: &session.user,
                        organization: &organization_view,
                    },
                    OrganizationEndpoint::new(ctx, request),
                )
                .await?;
            let count = ctx
                .database
                .count_pending_organization_invitations_value(&org_id)
                .await? as usize;
            if count >= limit {
                return Err(AuthError::forbidden("Invitation limit reached"));
            }
        }
        let team_ids_value = body.team_id.field_value();
        let check_teams = config.teams.enabled && team_ids_value.is_truthy();
        let team_ids = crate::plugins::organization::input::invitation_team_ids(team_ids_value);
        if check_teams {
            let raw = team_ids.field_value();
            let requested = raw
                .as_array()
                .ok_or_else(|| AuthError::from(AuthResponse::new(500)))?;
            for team_id in requested {
                let reserved = match team_id {
                    better_auth_core::FieldValue::String(id) => id.contains(','),
                    better_auth_core::FieldValue::Array(ids) => ids
                        .iter()
                        .any(|id| id.strict_equals(&better_auth_core::FieldValue::from(","))),
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
                    .filter(|team| team.organization_id.field_value().strict_equals(&org_id))
                    .ok_or_else(|| AuthError::bad_request("Team not found"))?;
                teams.push(team);
            }
            for team in &teams {
                let team_id = team.id.field_value();
                let limit = config
                    .team_member_limit(OrganizationTeamMemberLimit {
                        organization_id: &org_id,
                        team_id: &team_id,
                        session: OrganizationSession {
                            user: &session.user,
                            session: &session.session,
                        },
                    })
                    .await?;
                if let Some(limit) = limit
                    && ctx.database.count_team_members_value(&team_id).await? >= limit as u64
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
                .and_then(better_auth_core::FieldValue::as_str)
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
            organization_id: better_auth_core::SchemaValue::from_field(org_id),
            email: email.clone(),
            role: normalized_roles(&role_input),
            inviter_id: better_auth_core::SchemaValue::from_field(
                session.user_property("id")?.clone(),
            ),
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
                        user: &session.user,
                    },
                )
                .await?;
        }
        let expires_at = config.invitation_expires_at(chrono::Utc::now())?;
        ctx.database
            .create_invitation(draft.into_create(expires_at, session.user_property("id")?)?)
            .await?
    };
    let invitation = crate::plugins::organization::fields::invitation_snapshot(invitation, config);
    let invitation_view = InvitationView::from(&invitation);
    let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        request,
        better_auth_core::FieldValue::from_json(serde_json::to_value(body)?)?,
        ctx,
    );
    endpoint.session = Some(session.clone());
    let task = crate::plugins::organization::callbacks::delivery(
        config,
        InvitationEmail {
            invitation: invitation_view.clone(),
            organization: organization_view.clone(),
            member,
            inviter: session.user.clone(),
            request: endpoint.request.cloned(),
        },
        &endpoint,
    )?;
    better_auth_core::background::run_or_await(
        task,
        ctx.config.advanced.background_tasks.as_ref(),
        &ctx.config.logger,
    )
    .await;
    if !is_resend && let Some(hooks) = &config.hooks {
        hooks
            .after_create_invitation(OrganizationInvitationEvent {
                invitation: &invitation,
                user: &session.user,
                organization: &organization_view,
            })
            .await?;
    }
    Ok(invitation_view)
}

pub(crate) async fn get_invitation_core(
    query: &GetInvitationQuery,
    session: &NativeSessionData,
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
    if recipient.to_lowercase()
        != crate::plugins::helpers::user_email_field(session.user_property("email")?)?
            .to_lowercase()
    {
        return Err(AuthError::forbidden(
            "You are not the recipient of the invitation",
        ));
    }
    if config.require_email_verification_on_invitation
        && !session.user_property("emailVerified")?.is_truthy()
    {
        return Err(AuthError::forbidden(
            "Email verification required to view or list invitations for the session email",
        ));
    }

    let organization = ctx
        .database
        .get_organization_by_id_value(&invitation.organization_id.field_value())
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;

    let inviter = ctx
        .database
        .get_member_with_user_value(
            &invitation.organization_id.field_value(),
            &invitation.inviter_id.field_value(),
        )
        .await?
        .ok_or_else(|| {
            AuthError::bad_request("Inviter is no longer a member of the organization")
        })?;
    let inviter_email = inviter.user.email;

    Ok(Some(GetInvitationResponse {
        invitation: InvitationView::from(&invitation),
        organization_name: organization.name().clone(),
        organization_slug: organization.slug().clone(),
        inviter_email,
    }))
}

pub(crate) async fn list_invitations_core(
    query: &ListInvitationsQuery,
    session: &NativeSessionData,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<InvitationView>> {
    let org_id = resolve_organization_id(
        query.organization_id.as_deref(),
        None,
        &session.session,
        ctx,
    )
    .await?;

    let _ = ctx
        .database
        .get_member_with_user_value(&org_id, session.user_property("id")?)
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    let invitations = ctx
        .database
        .list_organization_invitations_value(&org_id)
        .await?;
    Ok(invitations.iter().map(InvitationView::from).collect())
}

pub(crate) async fn list_user_invitations_core(
    session: Option<&NativeSessionData>,
    email: Option<&str>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<UserInvitationResponse<InvitationView>>> {
    if let Some(session) = session
        && !session.user_property("emailVerified")?.is_truthy()
    {
        return Err(AuthError::forbidden(
            "Email verification required to view or list invitations for the session email",
        ));
    }
    let email = match session
        .map(|session| session.user_property("email"))
        .transpose()?
        .filter(|email| email.is_truthy())
    {
        Some(email) => email.clone(),
        None => email
            .map(better_auth_core::FieldValue::from)
            .unwrap_or_default(),
    };
    if !email.is_truthy() {
        return Err(AuthError::bad_request(
            "Missing session headers, or email query parameter.",
        ));
    }
    let user_email = crate::plugins::helpers::user_email_field(&email)?;

    let all_invitations = ctx.database.list_user_invitations(&user_email).await?;
    let pending = all_invitations
        .into_iter()
        .filter(|row| row.invitation.status == InvitationStatus::Pending)
        .map(|row| UserInvitationResponse {
            invitation: InvitationView::from(&row.invitation),
            organization_name: row
                .organization
                .map(|organization| organization.name)
                .unwrap_or_default(),
        })
        .collect();

    Ok(pending)
}

pub(crate) async fn accept_invitation_core(
    body: &AcceptInvitationRequest,
    session: &NativeSessionData,
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

    let recipient = crate::plugins::helpers::user_email_field(&invitation.email().field_value())?;
    let user_email = crate::plugins::helpers::user_email_field(session.user_property("email")?)?;

    if recipient.to_lowercase() != user_email.to_lowercase() {
        return Err(AuthError::forbidden(
            "You are not the recipient of the invitation",
        ));
    }

    if config.require_email_verification_on_invitation
        && !session.user_property("emailVerified")?.is_truthy()
    {
        return Err(AuthError::forbidden(
            "Email verification required before accepting or rejecting invitation",
        ));
    }

    let count = ctx
        .database
        .count_organization_members_value(&invitation.organization_id.field_value())
        .await?;
    let organization = ctx
        .database
        .get_organization_by_id_value(&invitation.organization_id.field_value())
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = crate::plugins::organization::fields::organization(&organization, ctx);
    let limit = config
        .member_limit(OrganizationUser {
            organization: &organization_view,
            user: &session.user,
        })
        .await?;
    if count >= limit as i64 {
        return Err(AuthError::Upstream {
            status: 403,
            code: "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
            message: "Organization membership limit reached",
        });
    }
    let event = OrganizationInvitationEvent {
        invitation: &invitation,
        user: &session.user,
        organization: &organization_view,
    };
    if let Some(hooks) = &config.hooks {
        hooks.before_accept_invitation(event).await?;
    }

    let resolver = InvitationTeamLimits {
        config,
        session: OrganizationSession {
            user: &session.user,
            session: &session.session,
        },
    };
    let (member, accepted, snapshot) = ctx
        .database
        .accept_invitation_with_teams_values(
            &body.invitation_id.as_str().into(),
            session.user_property("id")?,
            Some(&session.session.token.field_value()),
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
    session: &NativeSessionData,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AcceptInvitationResponse<InvitationView, Option<BasicMemberResponse>>> {
    let invitation = ctx
        .database
        .get_invitation_by_id(&body.invitation_id)
        .await?
        .filter(|invitation| invitation.is_pending())
        .ok_or_else(|| AuthError::bad_request("Invitation not found!"))?;

    let recipient = crate::plugins::helpers::user_email_field(&invitation.email().field_value())?;
    let user_email = crate::plugins::helpers::user_email_field(session.user_property("email")?)?;

    if recipient.to_lowercase() != user_email.to_lowercase() {
        return Err(AuthError::forbidden(
            "You are not the recipient of the invitation",
        ));
    }

    if config.require_email_verification_on_invitation
        && !session.user_property("emailVerified")?.is_truthy()
    {
        return Err(AuthError::forbidden(
            "Email verification required before accepting or rejecting invitation",
        ));
    }

    let organization = ctx
        .database
        .get_organization_by_id_value(&invitation.organization_id.field_value())
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = crate::plugins::organization::fields::organization(&organization, ctx);
    let event = OrganizationInvitationEvent {
        invitation: &invitation,
        user: &session.user,
        organization: &organization_view,
    };
    if let Some(hooks) = &config.hooks {
        hooks.before_reject_invitation(event).await?;
    }
    let updated_invitation = ctx
        .database
        .update_invitation_status(&body.invitation_id, InvitationStatus::Rejected)
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
    session: &NativeSessionData,
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
        .get_member_with_user_value(
            &invitation.organization_id().field_value(),
            session.user_property("id")?,
        )
        .await?
        .map(|joined| joined.member)
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    if !check_permission(
        member.role().typed()?,
        &invitation.organization_id().field_value(),
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
        .get_organization_by_id_value(&invitation.organization_id.field_value())
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = crate::plugins::organization::fields::organization(&organization, ctx);
    let event = OrganizationInvitationEvent {
        invitation: &invitation,
        user: &session.user,
        organization: &organization_view,
    };
    if let Some(hooks) = &config.hooks {
        hooks.before_cancel_invitation(event).await?;
    }
    let updated_invitation = ctx
        .database
        .update_invitation_status(&body.invitation_id, InvitationStatus::Canceled)
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
    let session = require_native_session(req, ctx).await?;
    let body: InviteMemberRequest = super::super::request::read(req, &config.schema)?;
    let invitation = invite_member_core(&body, &session, config, ctx, Some(req)).await?;
    Ok(AuthResponse::json(200, &invitation)?)
}

pub async fn handle_get_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = ctx
        .require_native_session(req)
        .await
        .map_err(|error| match error {
            AuthError::Unauthenticated => AuthError::authentication_failed("Not authenticated"),
            error => error,
        })?;
    let query = crate::plugins::query_input::parse::<GetInvitationQuery>(&req.query)?;
    match get_invitation_core(&query, &session, config, ctx).await? {
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
    let session = require_native_session(req, ctx).await?;
    let query = crate::plugins::query_input::parse::<ListInvitationsQuery>(&req.query)?;
    let invitations = list_invitations_core(&query, &session, ctx).await?;
    Ok(AuthResponse::json(200, &invitations)?)
}

pub async fn handle_list_user_invitations(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let session = ctx
        .native_session(req, better_auth_core::session::SessionRead::Cached)
        .await?;
    let email = req.query_string("email")?;
    let endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        Some(req),
        better_auth_core::FieldValue::Null,
        ctx,
    );
    if endpoint.request.is_some() && email.is_some_and(|email| !email.is_empty()) {
        return Err(AuthError::bad_request(
            "User email cannot be passed for client side API calls.",
        ));
    }
    let invitations = list_user_invitations_core(session.as_ref(), email, ctx).await?;
    Ok(AuthResponse::json(200, &invitations)?)
}

pub async fn handle_accept_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let body: AcceptInvitationRequest = super::super::request::read(req, &config.schema)?;
    let (response, snapshot) = accept_invitation_core(&body, &session, config, ctx).await?;
    let response = AuthResponse::json(200, &response)?;
    if let Some(snapshot) = snapshot {
        let manager = ctx.session_manager();
        // Upstream writes the team cookie before updating the active organization in the transaction.
        manager
            .set_native_session_cookie(
                req,
                NativeSessionData {
                    session: snapshot,
                    user: session.user,
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
    let session = require_native_session(req, ctx).await?;
    let body: RejectInvitationRequest = super::super::request::read(req, &config.schema)?;
    let response = reject_invitation_core(&body, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

pub async fn handle_cancel_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let body: CancelInvitationRequest = super::super::request::read(req, &config.schema)?;
    let response = cancel_invitation_core(&body, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::organization::OrganizationPlugin;
    use crate::plugins::test_helpers::{
        create_test_config, create_test_context_with_plugins, create_user_and_session,
    };
    use better_auth_core::{CreateMember, CreateOrganization, CreateUser};
    use chrono::Duration;

    #[tokio::test]
    async fn resend_renews_existing_invitation_when_pending_limit_is_reached() {
        let config = OrganizationConfig {
            invitation_limit: Some(1),
            ..Default::default()
        };
        let ctx = create_test_context_with_plugins(
            create_test_config(),
            &[&OrganizationPlugin::with_config(config.clone())],
        )
        .await;
        let (user, session) = create_user_and_session(
            &ctx,
            CreateUser {
                name: Some("Fixture".into()).into(),
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
        let mut body: InviteMemberRequest = serde_json::from_value(serde_json::json!({
            "organizationId": organization.id, "email": "invitee@example.com", "role": "member",
        }))
        .unwrap();
        let first = invite_member_core(
            &body,
            &(user.clone(), session.clone()).into(),
            &config,
            &ctx,
            None,
        )
        .await
        .unwrap();
        let shortened = first
            .expires_at
            .typed()
            .unwrap()
            .to_datetime()
            .unwrap()
            .unwrap()
            - Duration::hours(1);
        ctx.database
            .update_invitation_expiry(first.id.typed().unwrap(), shortened)
            .await
            .unwrap();
        body.resend = true.into();
        let resent = invite_member_core(
            &body,
            &(user.clone(), session.clone()).into(),
            &config,
            &ctx,
            None,
        )
        .await
        .unwrap();
        assert_eq!(resent.id, first.id);
        assert!(
            resent
                .expires_at
                .typed()
                .unwrap()
                .to_datetime()
                .unwrap()
                .unwrap()
                > shortened
        );
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
        let error = invite_member_core(
            &body,
            &(user.clone(), session.clone()).into(),
            &config,
            &ctx,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.status_code(), 403);
        assert!(error.to_string().contains("Invitation limit reached"));
    }
}

struct InvitationTeamLimits<'a> {
    config: &'a OrganizationConfig,
    session: OrganizationSession<'a>,
}
#[async_trait::async_trait]
impl better_auth_core::store::TeamMemberLimitResolver for InvitationTeamLimits<'_> {
    async fn maximum(
        &self,
        team_id: &str,
        organization_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Option<usize>> {
        self.config
            .team_member_limit(OrganizationTeamMemberLimit {
                organization_id,
                team_id: &team_id.into(),
                session: self.session,
            })
            .await
    }
}
