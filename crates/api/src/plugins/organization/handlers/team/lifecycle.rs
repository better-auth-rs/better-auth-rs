use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema};

use super::{CreateBody, TeamBody, authorize, find_team, optional_string};
use crate::plugins::organization::{
    OrganizationConfig, fields,
    handlers::{optional_session, request_present},
    hooks::*,
    request,
};

pub(super) async fn create(
    req: &AuthRequest,
    ctx: &AuthContext<impl AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = optional_session(req, ctx).await?;
    if session.is_none() && request_present(req, ctx) {
        return Err(AuthResponse::new(401).into());
    }
    let body: CreateBody = request::read(req, &config.schema)?;
    let additional_fields = body.additional_fields.clone();
    let organization_id = optional_string(body.organization_id, "body.organizationId")?;
    let org = organization_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .or_else(|| {
            session
                .as_ref()
                .and_then(|(_, session)| session.active_organization_id())
        })
        .ok_or_else(|| AuthError::bad_request("No active organization"))?;
    if let Some((user, _)) = &session {
        let member = ctx
            .database
            .get_member_with_user(org, user.id().typed()?)
            .await?
            .ok_or_else(|| {
                AuthError::forbidden("You are not allowed to invite users to this organization")
            })?;
        authorize(
            &member.member,
            org,
            ("team", "create"),
            "You are not allowed to create teams in this organization",
            config,
            ctx,
        )
        .await?;
    }
    let user_view = match &session {
        Some((user, _)) => Some(ctx.user_view(user).await?),
        None => None,
    };
    let session_view = match &session {
        Some((_, session)) => Some(ctx.session_view(session).await?),
        None => None,
    };
    let actor = user_view
        .as_ref()
        .zip(session_view.as_ref())
        .map(|(user, session)| OrganizationSession { user, session });
    let count = ctx.database.count_organization_teams(org).await?;
    if let Some(maximum) = config
        .team_limit(
            OrganizationTeamLimit {
                organization_id: org,
                session: actor,
            },
            OrganizationEndpoint::new(ctx, Some(req)),
        )
        .await?
        .filter(|limit| *limit > 0)
        && count >= maximum as u64
    {
        return Err(AuthError::bad_request(
            "You have reached the maximum number of teams",
        ));
    }
    let organization = ctx
        .database
        .get_organization_by_id(org)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = fields::organization(&organization, ctx);
    let created_at = chrono::Utc::now();
    let mut data = OrganizationTeamDraft {
        id: additional_fields
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        additional_fields,
        name: body.name,
        organization_id: org.into(),
        created_at: None,
        updated_at: None,
    };
    if let Some(hooks) = &config.hooks {
        hooks
            .before_create_team(&mut data, &organization_view, user_view.as_ref())
            .await?;
    }
    let team = ctx
        .database
        .create_team(data.into_create(created_at, Some(created_at)))
        .await?;
    let team = fields::team(team, ctx);
    if let Some(hooks) = &config.hooks {
        hooks
            .after_create_team(OrganizationTeamEvent {
                team: &team,
                user: user_view.as_ref(),
                organization: &organization_view,
            })
            .await?;
    }
    Ok(AuthResponse::json(200, &team)?)
}

pub(super) async fn remove(
    req: &AuthRequest,
    ctx: &AuthContext<impl AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = optional_session(req, ctx).await?;
    let body: TeamBody = request::read(req, &config.schema)?;
    let org = body
        .organization_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .or_else(|| {
            session
                .as_ref()
                .and_then(|(_, session)| session.active_organization_id())
        })
        .ok_or_else(|| AuthError::bad_request("No active organization"))?;
    if session.is_none() && request_present(req, ctx) {
        return Err(AuthResponse::new(401).into());
    }
    if let Some((user, session)) = &session {
        if session.active_team_id() == Some(body.team_id.as_str()) {
            return Err(AuthError::forbidden(
                "You are not allowed to delete this team",
            ));
        }
        let member = ctx
            .database
            .get_member_with_user(org, user.id().typed()?)
            .await?
            .ok_or_else(|| AuthError::forbidden("You are not allowed to delete this team"))?;
        authorize(
            &member.member,
            org,
            ("team", "delete"),
            "You are not allowed to delete teams in this organization",
            config,
            ctx,
        )
        .await?;
    }
    let user_view = match &session {
        Some((user, _)) => Some(ctx.user_view(user).await?),
        None => None,
    };
    let team = find_team(&body.team_id, org, ctx).await?;
    if !config.teams.allow_removing_all_teams
        && ctx.database.count_organization_teams(org).await? <= 1
    {
        return Err(AuthError::bad_request("Unable to remove last team"));
    }
    let organization = ctx
        .database
        .get_organization_by_id(org)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = fields::organization(&organization, ctx);
    let event = OrganizationTeamEvent {
        team: &team,
        user: user_view.as_ref(),
        organization: &organization_view,
    };
    if let Some(hooks) = &config.hooks {
        hooks.before_delete_team(event).await?;
    }
    ctx.database.delete_team(team.id.typed()?).await?;
    if let Some(hooks) = &config.hooks {
        hooks.after_delete_team(event).await?;
    }
    Ok(AuthResponse::json(
        200,
        &serde_json::json!({"message":"Team removed successfully."}),
    )?)
}
