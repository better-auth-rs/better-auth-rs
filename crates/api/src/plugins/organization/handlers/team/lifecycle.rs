use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, FieldValue,
};

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
        .map(FieldValue::from)
        .or_else(|| {
            session
                .as_ref()
                .map(|session| session.session.active_organization_id.field_value())
        })
        .filter(FieldValue::is_truthy)
        .ok_or_else(|| AuthError::bad_request("No active organization"))?;
    if let Some(session) = &session {
        let member = ctx
            .database
            .get_member_with_user_value(&org, session.user_property("id")?)
            .await?
            .ok_or_else(|| {
                AuthError::forbidden("You are not allowed to invite users to this organization")
            })?;
        authorize(
            &member.member,
            &org,
            ("team", "create"),
            "You are not allowed to create teams in this organization",
            config,
            ctx,
        )
        .await?;
    }
    let actor = session.as_ref().map(|session| OrganizationSession {
        user: &session.user,
        session: &session.session,
    });
    let count = ctx.database.count_organization_teams_value(&org).await?;
    if let Some(maximum) = config
        .team_limit(
            OrganizationTeamLimit {
                organization_id: &org,
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
        .get_organization_by_id_value(&org)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = fields::organization(&organization, ctx);
    let created_at = chrono::Utc::now();
    let mut data = OrganizationTeamDraft {
        id: additional_fields
            .get("id")
            .and_then(better_auth_core::FieldValue::as_str)
            .map(str::to_owned),
        additional_fields,
        name: body.name,
        organization_id: better_auth_core::SchemaValue::from_field(org),
        created_at: None,
        updated_at: None,
    };
    if let Some(hooks) = &config.hooks {
        hooks
            .before_create_team(
                &mut data,
                &organization_view,
                session.as_ref().map(|session| &session.user),
            )
            .await?;
    }
    let team = ctx
        .database
        .create_team(data.into_create(created_at, Some(created_at)))
        .await?;
    let team = fields::team(team, config)?;
    if let Some(hooks) = &config.hooks {
        hooks
            .after_create_team(OrganizationTeamEvent {
                team: &team,
                user: session.as_ref().map(|session| &session.user),
                organization: &organization_view,
            })
            .await?;
    }
    AuthResponse::json(None, &team)
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
        .map(FieldValue::from)
        .or_else(|| {
            session
                .as_ref()
                .map(|session| session.session.active_organization_id.field_value())
        })
        .filter(FieldValue::is_truthy)
        .ok_or_else(|| AuthError::bad_request("No active organization"))?;
    if session.is_none() && request_present(req, ctx) {
        return Err(AuthResponse::new(401).into());
    }
    if let Some(session) = &session {
        let member = ctx
            .database
            .get_member_with_user_value(&org, session.user_property("id")?)
            .await?
            .ok_or_else(|| AuthError::forbidden("You are not allowed to delete this team"))?;
        if session
            .session
            .active_team_id
            .field_value()
            .strict_equals(&body.team_id.as_str().into())
        {
            return Err(AuthError::forbidden(
                "You are not allowed to delete this team",
            ));
        }
        authorize(
            &member.member,
            &org,
            ("team", "delete"),
            "You are not allowed to delete teams in this organization",
            config,
            ctx,
        )
        .await?;
    }
    let team = find_team(&body.team_id.as_str().into(), &org, ctx, config).await?;
    if !config.teams.allow_removing_all_teams
        && ctx.database.count_organization_teams_value(&org).await? <= 1
    {
        return Err(AuthError::bad_request("Unable to remove last team"));
    }
    let organization = ctx
        .database
        .get_organization_by_id_value(&org)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = fields::organization(&organization, ctx);
    let event = OrganizationTeamEvent {
        team: &team,
        user: session.as_ref().map(|session| &session.user),
        organization: &organization_view,
    };
    if let Some(hooks) = &config.hooks {
        hooks.before_delete_team(event).await?;
    }
    ctx.database
        .delete_team_value(&team.id.field_value())
        .await?;
    if let Some(hooks) = &config.hooks {
        hooks.after_delete_team(event).await?;
    }
    AuthResponse::json(
        None,
        &serde_json::json!({"message":"Team removed successfully."}),
    )
}
