use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::{AuthContext, AuthRoute};
use better_auth_core::types::{AuthRequest, AuthResponse, CreateTeam, HttpMethod, Team};
use serde::Deserialize;
use validator::Validate;

use super::{require_session, resolve_organization_id};
use crate::plugins::organization::{OrganizationConfig, rbac::check_permission};

pub(crate) fn routes() -> Vec<AuthRoute> {
    vec![
        AuthRoute::post("/organization/create-team", "create_team"),
        AuthRoute::post("/organization/update-team", "update_team"),
        AuthRoute::post("/organization/remove-team", "remove_team"),
        AuthRoute::post("/organization/set-active-team", "set_active_team"),
        AuthRoute::post("/organization/add-team-member", "add_team_member"),
        AuthRoute::post("/organization/remove-team-member", "remove_team_member"),
        AuthRoute::get("/organization/list-teams", "list_teams"),
        AuthRoute::get("/organization/list-user-teams", "list_user_teams"),
        AuthRoute::get("/organization/list-team-members", "list_team_members"),
    ]
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct CreateBody {
    name: String,
    organization_id: Option<String>,
}
#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct TeamBody {
    team_id: String,
    organization_id: Option<String>,
}
#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct MemberBody {
    team_id: String,
    user_id: String,
    organization_id: Option<String>,
}
#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct UpdateBody {
    team_id: String,
    data: UpdateData,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateData {
    name: Option<String>,
    organization_id: Option<String>,
}
#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct ActiveBody {
    #[serde(
        default,
        deserialize_with = "crate::plugins::organization::types::deserialize_nullable_string_field"
    )]
    team_id: crate::plugins::organization::types::NullableStringField,
}

pub(crate) async fn find_team(
    team_id: &str,
    organization_id: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Team> {
    ctx.database
        .get_team(team_id)
        .await?
        .filter(|team| team.organization_id == organization_id)
        .ok_or_else(|| AuthError::bad_request("Team not found"))
}

async fn authorize(
    user_id: &str,
    org_id: &str,
    permission: (&str, &str),
    message: &'static str,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    let member = ctx
        .database
        .get_member(org_id, user_id)
        .await?
        .ok_or_else(|| AuthError::forbidden(message))?;
    if !check_permission(
        &member.role,
        org_id,
        permission.0,
        &[permission.1],
        config,
        ctx,
    )
    .await?
    {
        return Err(AuthError::forbidden(message));
    }
    Ok(())
}

pub(crate) async fn handle_team_request(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<Option<AuthResponse>> {
    let (user, session) = require_session(req, ctx).await?;
    macro_rules! body {
        ($ty:ty) => {
            match better_auth_core::validate_request_body::<$ty>(req) {
                Ok(body) => body,
                Err(response) => return Ok(Some(response)),
            }
        };
    }
    let response = match (req.method(), req.path()) {
        (HttpMethod::Post, "/organization/create-team") => {
            let body = body!(CreateBody);
            let org = resolve_organization_id(body.organization_id.as_deref(), None, &session, ctx)
                .await?;
            if ctx.database.get_member(&org, &user.id()).await?.is_none() {
                return Err(AuthError::forbidden(
                    "You are not allowed to invite users to this organization",
                ));
            }
            authorize(
                &user.id(),
                &org,
                ("team", "create"),
                "You are not allowed to create teams in this organization",
                config,
                ctx,
            )
            .await?;
            if let Some(maximum) = config.teams.maximum_teams.filter(|limit| *limit > 0)
                && ctx.database.list_organization_teams(&org).await?.len() >= maximum
            {
                return Err(AuthError::bad_request(
                    "You have reached the maximum number of teams",
                ));
            }
            if ctx.database.get_organization_by_id(&org).await?.is_none() {
                return Err(AuthError::bad_request("Organization not found"));
            }
            AuthResponse::json(
                200,
                &ctx.database
                    .create_team(CreateTeam {
                        name: body.name,
                        organization_id: org,
                        updated_at: Some(chrono::Utc::now()),
                    })
                    .await?,
            )?
        }
        (HttpMethod::Post, "/organization/update-team") => {
            let body = body!(UpdateBody);
            let org =
                resolve_organization_id(body.data.organization_id.as_deref(), None, &session, ctx)
                    .await?;
            authorize(
                &user.id(),
                &org,
                ("team", "update"),
                "You are not allowed to update this team",
                config,
                ctx,
            )
            .await?;
            let team = find_team(&body.team_id, &org, ctx).await?;
            AuthResponse::json(
                200,
                &ctx.database
                    .update_team(&team.id, body.data.name.as_deref().unwrap_or(&team.name))
                    .await?,
            )?
        }
        (HttpMethod::Post, "/organization/remove-team") => {
            let body = body!(TeamBody);
            let org = resolve_organization_id(body.organization_id.as_deref(), None, &session, ctx)
                .await?;
            if session.active_team_id() == Some(body.team_id.as_str())
                || ctx.database.get_member(&org, &user.id()).await?.is_none()
            {
                return Err(AuthError::forbidden(
                    "You are not allowed to delete this team",
                ));
            }
            authorize(
                &user.id(),
                &org,
                ("team", "delete"),
                "You are not allowed to delete teams in this organization",
                config,
                ctx,
            )
            .await?;
            let team = find_team(&body.team_id, &org, ctx).await?;
            if !config.teams.allow_removing_all_teams
                && ctx.database.list_organization_teams(&org).await?.len() <= 1
            {
                return Err(AuthError::bad_request("Unable to remove last team"));
            }
            ctx.database.delete_team(&team.id).await?;
            AuthResponse::json(
                200,
                &serde_json::json!({"message":"Team removed successfully."}),
            )?
        }
        (HttpMethod::Get, "/organization/list-teams") => {
            let org = resolve_organization_id(
                req.query.get("organizationId").map(String::as_str),
                None,
                &session,
                ctx,
            )
            .await?;
            if ctx.database.get_member(&org, &user.id()).await?.is_none() {
                return Err(AuthError::forbidden(
                    "You are not allowed to access this organization as an owner",
                ));
            }
            AuthResponse::json(200, &ctx.database.list_organization_teams(&org).await?)?
        }
        (HttpMethod::Post, "/organization/set-active-team") => {
            use crate::plugins::organization::types::NullableStringField;
            let body = body!(ActiveBody);
            let team_id = match body.team_id {
                NullableStringField::Null => {
                    if session.active_team_id().is_none() {
                        return Ok(Some(AuthResponse::json(200, &serde_json::Value::Null)?));
                    }
                    let _ = ctx
                        .database
                        .update_session_active_team(session.token(), None)
                        .await?;
                    return Ok(Some(with_session_cookie(
                        AuthResponse::json(200, &serde_json::Value::Null)?,
                        req,
                        session.token(),
                        ctx,
                    )));
                }
                NullableStringField::Value(id) if !id.is_empty() => Some(id),
                _ => session.active_team_id().map(str::to_owned),
            };
            let Some(team_id) = team_id else {
                return Ok(Some(AuthResponse::json(200, &serde_json::Value::Null)?));
            };
            let org = resolve_organization_id(None, None, &session, ctx).await?;
            let team = find_team(&team_id, &org, ctx).await?;
            if ctx
                .database
                .get_team_member(&team_id, &user.id())
                .await?
                .is_none()
            {
                return Err(AuthError::forbidden("User is not a member of the team"));
            }
            let _ = ctx
                .database
                .update_session_active_team(session.token(), Some(&team_id))
                .await?;
            with_session_cookie(AuthResponse::json(200, &team)?, req, session.token(), ctx)
        }
        (HttpMethod::Get, "/organization/list-user-teams") => {
            let target = req
                .query
                .get("userId")
                .filter(|id| !id.is_empty())
                .map(String::as_str)
                .unwrap_or(&user.id);
            let explicit_org = req.query.get("organizationId").filter(|id| !id.is_empty());
            let org = explicit_org
                .map(String::as_str)
                .or(session.active_organization_id());
            if target != user.id || explicit_org.is_some() {
                let org = org.ok_or_else(|| AuthError::bad_request("No active organization"))?;
                if ctx.database.get_member(org, &user.id()).await?.is_none() {
                    return Err(AuthError::forbidden(
                        "You are not a member of this organization",
                    ));
                }
                if target != user.id {
                    authorize(
                        &user.id(),
                        org,
                        ("member", "update"),
                        "You are not allowed to update this member",
                        config,
                        ctx,
                    )
                    .await?;
                    if ctx.database.get_member(org, target).await?.is_none() {
                        return Err(AuthError::bad_request(
                            "User is not a member of the organization",
                        ));
                    }
                }
                let teams = ctx
                    .database
                    .list_user_teams(target)
                    .await?
                    .into_iter()
                    .filter(|team| team.organization_id == org)
                    .collect::<Vec<_>>();
                AuthResponse::json(200, &teams)?
            } else {
                let mut teams = Vec::new();
                for team in ctx.database.list_user_teams(target).await? {
                    if ctx
                        .database
                        .get_member(&team.organization_id, target)
                        .await?
                        .is_some()
                    {
                        teams.push(team);
                    }
                }
                AuthResponse::json(200, &teams)?
            }
        }
        (HttpMethod::Get, "/organization/list-team-members") => {
            let team_id = req
                .query
                .get("teamId")
                .filter(|id| !id.is_empty())
                .map(String::as_str)
                .or(session.active_team_id())
                .ok_or_else(|| AuthError::bad_request("You do not have an active team"))?;
            let team = ctx
                .database
                .get_team(team_id)
                .await?
                .ok_or_else(|| AuthError::bad_request("Team not found"))?;
            if ctx
                .database
                .get_member(&team.organization_id, &user.id())
                .await?
                .is_none()
                || ctx
                    .database
                    .get_team_member(team_id, &user.id())
                    .await?
                    .is_none()
            {
                return Err(AuthError::bad_request("User is not a member of the team"));
            }
            AuthResponse::json(200, &ctx.database.list_team_members(team_id).await?)?
        }
        (
            HttpMethod::Post,
            "/organization/add-team-member" | "/organization/remove-team-member",
        ) => {
            let body = body!(MemberBody);
            let org = resolve_organization_id(body.organization_id.as_deref(), None, &session, ctx)
                .await?;
            if ctx.database.get_member(&org, &user.id()).await?.is_none() {
                return Err(AuthError::bad_request(
                    "User is not a member of the organization",
                ));
            }
            let adding = req.path() == "/organization/add-team-member";
            authorize(
                &user.id(),
                &org,
                ("member", if adding { "update" } else { "delete" }),
                if adding {
                    "You are not allowed to create a new member"
                } else {
                    "You are not allowed to remove a team member"
                },
                config,
                ctx,
            )
            .await?;
            if ctx
                .database
                .get_member(&org, &body.user_id)
                .await?
                .is_none()
            {
                return Err(AuthError::bad_request(
                    "User is not a member of the organization",
                ));
            }
            let _ = find_team(&body.team_id, &org, ctx).await?;
            if adding {
                let member = ctx
                    .database
                    .add_team_member(
                        &body.team_id,
                        &body.user_id,
                        config.teams.maximum_members_per_team,
                    )
                    .await?
                    .ok_or_else(|| AuthError::forbidden("Team member limit reached"))?;
                AuthResponse::json(200, &member)?
            } else {
                if ctx
                    .database
                    .get_team_member(&body.team_id, &body.user_id)
                    .await?
                    .is_none()
                {
                    return Err(AuthError::bad_request("User is not a member of the team"));
                }
                ctx.database
                    .remove_team_member(&body.team_id, &body.user_id)
                    .await?;
                AuthResponse::json(
                    200,
                    &serde_json::json!({"message":"Team member removed successfully."}),
                )?
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(response))
}

pub(crate) fn with_session_cookie(
    response: AuthResponse,
    req: &AuthRequest,
    token: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResponse {
    response.with_header(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_session_cookie_with_max_age(
            Some(token),
            (!ctx.session_manager().dont_remember(req))
                .then_some(ctx.config.session.expires_in.num_seconds()),
            &ctx.config,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::organization::OrganizationTeamsConfig;
    use crate::plugins::test_helpers::{
        create_auth_json_request_no_query, create_test_context, create_user_and_session,
    };
    use better_auth_core::{CreateMember, CreateOrganization, CreateUser};
    use chrono::Duration;

    #[tokio::test]
    async fn team_membership_is_idempotent_and_team_scope_is_enforced() {
        let ctx = create_test_context().await;
        let (user, session) = create_user_and_session(
            &ctx,
            CreateUser {
                email: Some("team-owner@example.com".into()),
                ..Default::default()
            },
            Duration::hours(1),
        )
        .await;
        let org = ctx
            .database
            .create_organization(CreateOrganization {
                id: None,
                name: "Teams".into(),
                slug: "teams".into(),
                logo: None,
                metadata: None,
            })
            .await
            .unwrap();
        ctx.database
            .create_member(CreateMember {
                organization_id: org.id.clone(),
                user_id: user.id.clone(),
                role: "owner".into(),
            })
            .await
            .unwrap();
        ctx.database
            .update_session_active_organization(&session.token, Some(&org.id))
            .await
            .unwrap();
        let config = OrganizationConfig {
            teams: OrganizationTeamsConfig {
                enabled: true,
                maximum_members_per_team: Some(1),
                ..Default::default()
            },
            ..Default::default()
        };
        let team = ctx
            .database
            .create_team(CreateTeam {
                name: "One".into(),
                organization_id: org.id.clone(),
                updated_at: None,
            })
            .await
            .unwrap();
        let add = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/organization/add-team-member",
            Some(&session.token),
            Some(serde_json::json!({"teamId":team.id,"userId":user.id})),
        );
        let first = handle_team_request(&add, &ctx, &config)
            .await
            .unwrap()
            .unwrap();
        let duplicate = handle_team_request(&add, &ctx, &config)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.body, duplicate.body);
        assert_eq!(
            ctx.database
                .list_team_members(&team.id)
                .await
                .unwrap()
                .len(),
            1
        );
        let full = super::super::org::get_full_organization_core(
            &crate::plugins::organization::types::GetFullOrganizationQuery {
                organization_id: Some(org.id.clone()),
                ..Default::default()
            },
            &user,
            &session,
            &config,
            &ctx,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(full.teams.unwrap()[0].member_count, 1);
        let foreign_org = ctx
            .database
            .create_organization(CreateOrganization {
                id: None,
                name: "Foreign".into(),
                slug: "foreign-teams".into(),
                logo: None,
                metadata: None,
            })
            .await
            .unwrap();
        let foreign = ctx
            .database
            .create_team(CreateTeam {
                name: "Foreign".into(),
                organization_id: foreign_org.id,
                updated_at: None,
            })
            .await
            .unwrap();
        let active = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/organization/set-active-team",
            Some(&session.token),
            Some(serde_json::json!({"teamId":foreign.id})),
        );
        assert_eq!(
            handle_team_request(&active, &ctx, &config)
                .await
                .unwrap_err()
                .status_code(),
            400
        );
        let active = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/organization/set-active-team",
            Some(&session.token),
            Some(serde_json::json!({"teamId":team.id})),
        );
        let active_response = handle_team_request(&active, &ctx, &config)
            .await
            .unwrap()
            .unwrap();
        assert!(
            active_response
                .headers
                .get_all("set-cookie")
                .any(|cookie| cookie.starts_with("better-auth.session_token="))
        );
        let remove = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/organization/remove-team",
            Some(&session.token),
            Some(serde_json::json!({"teamId":team.id})),
        );
        assert_eq!(
            handle_team_request(&remove, &ctx, &config)
                .await
                .unwrap_err()
                .status_code(),
            403
        );
    }
}
