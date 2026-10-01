use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::{AuthContext, AuthRoute};
use better_auth_core::types::{AuthRequest, AuthResponse, HttpMethod, Team};
use serde::Deserialize;
use validator::Validate;

use super::{require_session, resolve_organization_id};
use crate::plugins::organization::hooks::*;
use crate::plugins::organization::types::{NullableStringField, deserialize_nullable_string_field};
use crate::plugins::organization::{OrganizationConfig, rbac::check_permission};

#[cfg(test)]
#[path = "team_input_tests.rs"]
mod input_tests;

pub(crate) fn routes() -> Vec<AuthRoute> {
    vec![
        AuthRoute::post("/organization/create-team", "createTeam"),
        AuthRoute::post("/organization/update-team", "updateTeam"),
        AuthRoute::post("/organization/remove-team", "removeTeam"),
        AuthRoute::post("/organization/set-active-team", "setActiveTeam"),
        AuthRoute::post("/organization/add-team-member", "addTeamMember"),
        AuthRoute::post("/organization/remove-team-member", "removeTeamMember"),
        AuthRoute::get("/organization/list-teams", "listOrganizationTeams")
            .query_validator(crate::plugins::query_input::organization_id),
        AuthRoute::get("/organization/list-user-teams", "listUserTeams")
            .query_validator(crate::plugins::query_input::user_teams),
        AuthRoute::get("/organization/list-team-members", "listTeamMembers")
            .query_validator(crate::plugins::query_input::team_members),
    ]
}

#[derive(Deserialize, serde::Serialize, Validate)]
#[serde(rename_all = "camelCase")]
struct CreateBody {
    #[serde(flatten)]
    additional_fields: serde_json::Map<String, serde_json::Value>,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::SchemaValue::is_undefined"
    )]
    name: better_auth_core::SchemaValue<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_string_field",
        skip_serializing_if = "NullableStringField::is_missing"
    )]
    organization_id: NullableStringField,
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
#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateData {
    #[serde(flatten)]
    additional_fields: serde_json::Map<String, serde_json::Value>,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::SchemaValue::is_undefined"
    )]
    name: better_auth_core::SchemaValue<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_string_field",
        skip_serializing_if = "NullableStringField::is_missing"
    )]
    organization_id: NullableStringField,
}

fn optional_string(value: NullableStringField, path: &str) -> AuthResult<Option<String>> {
    match value {
        NullableStringField::Missing => Ok(None),
        NullableStringField::Value(value) => Ok(Some(value)),
        NullableStringField::Null => Err(AuthError::FieldInput {
            code: "VALIDATION_ERROR",
            message: format!("[{path}] Invalid input: expected string, received null"),
        }),
    }
}

fn input_schema(config: &OrganizationConfig) -> better_auth_core::user_fields::UserConfig {
    let mut schema = config.schema.team.clone();
    if !schema
        .additional_fields
        .get("name")
        .is_some_and(|field| field.input)
    {
        let _ = schema.additional_fields.insert(
            "name".into(),
            better_auth_core::user_fields::UserFieldConfig {
                required: Some(true),
                ..Default::default()
            },
        );
    }
    schema
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
        .map(|team| crate::plugins::organization::fields::team(team, ctx))
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
        member.role.typed()?,
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
    let user_view = ctx.user_view(&user)?;
    let session_view = ctx.session_view(&session).await?;
    let actor = OrganizationSession {
        user: &user_view,
        session: &session_view,
    };
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
            let additional_fields = crate::plugins::organization::fields::parse_input(
                &input_schema(config),
                &body,
                &body.additional_fields,
                "body",
                false,
            )?;
            let organization_id = optional_string(body.organization_id, "body.organizationId")?;
            let org =
                resolve_organization_id(organization_id.as_deref(), None, &session, ctx).await?;
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
            let count = ctx.database.list_organization_teams(&org).await?.len();
            if let Some(maximum) = config
                .team_limit(
                    OrganizationTeamLimit {
                        organization_id: &org,
                        session: Some(actor),
                    },
                    OrganizationEndpoint::new(ctx, Some(req)),
                )
                .await?
                .filter(|limit| *limit > 0)
                && count >= maximum
            {
                return Err(AuthError::bad_request(
                    "You have reached the maximum number of teams",
                ));
            }
            let organization = ctx
                .database
                .get_organization_by_id(&org)
                .await?
                .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
            let organization_view =
                crate::plugins::organization::fields::organization(&organization, ctx);
            let created_at = chrono::Utc::now();
            let mut data = OrganizationTeamDraft {
                id: additional_fields
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                additional_fields,
                name: body.name,
                organization_id: org,
                created_at: None,
                updated_at: None,
            };
            if let Some(hooks) = &config.hooks {
                hooks
                    .before_create_team(&mut data, &organization_view, Some(&user_view))
                    .await?;
            }
            let team = ctx
                .database
                .create_team(data.into_create(created_at, Some(created_at)))
                .await?;
            let team = crate::plugins::organization::fields::team(team, ctx);
            if let Some(hooks) = &config.hooks {
                hooks
                    .after_create_team(OrganizationTeamEvent {
                        team: &team,
                        user: Some(&user_view),
                        organization: &organization_view,
                    })
                    .await?;
            }
            AuthResponse::json(200, &team)?
        }
        (HttpMethod::Post, "/organization/update-team") => {
            let body = body!(UpdateBody);
            let additional_fields = crate::plugins::organization::fields::parse_input(
                &input_schema(config),
                &body.data,
                &body.data.additional_fields,
                "body.data",
                true,
            )?;
            let name = (!body.data.name.is_undefined()).then_some(body.data.name);
            let organization_id =
                optional_string(body.data.organization_id, "body.data.organizationId")?;
            let org =
                resolve_organization_id(organization_id.as_deref(), None, &session, ctx).await?;
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
            let organization = ctx
                .database
                .get_organization_by_id(&org)
                .await?
                .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
            let organization_view =
                crate::plugins::organization::fields::organization(&organization, ctx);
            let event = OrganizationTeamEvent {
                team: &team,
                user: Some(&user_view),
                organization: &organization_view,
            };
            let mut updates = better_auth_core::UpdateTeam {
                additional_fields,
                name,
                ..Default::default()
            };
            if let Some(hooks) = &config.hooks {
                hooks.before_update_team(&mut updates, event).await?;
            }
            let updated = ctx.database.update_team(&team.id, updates).await?;
            let updated = crate::plugins::organization::fields::team(updated, ctx);
            if let Some(hooks) = &config.hooks {
                hooks
                    .after_update_team(OrganizationTeamEvent {
                        team: &updated,
                        ..event
                    })
                    .await?;
            }
            AuthResponse::json(200, &updated)?
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
            let organization = ctx
                .database
                .get_organization_by_id(&org)
                .await?
                .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
            let organization_view =
                crate::plugins::organization::fields::organization(&organization, ctx);
            let event = OrganizationTeamEvent {
                team: &team,
                user: Some(&user_view),
                organization: &organization_view,
            };
            if let Some(hooks) = &config.hooks {
                hooks.before_delete_team(event).await?;
            }
            ctx.database.delete_team(&team.id).await?;
            if let Some(hooks) = &config.hooks {
                hooks.after_delete_team(event).await?;
            }
            AuthResponse::json(
                200,
                &serde_json::json!({"message":"Team removed successfully."}),
            )?
        }
        (HttpMethod::Get, "/organization/list-teams") => {
            let org =
                resolve_organization_id(req.query_string("organizationId")?, None, &session, ctx)
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
                    let updated = ctx
                        .database
                        .update_session_active_team(session.token(), None)
                        .await?;
                    let manager = ctx.session_manager();
                    manager
                        .set_session_cookie(
                            req,
                            manager.internal_data(&user, &updated).await?,
                            None,
                        )
                        .await?;
                    return Ok(Some(AuthResponse::json(200, &serde_json::Value::Null)?));
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
            let updated = ctx
                .database
                .update_session_active_team(session.token(), Some(&team_id))
                .await?;
            let manager = ctx.session_manager();
            manager
                .set_session_cookie(req, manager.internal_data(&user, &updated).await?, None)
                .await?;
            AuthResponse::json(200, &team)?
        }
        (HttpMethod::Get, "/organization/list-user-teams") => {
            let target = req
                .query_string("userId")?
                .filter(|id| !id.is_empty())
                .unwrap_or(&user.id);
            let explicit_org = req
                .query_string("organizationId")?
                .filter(|id| !id.is_empty());
            let org = explicit_org.or(session.active_organization_id());
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
                        .get_member(team.organization_id.typed()?, target)
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
                .query_string("teamId")?
                .filter(|id| !id.is_empty())
                .or(session.active_team_id())
                .ok_or_else(|| AuthError::bad_request("You do not have an active team"))?;
            let team = ctx
                .database
                .get_team(team_id)
                .await?
                .ok_or_else(|| AuthError::bad_request("Team not found"))?;
            if ctx
                .database
                .get_member(team.organization_id.typed()?, &user.id())
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
            let team = find_team(&body.team_id, &org, ctx).await?;
            let organization = ctx
                .database
                .get_organization_by_id(&org)
                .await?
                .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
            let organization_view =
                crate::plugins::organization::fields::organization(&organization, ctx);
            let target_user = ctx
                .database
                .get_user_by_id(&body.user_id)
                .await?
                .ok_or_else(|| AuthError::bad_request("User not found"))?;
            let target_view = ctx.internal_user_view(&target_user)?;
            let target = OrganizationTeamMemberTarget {
                team: &team,
                organization: &organization_view,
                user: &target_view,
            };
            if adding {
                if let Some(hooks) = &config.hooks {
                    hooks.before_add_team_member(target).await?;
                }
                let maximum = config
                    .team_member_limit(OrganizationTeamMemberLimit {
                        team_id: &team.id,
                        organization_id: &org,
                        session: actor,
                    })
                    .await?;
                let member = ctx
                    .database
                    .add_team_member(&body.team_id, &body.user_id, maximum)
                    .await?
                    .ok_or_else(|| AuthError::forbidden("Team member limit reached"))?;
                if let Some(hooks) = &config.hooks {
                    hooks.after_add_team_member(&member, target).await?;
                }
                AuthResponse::json(200, &member)?
            } else {
                let member = ctx
                    .database
                    .get_team_member(&body.team_id, &body.user_id)
                    .await?
                    .ok_or_else(|| AuthError::bad_request("User is not a member of the team"))?;
                if let Some(hooks) = &config.hooks {
                    hooks.before_remove_team_member(&member, target).await?;
                }
                ctx.database
                    .remove_team_member(&body.team_id, &body.user_id)
                    .await?;
                if let Some(hooks) = &config.hooks {
                    hooks.after_remove_team_member(&member, target).await?;
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::organization::OrganizationTeamsConfig;
    use crate::plugins::test_helpers::{
        create_auth_json_request_no_query, create_test_context, create_user_and_session,
    };
    use better_auth_core::CreateTeam;
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
                additional_fields: Default::default(),
                id: None,
                name: "Teams".into(),
                slug: "teams".into(),
                logo: None.into(),
                metadata: None.into(),
            })
            .await
            .unwrap();
        ctx.database
            .create_member(CreateMember {
                additional_fields: Default::default(),
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
                ..Default::default()
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
        assert_eq!(
            full.teams.unwrap()[0].team.additional_fields["memberCount"].as_f64(),
            Some(1.0)
        );
        let foreign_org = ctx
            .database
            .create_organization(CreateOrganization {
                additional_fields: Default::default(),
                id: None,
                name: "Foreign".into(),
                slug: "foreign-teams".into(),
                logo: None.into(),
                metadata: None.into(),
            })
            .await
            .unwrap();
        let foreign = ctx
            .database
            .create_team(CreateTeam {
                name: "Foreign".into(),
                organization_id: foreign_org.id,
                updated_at: None,
                ..Default::default()
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
        let active_response =
            crate::plugins::test_helpers::finalize_response(&ctx, &active, active_response);
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
