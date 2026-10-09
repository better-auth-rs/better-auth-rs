use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::{AuthContext, AuthRoute};
use better_auth_core::session::NativeSessionData;
use better_auth_core::types::{AuthRequest, AuthResponse, HttpMethod, Team};
use serde::Deserialize;
use validator::Validate;

use super::{require_native_session, resolve_organization_id};
use crate::plugins::organization::hooks::*;
use crate::plugins::organization::types::{NullableStringField, deserialize_nullable_string_field};
use crate::plugins::organization::{OrganizationConfig, rbac::check_permission};

mod lifecycle;

#[cfg(test)]
#[path = "team_input_tests.rs"]
mod input_tests;

use crate::plugins::organization::request::{from_fields, object, take};
use better_auth_core::{AuthRecordFields, FieldMap, FieldValue, FromFieldMap};

from_fields!(CreateBody { name: "name", organization_id: "organizationId" }; additional_fields);
from_fields!(UpdateData { name: "name", organization_id: "organizationId" }; additional_fields);
from_fields!(TeamBody {
    team_id: "teamId",
    organization_id: "organizationId"
});
from_fields!(MemberBody {
    team_id: "teamId",
    user_id: "userId",
    organization_id: "organizationId"
});
from_fields!(ActiveBody { team_id: "teamId" });

impl FromFieldMap for UpdateBody {
    fn from_field_values(mut fields: FieldMap) -> AuthResult<Self> {
        Ok(Self {
            team_id: take(&mut fields, "teamId")?,
            data: UpdateData::from_field_values(object(&mut fields, "data")?)?,
        })
    }
}

pub(crate) fn routes() -> Vec<AuthRoute> {
    vec![
        AuthRoute::post("/organization/create-team", "createTeam"),
        AuthRoute::post("/organization/update-team", "updateTeam").require_headers(true),
        AuthRoute::post("/organization/remove-team", "removeTeam"),
        AuthRoute::post("/organization/set-active-team", "setActiveTeam").require_headers(true),
        AuthRoute::post("/organization/add-team-member", "addTeamMember").require_headers(true),
        AuthRoute::post("/organization/remove-team-member", "removeTeamMember")
            .require_headers(true),
        AuthRoute::get("/organization/list-teams", "listOrganizationTeams")
            .require_headers(true)
            .query_validator(crate::plugins::query_input::organization_id),
        AuthRoute::get("/organization/list-user-teams", "listUserTeams")
            .require_headers(true)
            .query_validator(crate::plugins::query_input::user_teams),
        AuthRoute::get("/organization/list-team-members", "listTeamMembers")
            .require_headers(true)
            .query_validator(crate::plugins::query_input::team_members),
    ]
}

#[derive(Clone, Deserialize, serde::Serialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins::organization) struct CreateBody {
    #[serde(flatten)]
    #[serde(with = "better_auth_core::field_value::serde::map")]
    additional_fields: better_auth_core::FieldMap,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted"
    )]
    name: better_auth_core::SchemaValue<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_nullable_string_field",
        skip_serializing_if = "NullableStringField::is_missing"
    )]
    organization_id: NullableStringField,
}
#[derive(Clone, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins::organization) struct TeamBody {
    team_id: String,
    organization_id: Option<String>,
}
#[derive(Clone, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins::organization) struct MemberBody {
    team_id: String,
    user_id: String,
    organization_id: Option<String>,
}
#[derive(Clone, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins::organization) struct UpdateBody {
    team_id: String,
    data: UpdateData,
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins::organization) struct UpdateData {
    #[serde(flatten)]
    #[serde(with = "better_auth_core::field_value::serde::map")]
    additional_fields: better_auth_core::FieldMap,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted"
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

#[derive(Clone, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins::organization) struct ActiveBody {
    #[serde(
        default,
        deserialize_with = "crate::plugins::organization::types::deserialize_nullable_string_field"
    )]
    team_id: crate::plugins::organization::types::NullableStringField,
}

pub(crate) async fn find_team(
    team_id: &FieldValue,
    organization_id: &FieldValue,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<Team> {
    let details = ctx
        .database
        .get_team_details_value(team_id, Some(organization_id), false)
        .await?
        .ok_or_else(|| AuthError::bad_request("Team not found"))?;
    Ok(details.into_public_parts(&config.schema.team)?.0)
}

fn public_teams(teams: Vec<Team>, config: &OrganizationConfig) -> AuthResult<Vec<Team>> {
    teams
        .into_iter()
        .map(|team| crate::plugins::organization::fields::team(team, config))
        .collect()
}

fn teams_response(teams: Vec<Team>) -> AuthResult<AuthResponse> {
    let teams = teams
        .into_iter()
        .map(|team| team.field_values().map(FieldValue::from))
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(AuthResponse::native(None, teams.into()))
}

async fn list_teams(
    organization_id: &FieldValue,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<Vec<Team>> {
    public_teams(
        ctx.database
            .list_organization_teams_value(organization_id)
            .await?,
        config,
    )
}

async fn authorize(
    member: &better_auth_core::Member,
    org_id: &FieldValue,
    permission: (&str, &str),
    message: &'static str,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
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
    match (req.method(), req.path()) {
        (HttpMethod::Post, "/organization/create-team") => {
            return lifecycle::create(req, ctx, config).await.map(Some);
        }
        (HttpMethod::Post, "/organization/remove-team") => {
            return lifecycle::remove(req, ctx, config).await.map(Some);
        }
        _ => {}
    }
    let data = require_native_session(req, ctx).await?;
    let session = &data.session;
    let actor = OrganizationSession {
        user: &data.user,
        session,
    };
    macro_rules! body {
        ($ty:ty) => {
            super::super::request::read::<$ty>(req, &config.schema)?
        };
    }
    let response = match (req.method(), req.path()) {
        (HttpMethod::Post, "/organization/update-team") => {
            let body = body!(UpdateBody);
            let additional_fields = body.data.additional_fields.clone();
            let name = (!body.data.name.is_undefined()).then_some(body.data.name);
            let organization_id =
                optional_string(body.data.organization_id, "body.data.organizationId")?;
            let org =
                resolve_organization_id(organization_id.as_deref(), None, session, ctx).await?;
            let member = ctx
                .database
                .get_member_with_user_value(&org, &data.user_property("id")?)
                .await?
                .ok_or_else(|| AuthError::forbidden("You are not allowed to update this team"))?;
            authorize(
                &member.member,
                &org,
                ("team", "update"),
                "You are not allowed to update this team",
                config,
                ctx,
            )
            .await?;
            let team = find_team(&body.team_id.as_str().into(), &org, ctx, config).await?;
            if !team.organization_id.field_value().strict_equals(&org) {
                return Err(AuthError::bad_request("Team not found"));
            }
            let organization = ctx
                .database
                .get_organization_by_id_value(&org)
                .await?
                .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
            let organization_view =
                crate::plugins::organization::fields::organization(&organization, ctx);
            let event = OrganizationTeamEvent {
                team: &team,
                user: Some(&data.user),
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
            let updated = ctx
                .database
                .update_team_value(&team.id.field_value(), updates)
                .await?;
            let updated = crate::plugins::organization::fields::team(updated, config)?;
            if let Some(hooks) = &config.hooks {
                hooks
                    .after_update_team(OrganizationTeamEvent {
                        team: &updated,
                        ..event
                    })
                    .await?;
            }
            AuthResponse::native(None, updated.field_values()?.into())
        }
        (HttpMethod::Get, "/organization/list-teams") => {
            let org =
                resolve_organization_id(req.query_string("organizationId")?, None, session, ctx)
                    .await?;
            if ctx
                .database
                .get_member_with_user_value(&org, &data.user_property("id")?)
                .await?
                .is_none()
            {
                return Err(AuthError::forbidden(
                    "You are not allowed to access this organization as an owner",
                ));
            }
            teams_response(list_teams(&org, ctx, config).await?)?
        }
        (HttpMethod::Post, "/organization/set-active-team") => {
            use crate::plugins::organization::types::NullableStringField;
            let body = body!(ActiveBody);
            let team_id = match body.team_id {
                NullableStringField::Null => {
                    if !session.active_team_id.field_value().is_truthy() {
                        return Ok(Some(AuthResponse::json(None, &serde_json::Value::Null)?));
                    }
                    let updated = ctx
                        .database
                        .update_session_active_team_by_token_value(
                            &session.token.field_value(),
                            None,
                        )
                        .await?;
                    let manager = ctx.session_manager();
                    manager
                        .set_native_session_cookie(
                            req,
                            NativeSessionData {
                                session: updated,
                                user: data.user.clone(),
                            },
                            None,
                        )
                        .await?;
                    return Ok(Some(AuthResponse::json(None, &serde_json::Value::Null)?));
                }
                NullableStringField::Value(id) if !id.is_empty() => FieldValue::from(id),
                _ => session.active_team_id.field_value(),
            };
            if !team_id.is_truthy() {
                return Ok(Some(AuthResponse::json(None, &serde_json::Value::Null)?));
            }
            let org = resolve_organization_id(None, None, session, ctx).await?;
            let team = find_team(&team_id, &org, ctx, config).await?;
            if ctx
                .database
                .get_team_member_value(&team_id, &data.user_property("id")?)
                .await?
                .is_none()
            {
                return Err(AuthError::forbidden("User is not a member of the team"));
            }
            let updated = ctx
                .database
                .update_session_active_team_by_token_value(
                    &session.token.field_value(),
                    Some(&team.id.field_value()),
                )
                .await?;
            let manager = ctx.session_manager();
            manager
                .set_native_session_cookie(
                    req,
                    NativeSessionData {
                        session: updated,
                        user: data.user.clone(),
                    },
                    None,
                )
                .await?;
            AuthResponse::native(None, team.field_values()?.into())
        }
        (HttpMethod::Get, "/organization/list-user-teams") => {
            let target = req
                .query_string("userId")?
                .filter(|id| !id.is_empty())
                .map(FieldValue::from)
                .map(Ok)
                .unwrap_or_else(|| data.user_property("id"))?;
            let is_self = target.strict_equals(&data.user_property("id")?);
            let explicit_org = req
                .query_string("organizationId")?
                .filter(|id| !id.is_empty());
            let org = explicit_org
                .map(FieldValue::from)
                .unwrap_or_else(|| session.active_organization_id.field_value());
            if !is_self || explicit_org.is_some() {
                if !org.is_truthy() {
                    return Err(AuthError::bad_request("No active organization"));
                }
                let member = ctx
                    .database
                    .get_member_with_user_value(&org, &data.user_property("id")?)
                    .await?
                    .ok_or_else(|| {
                        AuthError::forbidden("You are not a member of this organization")
                    })?;
                if !is_self {
                    authorize(
                        &member.member,
                        &org,
                        ("member", "update"),
                        "You are not allowed to update this member",
                        config,
                        ctx,
                    )
                    .await?;
                    if ctx
                        .database
                        .get_member_with_user_value(&org, &target)
                        .await?
                        .is_none()
                    {
                        return Err(AuthError::bad_request(
                            "User is not a member of the organization",
                        ));
                    }
                }
                let teams =
                    public_teams(ctx.database.list_user_teams_value(&target).await?, config)?
                        .into_iter()
                        .filter(|team| team.organization_id.field_value().strict_equals(&org))
                        .collect::<Vec<_>>();
                teams_response(teams)?
            } else {
                let mut teams = Vec::new();
                for team in
                    public_teams(ctx.database.list_user_teams_value(&target).await?, config)?
                {
                    if ctx
                        .database
                        .get_member_value(&team.organization_id.field_value(), &target)
                        .await?
                        .is_some()
                    {
                        teams.push(team);
                    }
                }
                teams_response(teams)?
            }
        }
        (HttpMethod::Get, "/organization/list-team-members") => {
            let team_id = req
                .query_string("teamId")?
                .filter(|id| !id.is_empty())
                .map(FieldValue::from)
                .unwrap_or_else(|| session.active_team_id.field_value());
            if !team_id.is_truthy() {
                return Err(AuthError::bad_request("You do not have an active team"));
            }
            let details = ctx
                .database
                .get_team_details_value(&team_id, None, false)
                .await?
                .ok_or_else(|| AuthError::bad_request("Team not found"))?;
            let team = details.into_public_parts(&config.schema.team)?.0;
            if ctx
                .database
                .get_member_value(
                    &team.organization_id.field_value(),
                    &data.user_property("id")?,
                )
                .await?
                .is_none()
                || ctx
                    .database
                    .get_team_member_value(&team_id, &data.user_property("id")?)
                    .await?
                    .is_none()
            {
                return Err(AuthError::bad_request("User is not a member of the team"));
            }
            let members = ctx.database.list_team_members_value(&team_id).await?;
            let members = members
                .iter()
                .map(|member| member.field_values().map(FieldValue::from))
                .collect::<AuthResult<Vec<_>>>()?;
            AuthResponse::native(None, members.into())
        }
        (
            HttpMethod::Post,
            "/organization/add-team-member" | "/organization/remove-team-member",
        ) => {
            let body = body!(MemberBody);
            let org = resolve_organization_id(body.organization_id.as_deref(), None, session, ctx)
                .await?;
            let member = ctx
                .database
                .get_member_with_user_value(&org, &data.user_property("id")?)
                .await?
                .ok_or_else(|| {
                    AuthError::bad_request("User is not a member of the organization")
                })?;
            let adding = req.path() == "/organization/add-team-member";
            authorize(
                &member.member,
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
                .get_member_with_user_value(&org, &body.user_id.as_str().into())
                .await?
                .is_none()
            {
                return Err(AuthError::bad_request(
                    "User is not a member of the organization",
                ));
            }
            let team = find_team(&body.team_id.as_str().into(), &org, ctx, config).await?;
            let organization = ctx
                .database
                .get_organization_by_id_value(&org)
                .await?
                .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
            let organization_view =
                crate::plugins::organization::fields::organization(&organization, ctx);
            let target_user = ctx
                .database
                .get_user_by_id(&body.user_id)
                .await?
                .ok_or_else(|| AuthError::bad_request("User not found"))?;
            let target_value = FieldValue::from(FieldMap::from(target_user));
            let target = OrganizationTeamMemberTarget {
                team: &team,
                organization: &organization_view,
                user: &target_value,
            };
            if adding {
                if let Some(hooks) = &config.hooks {
                    hooks.before_add_team_member(target).await?;
                }
                let maximum = config
                    .team_member_limit(OrganizationTeamMemberLimit {
                        team_id: &body.team_id.as_str().into(),
                        organization_id: &org,
                        session: actor,
                    })
                    .await?;
                let member = ctx
                    .database
                    .add_team_member(&body.team_id.clone().into(), &body.user_id, maximum)
                    .await?
                    .ok_or_else(|| AuthError::forbidden("Team member limit reached"))?;
                if let Some(hooks) = &config.hooks {
                    hooks.after_add_team_member(&member, target).await?;
                }
                AuthResponse::native(None, member.field_values()?.into())
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
                    None,
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
    use crate::plugins::organization::{OrganizationPlugin, OrganizationTeamsConfig};
    use crate::plugins::test_helpers::{
        create_auth_json_request_no_query, create_test_config, create_test_context_with_plugins,
        create_user_and_session,
    };
    use better_auth_core::CreateTeam;
    use better_auth_core::{CreateMember, CreateOrganization, CreateUser};
    use chrono::Duration;

    #[tokio::test]
    async fn team_membership_is_idempotent_and_team_scope_is_enforced() {
        let config = OrganizationConfig {
            teams: OrganizationTeamsConfig {
                enabled: true,
                maximum_members_per_team: Some(1),
                ..Default::default()
            },
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
            .update_session_active_organization(
                session.token.typed().unwrap(),
                Some(org.id.typed().unwrap()),
            )
            .await
            .unwrap();
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
            Some(session.token.typed().unwrap()),
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
        assert_eq!(first.body.bytes().unwrap(), duplicate.body.bytes().unwrap());
        assert_eq!(
            ctx.database
                .list_team_members(team.id.typed().unwrap())
                .await
                .unwrap()
                .len(),
            1
        );
        let full = super::super::org::get_full_organization_core(
            &crate::plugins::organization::types::GetFullOrganizationQuery {
                organization_id: Some(org.id.typed().unwrap().clone()),
                ..Default::default()
            },
            &(user.clone(), session.clone()).into(),
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
            Some(session.token.typed().unwrap()),
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
            Some(session.token.typed().unwrap()),
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
            Some(session.token.typed().unwrap()),
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
