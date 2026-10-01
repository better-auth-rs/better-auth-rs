use super::{require_session, resolve_organization_id};
use crate::plugins::organization::rbac::check_permission;
use crate::plugins::organization::types::{
    BasicMemberResponse, CheckSlugRequest, CheckSlugResponse, CreateOrganizationRequest,
    CreateOrganizationResponse, CreatedOrganizationResponse, DeleteOrganizationRequest,
    FullOrganizationResponse, GetFullOrganizationQuery, LeaveOrganizationRequest, MemberResponse,
    NullableStringField, OrganizationResponse, SetActiveOrganizationRequest,
    UpdateOrganizationRequest,
};
use crate::plugins::organization::{OrganizationConfig, hooks::*};
use better_auth_core::entity::{AuthMember, AuthOrganization, AuthSession, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::store::ListOrganizationMembersParams;
use better_auth_core::types::{AuthRequest, AuthResponse, CreateOrganization, UpdateOrganization};
use better_auth_core::wire::InvitationView;
use std::collections::HashMap;

fn validate_metadata_input(value: Option<&serde_json::Value>, path: &str) -> AuthResult<()> {
    if let Some(value) = value {
        let received = match value {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => return Ok(()),
        };
        return Err(AuthError::FieldInput {
            code: "VALIDATION_ERROR",
            message: format!("[{path}] Invalid input: expected record, received {received}"),
        });
    }
    Ok(())
}

fn has_role(member: &impl AuthMember, role: &str) -> AuthResult<bool> {
    Ok(member
        .role()
        .typed()?
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == role))
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

pub(crate) async fn create_organization_core(
    body: &CreateOrganizationRequest,
    user: &impl AuthUser,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: Option<&AuthRequest>,
) -> AuthResult<(
    CreateOrganizationResponse<CreatedOrganizationResponse, BasicMemberResponse>,
    Option<String>,
)> {
    let user_view = ctx.user_view(user)?;
    if !config.may_create(&user_view).await? {
        return Err(AuthError::Upstream {
            status: 403,
            code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION",
            message: "You are not allowed to create a new organization",
        });
    }
    let user_orgs = ctx.database.list_user_organizations(&user.id()).await?;
    if config
        .organization_limit_reached(&user_view, user_orgs.len())
        .await?
    {
        return Err(AuthError::Upstream {
            status: 403,
            code: "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS",
            message: "You have reached the maximum number of organizations",
        });
    }

    if ctx
        .database
        .get_organization_by_slug_value(&body.slug.json()?.unwrap_or(serde_json::Value::Null))
        .await?
        .is_some()
    {
        return Err(AuthError::bad_request("Organization already exists"));
    }

    let mut org_data = CreateOrganization {
        additional_fields: body.additional_fields.clone(),
        id: body
            .additional_fields
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        name: body.name.clone(),
        slug: body.slug.clone(),
        logo: body.logo.clone(),
        metadata: body.metadata.clone(),
    };

    if let Some(hooks) = &config.hooks {
        hooks
            .before_create_organization(&mut org_data, &user_view)
            .await?;
    }
    org_data.metadata = better_auth_core::SchemaValue::from_json(
        org_data
            .metadata
            .json()?
            .filter(better_auth_core::user_fields::is_truthy),
    );
    let mut organization = ctx.database.create_organization(org_data).await?;
    organization.metadata = super::super::native_json::metadata(organization.metadata, true)?;
    let organization_view =
        crate::plugins::organization::fields::created_organization(&organization, ctx);

    let mut member_data = OrganizationMemberDraft {
        additional_fields: Default::default(),
        team_id: None,
        created_at: None,
        organization_id: organization.id().to_string(),
        user_id: user.id().to_string(),
        role: if config.creator_role.is_empty() {
            "owner".into()
        } else {
            config.creator_role.clone().into()
        },
    };

    if let Some(hooks) = &config.hooks {
        hooks
            .before_add_member(
                &mut member_data,
                OrganizationUser {
                    organization: &organization_view,
                    user: &user_view,
                },
            )
            .await?;
    }
    let member = ctx
        .database
        .create_member(member_data.into_create())
        .await?;
    let event = OrganizationMemberEvent {
        member: &member,
        user: &user_view,
        organization: &organization_view,
    };
    if let Some(hooks) = &config.hooks {
        hooks.after_add_member(event).await?;
    }
    let mut default_team_id = None;
    if config.teams.enabled && config.teams.default_team {
        let created_at = chrono::Utc::now();
        let mut team_data = OrganizationTeamDraft {
            additional_fields: Default::default(),
            id: None,
            name: organization.name.display_string()?.into(),
            organization_id: organization.id.clone(),
            created_at: None,
            updated_at: None,
        };
        if let Some(hooks) = &config.hooks {
            hooks
                .before_create_team(&mut team_data, &organization_view, Some(&user_view))
                .await?;
        }
        let team = match config
            .custom_default_team(&organization_view, OrganizationEndpoint::new(ctx, request))
            .await?
        {
            Some(team) => team,
            None => {
                ctx.database
                    .create_team(team_data.into_create(created_at, None))
                    .await?
            }
        };
        let team = crate::plugins::organization::fields::team(team, ctx);
        let _ = ctx
            .database
            .add_team_member(&team.id, &user.id(), None)
            .await?;
        if let Some(hooks) = &config.hooks {
            hooks
                .after_create_team(OrganizationTeamEvent {
                    team: &team,
                    user: Some(&user_view),
                    organization: &organization_view,
                })
                .await?;
        }
        default_team_id = Some(team.id);
    }
    if let Some(hooks) = &config.hooks {
        hooks.after_create_organization(event).await?;
    }
    let mut response = CreatedOrganizationResponse::from_organization(&organization);
    if let Some(serde_json::Value::String(value)) = response.metadata.json()?
        && !value.is_empty()
    {
        response.metadata =
            better_auth_core::SchemaValue::Dynamic(super::super::native_json::parse_json(&value)?);
    }
    Ok((
        CreateOrganizationResponse {
            organization: response,
            members: vec![BasicMemberResponse::from_member(&member)],
        },
        default_team_id,
    ))
}

pub(crate) async fn update_organization_core(
    body: &UpdateOrganizationRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<CreatedOrganizationResponse> {
    let nonempty = |field: &NullableStringField, name: &str| -> AuthResult<Option<String>> {
        let message = match field {
            NullableStringField::Missing => return Ok(None),
            NullableStringField::Value(value) if !value.is_empty() => {
                return Ok(Some(value.clone()));
            }
            NullableStringField::Value(_) => "Too small: expected string to have >=1 characters",
            NullableStringField::Null => "Invalid input: expected string, received null",
        };
        Err(AuthError::FieldInput {
            code: "VALIDATION_ERROR",
            message: format!("[body.data.{name}] {message}"),
        })
    };
    let name = nonempty(&body.data.name, "name")?;
    let slug = nonempty(&body.data.slug, "slug")?;
    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, session, ctx).await?;

    let member = ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    if !check_permission(
        member.role().typed()?,
        &org_id,
        "organization",
        &["update"],
        config,
        ctx,
    )
    .await?
    {
        return Err(AuthError::forbidden(
            "You are not allowed to update this organization",
        ));
    }

    if let Some(ref new_slug) = slug
        && let Some(existing) = ctx.database.get_organization_by_slug(new_slug).await?
        && existing.id() != org_id
    {
        return Err(AuthError::bad_request("Organization slug already taken"));
    }

    let mut update_data = UpdateOrganization {
        additional_fields: body.data.additional_fields.clone(),
        name,
        slug,
        logo: match &body.data.logo {
            NullableStringField::Missing => None,
            NullableStringField::Null => Some(None),
            NullableStringField::Value(value) => Some(Some(value.clone())),
        },
        metadata: body.data.metadata.clone(),
        ..Default::default()
    };

    let user_view = ctx.user_view(user)?;
    let actor = OrganizationActor {
        member: &member,
        user: &user_view,
    };
    if let Some(hooks) = &config.hooks {
        hooks
            .before_update_organization(&mut update_data, actor)
            .await?;
    }
    let mut updated = ctx
        .database
        .update_organization(&org_id, update_data)
        .await?;
    updated.metadata = super::super::native_json::metadata(updated.metadata, false)?;

    if let Some(hooks) = &config.hooks {
        hooks
            .after_update_organization(
                &crate::plugins::organization::fields::created_organization(&updated, ctx),
                actor,
            )
            .await?;
    }
    Ok(CreatedOrganizationResponse::from_organization(&updated))
}

pub(crate) async fn delete_organization_core(
    body: &DeleteOrganizationRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    request: Option<&AuthRequest>,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<OrganizationResponse> {
    if config.disable_organization_deletion {
        return Err(AuthError::Upstream {
            status: 404,
            code: "ORGANIZATION_DELETION_DISABLED",
            message: "Organization deletion is disabled",
        });
    }

    let member = ctx
        .database
        .get_member(&body.organization_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::bad_request("User is not a member of the organization"))?;

    if !check_permission(
        member.role().typed()?,
        &body.organization_id,
        "organization",
        &["delete"],
        config,
        ctx,
    )
    .await?
    {
        return Err(AuthError::forbidden(
            "You are not allowed to delete this organization",
        ));
    }

    if session.active_organization_id() == Some(&body.organization_id) {
        let _ = ctx
            .database
            .update_session_active_organization(session.token(), None)
            .await?;
    }
    let organization = ctx
        .database
        .get_organization_by_id(&body.organization_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = crate::plugins::organization::fields::organization(&organization, ctx);

    let user_view = ctx.user_view(user)?;
    let event = OrganizationUser {
        organization: &organization_view,
        user: &user_view,
    };
    if let Some(hooks) = &config.hooks {
        hooks
            .before_delete_organization(event, OrganizationEndpoint::new(ctx, request))
            .await?;
    }
    ctx.database
        .delete_organization(&body.organization_id)
        .await?;

    if let Some(hooks) = &config.hooks {
        hooks
            .after_delete_organization(event, OrganizationEndpoint::new(ctx, request))
            .await?;
    }
    Ok(crate::plugins::organization::fields::organization(
        &organization,
        ctx,
    ))
}

pub(crate) async fn list_organizations_core(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<OrganizationResponse>> {
    let organizations = ctx.database.list_user_organizations(&user.id()).await?;
    Ok(organizations
        .iter()
        .map(OrganizationResponse::from_organization)
        .collect())
}

pub(crate) async fn get_full_organization_core(
    query: &GetFullOrganizationQuery,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Option<FullOrganizationResponse<OrganizationResponse, InvitationView>>> {
    let org_id = if let Some(slug) = query.organization_slug.as_deref() {
        let organization = ctx
            .database
            .get_organization_by_slug(slug)
            .await?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        organization.id().to_string()
    } else if let Some(id) = query.organization_id.as_deref() {
        id.to_string()
    } else if let Some(active_org_id) = session.active_organization_id() {
        active_org_id.to_string()
    } else {
        return Ok(None);
    };

    let _ = ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("User is not a member of the organization"))?;

    let organization = ctx
        .database
        .get_organization_by_id(&org_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;

    let members_limit = query
        .members_limit
        .filter(|limit| *limit > 0)
        .or(Some(config.member_list_limit()));
    let member_params = ListOrganizationMembersParams {
        organization_id: org_id.clone(),
        limit: members_limit,
        ..Default::default()
    };
    let (members_raw, _) = ctx
        .database
        .query_organization_members(&member_params)
        .await?;
    let user_ids = members_raw
        .iter()
        .map(|member| member.user_id.typed().cloned())
        .collect::<AuthResult<Vec<_>>>()?;
    let users_by_id = ctx
        .database
        .list_users_by_ids(&user_ids)
        .await?
        .into_iter()
        .map(|user| (user.id().to_string(), user))
        .collect::<HashMap<_, _>>();
    let mut members = Vec::with_capacity(members_raw.len());

    for member in &members_raw {
        if let Some(user_info) = users_by_id.get(member.user_id.typed()?) {
            members.push(MemberResponse::from_member_and_user(member, user_info));
        }
    }

    let invitations = ctx.database.list_organization_invitations(&org_id).await?;

    let teams = if config.teams.enabled {
        let mut teams = Vec::new();
        for team in ctx.database.list_organization_teams(&org_id).await? {
            teams.push(crate::plugins::organization::types::FullOrganizationTeam { team });
        }
        Some(teams)
    } else {
        None
    };
    Ok(Some(FullOrganizationResponse {
        organization: crate::plugins::organization::fields::organization(&organization, ctx),
        members,
        invitations: invitations.iter().map(InvitationView::from).collect(),
        teams,
    }))
}

pub(crate) async fn check_slug_core(
    body: &CheckSlugRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<CheckSlugResponse> {
    if ctx
        .database
        .get_organization_by_slug(&body.slug)
        .await?
        .is_some()
    {
        return Err(AuthError::bad_request("Organization slug already taken"));
    }

    Ok(CheckSlugResponse { status: true })
}

pub(crate) async fn set_active_organization_core(
    req: &AuthRequest,
    body: &SetActiveOrganizationRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Option<OrganizationResponse>> {
    if matches!(body.organization_id, NullableStringField::Null) {
        if session.active_organization_id().is_none() {
            return Ok(None);
        }

        let updated = ctx
            .database
            .update_session_active_organization(session.token(), None)
            .await?;
        let manager = ctx.session_manager();
        manager
            .set_session_cookie(req, manager.internal_data(user, &updated).await?, None)
            .await?;
        return Ok(None);
    }

    let org_id = if let NullableStringField::Value(id) = &body.organization_id {
        id.clone()
    } else if let Some(slug) = body.organization_slug.as_deref() {
        let organization = ctx
            .database
            .get_organization_by_slug(slug)
            .await?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        organization.id().to_string()
    } else if let Some(active_org_id) = session.active_organization_id() {
        active_org_id.to_string()
    } else {
        return Ok(None);
    };

    let _ = ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("User is not a member of the organization"))?;

    let organization = ctx
        .database
        .get_organization_by_id(&org_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;

    let updated = ctx
        .database
        .update_session_active_organization(session.token(), Some(&org_id))
        .await?;
    let manager = ctx.session_manager();
    manager
        .set_session_cookie(req, manager.internal_data(user, &updated).await?, None)
        .await?;

    Ok(Some(crate::plugins::organization::fields::organization(
        &organization,
        ctx,
    )))
}

pub(crate) async fn leave_organization_core(
    body: &LeaveOrganizationRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<MemberResponse> {
    let member = ctx
        .database
        .get_member(&body.organization_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    if has_role(&member, &config.creator_role)? {
        let all_members = ctx
            .database
            .list_organization_members(&body.organization_id)
            .await?;
        let owner_count =
            all_members
                .iter()
                .try_fold(0, |count, candidate| -> AuthResult<usize> {
                    Ok(count + usize::from(has_role(candidate, &config.creator_role)?))
                })?;

        if owner_count <= 1 {
            return Err(AuthError::bad_request(
                "You cannot leave the organization as the only owner",
            ));
        }
    }

    let response = MemberResponse::from_member_and_user(&member, user);
    ctx.database.delete_member(&member.id()).await?;

    if session.active_organization_id() == Some(&body.organization_id) {
        let _ = ctx
            .database
            .update_session_active_organization(session.token(), None)
            .await?;
    }

    Ok(response)
}

// ---------------------------------------------------------------------------
// Old handlers (rewritten to call core)
// ---------------------------------------------------------------------------

/// Handle create organization request
pub async fn handle_create_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let mut body: CreateOrganizationRequest = req
        .body_as_json()
        .map_err(|error| AuthError::bad_request(format!("Invalid JSON: {error}")))?;
    let mut schema = config.schema.organization.clone();
    for (name, required) in [("name", true), ("slug", true), ("logo", false)] {
        if !schema
            .additional_fields
            .get(name)
            .is_some_and(|field| field.input)
        {
            let _ = schema.additional_fields.insert(
                name.into(),
                better_auth_core::user_fields::UserFieldConfig {
                    required: Some(required),
                    ..Default::default()
                },
            );
        }
    }
    if !config
        .schema
        .organization
        .additional_fields
        .get("metadata")
        .is_some_and(|field| field.input)
    {
        validate_metadata_input(body.metadata.json()?.as_ref(), "body.metadata")?;
    }
    body.additional_fields = crate::plugins::organization::fields::parse_input(
        &schema,
        &body,
        &body.additional_fields,
        "body",
        false,
    )?;
    for (name, value) in [("name", &body.name), ("slug", &body.slug)] {
        if !config
            .schema
            .organization
            .additional_fields
            .get(name)
            .is_some_and(|field| field.input)
            && value.typed()?.is_empty()
        {
            return Err(AuthError::FieldInput {
                code: "VALIDATION_ERROR",
                message: format!("[body.{name}] Too small: expected string to have >=1 characters"),
            });
        }
    }
    let (response, default_team_id) =
        create_organization_core(&body, &user, config, ctx, Some(req)).await?;
    if !body.keep_current_active_organization.unwrap_or(false) {
        let _ = ctx
            .database
            .update_session_active_organization(
                session.token(),
                Some(response.organization.id.as_str()),
            )
            .await?;
    }
    if !body.keep_current_active_organization.unwrap_or(false)
        && let Some(team_id) = default_team_id
    {
        let _ = ctx
            .database
            .update_session_active_team(session.token(), Some(&team_id))
            .await?;
    }
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle update organization request
pub async fn handle_update_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let raw: serde_json::Value = req
        .body_as_json()
        .map_err(|error| AuthError::bad_request(format!("Invalid JSON: {error}")))?;
    let base = better_auth_core::user_fields::UserConfig {
        additional_fields: [("name", true), ("slug", true), ("logo", false)]
            .into_iter()
            .map(|(name, required)| {
                (
                    name.to_owned(),
                    better_auth_core::user_fields::UserFieldConfig {
                        required: Some(required),
                        ..Default::default()
                    },
                )
            })
            .collect(),
    };
    if let Some(data) = raw.get("data").and_then(serde_json::Value::as_object) {
        let _ = base.parse_organization_input(data, "body.data", true)?;
    }
    let mut body: UpdateOrganizationRequest = serde_json::from_value(raw)
        .map_err(|error| AuthError::bad_request(format!("Invalid JSON: {error}")))?;
    validate_metadata_input(body.data.metadata.as_ref(), "body.data.metadata")?;
    let mut schema = config.schema.organization.clone();
    // The upstream update schema applies base fields after additional fields.
    schema
        .additional_fields
        .retain(|name, _| !matches!(name.as_str(), "name" | "slug" | "logo" | "metadata"));
    body.data.additional_fields =
        schema.parse_organization_input(&body.data.additional_fields, "body.data", true)?;
    let updated = update_organization_core(&body, &user, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &updated)?)
}

/// Handle delete organization request
pub async fn handle_delete_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: DeleteOrganizationRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let response = delete_organization_core(&body, &user, &session, Some(req), config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle list organizations request
pub async fn handle_list_organizations(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let organizations = list_organizations_core(&user, ctx).await?;
    Ok(AuthResponse::json(200, &organizations)?)
}

/// Get organization metadata for a member, without expanding members or invitations.
pub async fn handle_get_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let nonempty = |key: &str| req.query.get(key).filter(|value| !value.is_empty());
    let organization = if let Some(slug) = nonempty("organizationSlug") {
        ctx.database.get_organization_by_slug(slug).await?
    } else if let Some(id) = nonempty("organizationId")
        .map(String::as_str)
        .or(session.active_organization_id())
    {
        ctx.database.get_organization_by_id(id).await?
    } else {
        return Ok(AuthResponse::json(200, &serde_json::Value::Null)?);
    }
    .ok_or_else(|| AuthError::bad_request("Organization not found"))?;

    if ctx
        .database
        .get_member(&organization.id(), &user.id())
        .await?
        .is_none()
    {
        _ = ctx
            .database
            .update_session_active_organization(session.token(), None)
            .await?;
        return Err(AuthError::forbidden(
            "User is not a member of the organization",
        ));
    }
    Ok(AuthResponse::json(
        200,
        &crate::plugins::organization::fields::organization(&organization, ctx),
    )?)
}

/// Handle get full organization request
pub async fn handle_get_full_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let query = parse_query::<GetFullOrganizationQuery>(&req.query);
    let response = get_full_organization_core(&query, &user, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle check slug request
pub async fn handle_check_slug(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let _ = require_session(req, ctx).await?;
    let body: CheckSlugRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let response = check_slug_core(&body, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle set active organization request
pub async fn handle_set_active_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: SetActiveOrganizationRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let organization = set_active_organization_core(req, &body, &user, &session, ctx).await?;
    Ok(AuthResponse::json(200, &organization)?)
}

/// Handle leave organization request
pub async fn handle_leave_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: LeaveOrganizationRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let response = leave_organization_core(&body, &user, &session, config, ctx).await?;
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

#[cfg(test)]
mod tests {

    use better_auth_core::types::{CreateOrganization, CreateUser, HttpMethod};
    use chrono::Duration;

    use crate::plugins::organization::OrganizationConfig;
    use crate::plugins::test_helpers::{
        create_auth_json_request_no_query, create_test_context, create_user,
        create_user_and_session,
    };

    use super::{get_full_organization_core, handle_create_organization};
    use crate::plugins::organization::types::GetFullOrganizationQuery;

    fn test_config() -> OrganizationConfig {
        OrganizationConfig {
            allow_user_to_create_organization: true,
            organization_limit: None,
            membership_limit: Some(100),
            creator_role: "owner".to_string(),
            invitation_expires_in: 60 * 60 * 48,
            invitation_limit: Some(100),
            disable_organization_deletion: false,
            roles: None,
            send_invitation_email: None,
            ..Default::default()
        }
    }

    fn test_user(email: &str, name: &str) -> CreateUser {
        CreateUser {
            email: Some(email.to_string()),
            name: Some(name.to_string()),
            ..CreateUser::default()
        }
    }

    #[tokio::test]
    async fn create_organization_keeps_current_active_organization_when_requested() {
        let ctx = create_test_context().await;
        let config = test_config();
        let (user, session) = create_user_and_session(
            &ctx,
            test_user("owner@example.com", "Owner"),
            Duration::hours(1),
        )
        .await;
        let existing = ctx
            .database
            .create_organization(CreateOrganization {
                additional_fields: Default::default(),
                id: None,
                name: "Existing".to_string().into(),
                slug: "existing".to_string().into(),
                logo: None.into(),
                metadata: None.into(),
            })
            .await
            .expect("organization should be created");
        ctx.database
            .update_session_active_organization(&session.token, Some(&existing.id))
            .await
            .expect("active organization should update");

        let request = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/organization/create",
            Some(&session.token),
            Some(serde_json::json!({
                "name": "Next",
                "slug": "next",
                "keepCurrentActiveOrganization": true
            })),
        );

        handle_create_organization(&request, &ctx, &config)
            .await
            .expect("request should succeed");

        let updated_session = ctx
            .database
            .get_session(&session.token)
            .await
            .expect("session lookup should succeed")
            .expect("session should exist");
        assert_eq!(updated_session.active_organization_id, Some(existing.id));
        assert_eq!(user.id, session.user_id);
    }

    #[tokio::test]
    async fn create_organization_updates_active_organization_by_default() {
        let ctx = create_test_context().await;
        let config = test_config();
        let (_, session) = create_user_and_session(
            &ctx,
            test_user("owner2@example.com", "Owner"),
            Duration::hours(1),
        )
        .await;

        let request = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/organization/create",
            Some(&session.token),
            Some(serde_json::json!({
                "name": "Created",
                "slug": "created"
            })),
        );

        let response = handle_create_organization(&request, &ctx, &config)
            .await
            .expect("request should succeed");
        let body: serde_json::Value =
            serde_json::from_slice(&response.body).expect("response should be JSON");
        let created_id = body["id"]
            .as_str()
            .expect("response should contain organization id");

        let updated_session = ctx
            .database
            .get_session(&session.token)
            .await
            .expect("session lookup should succeed")
            .expect("session should exist");
        assert_eq!(
            updated_session.active_organization_id.as_deref(),
            Some(created_id)
        );
    }

    #[tokio::test]
    async fn get_full_organization_respects_members_limit() {
        let ctx = create_test_context().await;
        let config = test_config();
        let (user, session) = create_user_and_session(
            &ctx,
            test_user("owner3@example.com", "Owner"),
            Duration::hours(1),
        )
        .await;
        let organization = ctx
            .database
            .create_organization(CreateOrganization {
                additional_fields: Default::default(),
                id: None,
                name: "Team".to_string().into(),
                slug: "team".to_string().into(),
                logo: None.into(),
                metadata: None.into(),
            })
            .await
            .expect("organization should be created");
        ctx.database
            .create_member(better_auth_core::types::CreateMember {
                additional_fields: Default::default(),
                organization_id: organization.id.clone(),
                user_id: user.id.clone(),
                role: config.creator_role.clone().into(),
            })
            .await
            .expect("owner member should be created");

        let extra_user = create_user(&ctx, test_user("member@example.com", "Member")).await;
        ctx.database
            .create_member(better_auth_core::types::CreateMember {
                additional_fields: Default::default(),
                organization_id: organization.id.clone(),
                user_id: extra_user.id.clone(),
                role: "member".into(),
            })
            .await
            .expect("extra member should be created");

        let response = get_full_organization_core(
            &GetFullOrganizationQuery {
                organization_id: Some(organization.id.clone()),
                organization_slug: None,
                members_limit: Some(1),
            },
            &user,
            &session,
            &config,
            &ctx,
        )
        .await
        .expect("request should succeed")
        .expect("organization should exist");

        assert_eq!(response.members.len(), 1);
    }
}
