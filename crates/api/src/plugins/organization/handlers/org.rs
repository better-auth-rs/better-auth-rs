use super::{
    optional_session, request_only_session, request_present, require_native_session,
    resolve_organization_id,
};
use crate::plugins::organization::rbac::check_permission;
use crate::plugins::organization::types::{
    BasicMemberResponse, CheckSlugRequest, CheckSlugResponse, CreateOrganizationRequest,
    CreateOrganizationResponse, CreatedOrganizationResponse, DeleteOrganizationRequest,
    FullOrganizationResponse, GetFullOrganizationQuery, LeaveOrganizationRequest, MemberResponse,
    NullableStringField, OrganizationResponse, SetActiveOrganizationRequest,
    UpdateOrganizationRequest,
};
use crate::plugins::organization::{OrganizationConfig, hooks::*};
use better_auth_core::entity::{AuthMember, AuthOrganization, AuthSession};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::session::NativeSessionData;
use better_auth_core::types::{AuthRequest, AuthResponse, CreateOrganization, UpdateOrganization};
use better_auth_core::wire::InvitationView;
use better_auth_core::{AuthRecordFields, FieldMap, FieldValue, SchemaValue};

fn has_role(member: &impl AuthMember, role: &str) -> AuthResult<bool> {
    Ok(member
        .role()
        .typed()?
        .split(',')
        .any(|candidate| candidate == role))
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

pub(crate) async fn create_organization_core(
    body: &CreateOrganizationRequest,
    session: Option<&NativeSessionData>,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: Option<&AuthRequest>,
) -> AuthResult<(
    CreateOrganizationResponse<CreatedOrganizationResponse, BasicMemberResponse>,
    Option<better_auth_core::FieldValue>,
)> {
    let user = if let Some(session) = session.filter(|session| session.user.is_truthy()) {
        session.user.clone()
    } else {
        let id = body.user_id.as_deref().filter(|id| !id.is_empty());
        let user = match id {
            Some(id) => ctx.database.get_user_by_id(id).await?,
            None => None,
        }
        .ok_or(AuthError::from(AuthResponse::json(
            401,
            &serde_json::Value::Null,
        )?))?;
        FieldValue::from(FieldMap::from(user))
    };
    let user = &user;
    let system_action = session.is_none();
    if !config.may_create(user).await? && !system_action {
        return Err(AuthError::Upstream {
            status: 403,
            code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION",
            message: "You are not allowed to create a new organization",
        });
    }
    let user_orgs = ctx
        .database
        .list_user_organizations_value(user.model_property("id")?)
        .await?;
    if config
        .organization_limit_reached(user, user_orgs.len())
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
        .get_organization_by_slug_value(&body.slug.field_value())
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
            .and_then(better_auth_core::FieldValue::as_str)
            .map(str::to_owned),
        name: body.name.clone(),
        slug: body.slug.clone(),
        logo: body.logo.clone(),
        metadata: body.metadata.clone(),
    };

    if let Some(hooks) = &config.hooks {
        hooks
            .before_create_organization(&mut org_data, user)
            .await?;
    }
    if !org_data.metadata.is_truthy()? {
        org_data.metadata = better_auth_core::SchemaValue::Undefined;
    }
    let mut organization = ctx.database.create_organization(org_data).await?;
    organization.metadata = super::super::native_json::metadata(organization.metadata, true)?;
    let organization_view =
        crate::plugins::organization::fields::created_organization(&organization, ctx);

    let mut member_data = OrganizationMemberDraft {
        additional_fields: Default::default(),
        team_id: SchemaValue::Undefined,
        created_at: None,
        organization_id: organization.id().into_owned(),
        user_id: SchemaValue::from_field(user.model_property("id")?.clone()),
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
                    user,
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
        user,
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
                .before_create_team(&mut team_data, &organization_view, Some(user))
                .await?;
        }
        let team = match config
            .custom_default_team(&organization_view, OrganizationEndpoint::new(ctx, request))
            .await?
        {
            Some(team) => team,
            None => {
                let team = ctx
                    .database
                    .create_team(team_data.into_create(created_at, None))
                    .await?;
                crate::plugins::organization::fields::team(team, config)?
            }
        };
        let team_member = ctx
            .database
            .add_team_member_value(&team.id.field_value(), user.model_property("id")?, None)
            .await?;
        if let Some(hooks) = &config.hooks {
            hooks
                .after_create_team(OrganizationTeamEvent {
                    team: &team,
                    user: Some(user),
                    organization: &organization_view,
                })
                .await?;
        }
        default_team_id = team_member.map(|member| member.team_id.field_value());
    }
    if let Some(hooks) = &config.hooks {
        hooks.after_create_organization(event).await?;
    }
    let mut response = CreatedOrganizationResponse::from_organization(&organization);
    if let better_auth_core::FieldValue::String(value) = response.metadata.field_value()
        && !value.is_empty()
    {
        response.metadata = better_auth_core::SchemaValue::from_json(Some(
            super::super::native_json::parse_json(&value)?,
        ))?;
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
    session: &NativeSessionData,
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
        resolve_organization_id(body.organization_id.as_deref(), None, &session.session, ctx)
            .await?;

    let member = ctx
        .database
        .get_member_with_user_value(&org_id, &session.user_property("id")?)
        .await?
        .map(|joined| joined.member)
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
        && !existing.id.field_value().strict_equals(&org_id)
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

    let actor = OrganizationActor {
        member: &member,
        user: &session.user,
    };
    if let Some(hooks) = &config.hooks {
        hooks
            .before_update_organization(&mut update_data, actor)
            .await?;
    }
    let mut updated = ctx
        .database
        .update_organization_value(&org_id, update_data)
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
    session: &NativeSessionData,
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
        .get_member_with_user_value(
            &body.organization_id.as_str().into(),
            &session.user_property("id")?,
        )
        .await?
        .map(|joined| joined.member)
        .ok_or_else(|| AuthError::bad_request("User is not a member of the organization"))?;

    if !check_permission(
        member.role().typed()?,
        &body.organization_id.as_str().into(),
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

    if session
        .session
        .active_organization_id()
        .field_value()
        .strict_equals(&body.organization_id.as_str().into())
    {
        let _ = ctx
            .database
            .update_session_active_organization_by_token_value(
                &session.session.token.field_value(),
                None,
            )
            .await?;
    }
    let organization = ctx
        .database
        .get_organization_by_id(&body.organization_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = crate::plugins::organization::fields::organization(&organization, ctx);

    let event = OrganizationUser {
        organization: &organization_view,
        user: &session.user,
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
    session: &NativeSessionData,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<OrganizationResponse>> {
    let organizations = ctx
        .database
        .list_user_organizations_value(&session.user_property("id")?)
        .await?;
    Ok(organizations
        .iter()
        .map(OrganizationResponse::from_organization)
        .collect())
}

pub(crate) async fn get_full_organization_core(
    query: &GetFullOrganizationQuery,
    session: &NativeSessionData,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Option<FullOrganizationResponse<OrganizationResponse, InvitationView>>> {
    use better_auth_core::store::{OrganizationDetailsQuery, OrganizationKey};

    let active_id = session.session.active_organization_id.field_value();
    let selector = if let Some(slug) = query
        .organization_slug
        .as_deref()
        .filter(|slug| !slug.is_empty())
    {
        OrganizationKey::Slug(slug)
    } else {
        let id = query.organization_id.as_deref().filter(|id| !id.is_empty());
        if let Some(id) = id {
            OrganizationKey::Id(id)
        } else if active_id.is_truthy() {
            OrganizationKey::IdValue(&active_id)
        } else {
            return Ok(None);
        }
    };
    let details = ctx
        .database
        .get_organization_details(OrganizationDetailsQuery {
            organization: selector,
            members_limit: query
                .members_limit
                .filter(|limit| *limit != 0.0 && !limit.is_nan()),
            users_limit: config.member_list_limit() as f64,
            include_teams: config.teams.enabled,
        })
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization = details.organization;
    if ctx
        .database
        .get_member_value(
            &organization.id.field_value(),
            &session.user_property("id")?,
        )
        .await?
        .is_none()
    {
        let _ = ctx
            .database
            .update_session_active_organization_by_token_value(
                &session.session.token.field_value(),
                None,
            )
            .await?;
        return Err(AuthError::forbidden(
            "User is not a member of the organization",
        ));
    }
    Ok(Some(FullOrganizationResponse {
        organization: crate::plugins::organization::fields::organization(&organization, ctx),
        members: details
            .members
            .iter()
            .map(|joined| MemberResponse::from_member_and_user(&joined.member, &joined.user))
            .collect(),
        invitations: details
            .invitations
            .iter()
            .map(InvitationView::from)
            .collect(),
        teams: details.teams.map(|teams| {
            teams
                .into_iter()
                .map(|team| crate::plugins::organization::types::FullOrganizationTeam { team })
                .collect()
        }),
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
    session: &NativeSessionData,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Option<OrganizationResponse>> {
    if matches!(body.organization_id, NullableStringField::Null) {
        if !session
            .session
            .active_organization_id
            .field_value()
            .is_truthy()
        {
            return Ok(None);
        }

        let updated = ctx
            .database
            .update_session_active_organization_by_token_value(
                &session.session.token.field_value(),
                None,
            )
            .await?;
        let manager = ctx.session_manager();
        manager
            .set_native_session_cookie(
                req,
                NativeSessionData {
                    session: updated,
                    user: session.user.clone(),
                },
                None,
            )
            .await?;
        return Ok(None);
    }

    let org_id = if let NullableStringField::Value(id) = &body.organization_id
        && !id.is_empty()
    {
        id.as_str().into()
    } else if let Some(slug) = body
        .organization_slug
        .as_deref()
        .filter(|slug| !slug.is_empty())
    {
        let organization = ctx
            .database
            .get_organization_by_slug(slug)
            .await?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        organization.id().field_value()
    } else {
        let active_id = session.session.active_organization_id.field_value();
        if !active_id.is_truthy() {
            return Ok(None);
        }
        active_id
    };
    if !org_id.is_truthy() {
        return Err(AuthError::bad_request("Organization not found"));
    }
    if ctx
        .database
        .get_member_value(&org_id, &session.user_property("id")?)
        .await?
        .is_none()
    {
        let _ = ctx
            .database
            .update_session_active_organization_by_token_value(
                &session.session.token.field_value(),
                None,
            )
            .await?;
        return Err(AuthError::forbidden(
            "User is not a member of the organization",
        ));
    }

    let organization = ctx
        .database
        .get_organization_by_id_value(&org_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;

    let updated = ctx
        .database
        .update_session_active_organization_by_token_value(
            &session.session.token.field_value(),
            Some(&organization.id.field_value()),
        )
        .await?;
    let manager = ctx.session_manager();
    manager
        .set_native_session_cookie(
            req,
            NativeSessionData {
                session: updated,
                user: session.user.clone(),
            },
            None,
        )
        .await?;

    Ok(Some(crate::plugins::organization::fields::organization(
        &organization,
        ctx,
    )))
}

pub(crate) async fn leave_organization_core(
    body: &LeaveOrganizationRequest,
    session: &NativeSessionData,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<MemberResponse> {
    let joined = ctx
        .database
        .get_member_with_user_value(
            &body.organization_id.as_str().into(),
            &session.user_property("id")?,
        )
        .await?
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    let member = &joined.member;
    if has_role(member, config.creator_role())? {
        let all_members = ctx
            .database
            .list_organization_members(&body.organization_id)
            .await?;
        let owner_count =
            all_members
                .iter()
                .try_fold(0, |count, candidate| -> AuthResult<usize> {
                    Ok(count + usize::from(has_role(candidate, config.creator_role())?))
                })?;

        if owner_count <= 1 {
            return Err(AuthError::bad_request(
                "You cannot leave the organization as the only owner",
            ));
        }
    }

    let response = MemberResponse::from_member_and_user(member, &joined.user);
    ctx.database
        .delete_member_for_user_value(
            &member.id().field_value(),
            &body.organization_id.as_str().into(),
            &session.user_property("id")?,
        )
        .await?;

    if session
        .session
        .active_organization_id()
        .field_value()
        .strict_equals(&body.organization_id.as_str().into())
    {
        let _ = ctx
            .database
            .update_session_active_organization_by_token_value(
                &session.session.token.field_value(),
                None,
            )
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
    let session = optional_session(req, ctx).await?;
    if session.is_none() && request_present(req, ctx) {
        return Err(AuthError::from(AuthResponse::json(
            401,
            &serde_json::Value::Null,
        )?));
    }
    let body: CreateOrganizationRequest = super::super::request::read(req, &config.schema)?;
    let (response, default_team_id) =
        create_organization_core(&body, session.as_ref(), config, ctx, Some(req)).await?;
    if !body.keep_current_active_organization.unwrap_or(false)
        && let Some(session) = session
    {
        let _ = ctx
            .database
            .update_session_active_organization_by_token_value(
                &session.session.token.field_value(),
                Some(&response.organization.id.field_value()),
            )
            .await?;
        if let Some(team_id) = default_team_id {
            let _ = ctx
                .database
                .update_session_active_team_by_token_value(
                    &session.session.token.field_value(),
                    Some(&team_id),
                )
                .await?;
        }
    }
    Ok(AuthResponse::native(None, response.field_values()?.into()))
}

/// Handle update organization request
pub async fn handle_update_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = match ctx.require_native_session(req).await {
        Ok(session) => session,
        Err(AuthError::Unauthenticated) => {
            return Err(
                AuthResponse::json(401, &serde_json::json!({"message":"User not found"}))?.into(),
            );
        }
        Err(error) => return Err(error),
    };
    let body: UpdateOrganizationRequest = super::super::request::read(req, &config.schema)?;
    let updated = update_organization_core(&body, &session, config, ctx).await?;
    AuthResponse::json(None, &updated)
}

/// Handle delete organization request
pub async fn handle_delete_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = ctx
        .require_native_session(req)
        .await
        .map_err(|error| match error {
            AuthError::Unauthenticated => AuthResponse::new(401).into(),
            error => error,
        })?;
    let body: DeleteOrganizationRequest = super::super::request::read(req, &config.schema)?;
    let response = delete_organization_core(&body, &session, Some(req), config, ctx).await?;
    AuthResponse::json(None, &response)
}

/// Handle list organizations request
pub async fn handle_list_organizations(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let organizations = list_organizations_core(&session, ctx).await?;
    AuthResponse::json(None, &organizations)
}

/// Get organization metadata for a member, without expanding members or invitations.
pub async fn handle_get_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let nonempty = |key: &str| {
        req.query_string(key)
            .map(|value| value.filter(|value| !value.is_empty()))
    };
    let organization = if let Some(slug) = nonempty("organizationSlug")? {
        ctx.database.get_organization_by_slug(slug).await?
    } else {
        let id = nonempty("organizationId")?
            .map(better_auth_core::FieldValue::from)
            .unwrap_or_else(|| session.session.active_organization_id.field_value());
        if !id.is_truthy() {
            return AuthResponse::json(None, &serde_json::Value::Null);
        }
        ctx.database.get_organization_by_id_value(&id).await?
    }
    .ok_or_else(|| AuthError::bad_request("Organization not found"))?;

    if ctx
        .database
        .get_member_value(
            &organization.id().field_value(),
            &session.user_property("id")?,
        )
        .await?
        .is_none()
    {
        _ = ctx
            .database
            .update_session_active_organization_by_token_value(
                &session.session.token.field_value(),
                None,
            )
            .await?;
        return Err(AuthError::forbidden(
            "User is not a member of the organization",
        ));
    }
    AuthResponse::json(
        None,
        &crate::plugins::organization::fields::organization(&organization, ctx),
    )
}

/// Handle get full organization request
pub async fn handle_get_full_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let query = crate::plugins::query_input::parse::<GetFullOrganizationQuery>(&req.query)?;
    let response = get_full_organization_core(&query, &session, config, ctx).await?;
    AuthResponse::json(None, &response)
}

/// Handle check slug request
pub async fn handle_check_slug(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let _ = request_only_session(req, ctx).await?;
    let body: CheckSlugRequest = super::super::request::read(req, &Default::default())?;
    let response = check_slug_core(&body, ctx).await?;
    AuthResponse::json(None, &response)
}

/// Handle set active organization request
pub async fn handle_set_active_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let body: SetActiveOrganizationRequest = super::super::request::read(req, &Default::default())?;
    let organization = set_active_organization_core(req, &body, &session, ctx).await?;
    AuthResponse::json(None, &organization)
}

/// Handle leave organization request
pub async fn handle_leave_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let body: LeaveOrganizationRequest = super::super::request::read(req, &config.schema)?;
    let response = leave_organization_core(&body, &session, config, ctx).await?;
    AuthResponse::json(None, &response)
}

#[cfg(test)]
mod tests {

    use better_auth_core::types::{CreateOrganization, CreateUser, HttpMethod};
    use chrono::Duration;

    use crate::plugins::organization::{OrganizationConfig, OrganizationPlugin};
    use crate::plugins::test_helpers::{
        create_auth_json_request_no_query, create_test_config, create_test_context_with_plugins,
        create_user, create_user_and_session,
    };

    use super::{get_full_organization_core, handle_create_organization};
    use crate::plugins::organization::types::GetFullOrganizationQuery;

    fn test_config() -> OrganizationConfig {
        OrganizationConfig {
            allow_user_to_create_organization: true,
            organization_limit: None,
            membership_limit: Some(100),
            creator_role: "owner".to_string(),
            invitation_expires_in: 172800.0,
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
            name: Some(name.to_string()).into(),
            ..CreateUser::default()
        }
    }

    #[tokio::test]
    async fn create_organization_keeps_current_active_organization_when_requested() {
        let config = test_config();
        let ctx = create_test_context_with_plugins(
            create_test_config(),
            &[&OrganizationPlugin::with_config(config.clone())],
        )
        .await;
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
            .update_session_active_organization(
                session.token.typed().unwrap(),
                Some(existing.id.typed().unwrap()),
            )
            .await
            .expect("active organization should update");

        let request = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/organization/create",
            Some(session.token.typed().unwrap()),
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
            .get_session(session.token.typed().unwrap())
            .await
            .expect("session lookup should succeed")
            .expect("session should exist");
        assert_eq!(
            updated_session
                .active_organization_id
                .typed()
                .unwrap()
                .as_ref(),
            Some(existing.id.typed().unwrap())
        );
        assert_eq!(user.id, session.user_id);
    }

    #[tokio::test]
    async fn create_organization_updates_active_organization_by_default() {
        let config = test_config();
        let ctx = create_test_context_with_plugins(
            create_test_config(),
            &[&OrganizationPlugin::with_config(config.clone())],
        )
        .await;
        let (_, session) = create_user_and_session(
            &ctx,
            test_user("owner2@example.com", "Owner"),
            Duration::hours(1),
        )
        .await;

        let request = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/organization/create",
            Some(session.token.typed().unwrap()),
            Some(serde_json::json!({
                "name": "Created",
                "slug": "created"
            })),
        );

        let response = handle_create_organization(&request, &ctx, &config)
            .await
            .expect("request should succeed");
        let body: serde_json::Value = serde_json::from_slice(&response.body.bytes().unwrap())
            .expect("response should be JSON");
        let created_id = body["id"]
            .as_str()
            .expect("response should contain organization id");

        let updated_session = ctx
            .database
            .get_session(session.token.typed().unwrap())
            .await
            .expect("session lookup should succeed")
            .expect("session should exist");
        assert_eq!(
            updated_session
                .active_organization_id
                .typed()
                .unwrap()
                .as_deref(),
            Some(created_id)
        );
    }

    #[tokio::test]
    async fn get_full_organization_respects_members_limit() {
        let config = test_config();
        let ctx = create_test_context_with_plugins(
            create_test_config(),
            &[&OrganizationPlugin::with_config(config.clone())],
        )
        .await;
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
                organization_id: Some(organization.id.typed().unwrap().clone()),
                organization_slug: None,
                members_limit: Some(1.0),
            },
            &(user, session).into(),
            &config,
            &ctx,
        )
        .await
        .expect("request should succeed")
        .expect("organization should exist");

        assert_eq!(response.members.len(), 1);
    }
}
