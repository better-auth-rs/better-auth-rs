use super::{
    optional_session, request_only_session, request_present, require_native_session,
    resolve_organization_id,
};
use crate::plugins::organization::rbac::check_permission;
use crate::plugins::organization::types::{
    BasicMemberResponse, CheckSlugRequest, CheckSlugResponse, CreateOrganizationRequest,
    CreateOrganizationResponse, CreatedOrganizationResponse, DeleteOrganizationRequest,
    GetFullOrganizationQuery, LeaveOrganizationRequest, MemberResponse, NullableStringField,
    OrganizationResponse, SetActiveOrganizationRequest, UpdateOrganizationRequest,
};
use crate::plugins::organization::{OrganizationConfig, hooks::*};
use better_auth_core::entity::{AuthMember, AuthOrganization};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::session::NativeSessionData;
use better_auth_core::types::{AuthRequest, AuthResponse, CreateOrganization, UpdateOrganization};
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
    let user = if let Some(user) = session
        .map(NativeSessionData::user_value)
        .transpose()?
        .filter(FieldValue::is_truthy)
    {
        user
    } else {
        let id = body.user_id.as_deref().filter(|id| !id.is_empty());
        let user = match id {
            Some(id) => ctx.database.get_user_by_id(id).await?,
            None => None,
        }
        .ok_or_else(|| {
            AuthError::from_status("UNAUTHORIZED", better_auth_core::FieldValue::Undefined)
        })?;
        FieldValue::from(FieldMap::from(user))
    };
    let user = &user;
    let system_action = session.is_none();
    if !config.may_create(user).await? && !system_action {
        return Err(AuthError::from_code(
            "FORBIDDEN",
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION",
            "You are not allowed to create a new organization",
        ));
    }
    let user_orgs = user_organizations(&user.model_property("id")?, ctx).await?;
    if config
        .organization_limit_reached(user, user_orgs.len())
        .await?
    {
        return Err(AuthError::from_code(
            "FORBIDDEN",
            "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS",
            "You have reached the maximum number of organizations",
        ));
    }

    if ctx
        .database
        .get_organization_by_slug_value(&body.slug.field_value())
        .await?
        .as_ref()
        .map(|organization| super::super::fields::organization(organization, ctx))
        .transpose()?
        .is_some()
    {
        return Err(AuthError::from_code(
            "BAD_REQUEST",
            "ORGANIZATION_ALREADY_EXISTS",
            "Organization already exists",
        ));
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
    let organization = super::super::native_json::metadata(
        ctx.database.create_organization(org_data).await?,
        true,
    )?;
    let organization = crate::plugins::organization::fields::organization(&organization, ctx)?;

    let mut member_data = OrganizationMemberDraft {
        additional_fields: Default::default(),
        team_id: SchemaValue::Undefined,
        created_at: None,
        organization_id: organization.id().into_owned(),
        user_id: SchemaValue::from_field(user.model_property("id")?),
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
                    organization: &organization,
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
        organization: &organization,
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
                .before_create_team(&mut team_data, &organization, Some(user))
                .await?;
        }
        let team = match config
            .custom_default_team(&organization, OrganizationEndpoint::new(ctx, request))
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
            .add_team_member_value(&team.id.field_value(), &user.model_property("id")?, None)
            .await?;
        if let Some(hooks) = &config.hooks {
            hooks
                .after_create_team(OrganizationTeamEvent {
                    team: &team,
                    user: Some(user),
                    organization: &organization,
                })
                .await?;
        }
        default_team_id = team_member.map(|member| member.team_id.field_value());
    }
    if let Some(hooks) = &config.hooks {
        hooks.after_create_organization(event).await?;
    }
    Ok((
        CreateOrganizationResponse {
            organization,
            members: vec![BasicMemberResponse::try_from_member(&member)?],
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
        Err(AuthError::RequestValidation {
            message: format!("[body.data.{name}] {message}"),
        })
    };
    let name = nonempty(&body.data.name, "name")?;
    let slug = nonempty(&body.data.slug, "slug")?;
    let org_id = resolve_organization_id(
        body.organization_id.as_deref(),
        session,
        AuthError::from_code(
            "BAD_REQUEST",
            "ORGANIZATION_NOT_FOUND",
            "Organization not found",
        ),
    )?;

    let member = ctx
        .database
        .get_member_with_user_value(&org_id, &session.user_property("id")?)
        .await?
        .map(|joined| joined.member)
        .ok_or_else(|| {
            AuthError::from_code(
                "BAD_REQUEST",
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
                "User is not a member of the organization",
            )
        })?;

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
        return Err(AuthError::from_code(
            "FORBIDDEN",
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION",
            "You are not allowed to update this organization",
        ));
    }

    if let Some(ref new_slug) = slug
        && let Some(existing) = ctx
            .database
            .get_organization_by_slug(new_slug)
            .await?
            .as_ref()
            .map(|organization| super::super::fields::organization(organization, ctx))
            .transpose()?
        && !existing.id.field_value().strict_equals(&org_id)
    {
        return Err(AuthError::from_code(
            "BAD_REQUEST",
            "ORGANIZATION_SLUG_ALREADY_TAKEN",
            "Organization slug already taken",
        ));
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

    if let Some(hooks) = &config.hooks {
        hooks
            .before_update_organization(
                &mut update_data,
                OrganizationActor {
                    member: &member,
                    user: &session.user_value()?,
                },
            )
            .await?;
    }
    let updated = super::super::native_json::metadata(
        ctx.database
            .update_organization_value(&org_id, update_data)
            .await?,
        false,
    )?;

    let updated = crate::plugins::organization::fields::organization(&updated, ctx)?;
    if let Some(hooks) = &config.hooks {
        hooks
            .after_update_organization(
                &updated,
                OrganizationActor {
                    member: &member,
                    user: &session.user_value()?,
                },
            )
            .await?;
    }
    Ok(updated)
}

pub(crate) async fn delete_organization_core(
    body: &DeleteOrganizationRequest,
    session: &NativeSessionData,
    request: Option<&AuthRequest>,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<OrganizationResponse> {
    if body.organization_id.is_empty() {
        return Err(AuthError::from_code(
            "BAD_REQUEST",
            "ORGANIZATION_NOT_FOUND",
            "Organization not found",
        ));
    }

    let member = ctx
        .database
        .get_member_with_user_value(
            &body.organization_id.as_str().into(),
            &session.user_property("id")?,
        )
        .await?
        .map(|joined| joined.member)
        .ok_or_else(|| {
            AuthError::from_code(
                "BAD_REQUEST",
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
                "User is not a member of the organization",
            )
        })?;

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
        return Err(AuthError::from_code(
            "FORBIDDEN",
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION",
            "You are not allowed to delete this organization",
        ));
    }

    if session
        .session_property("activeOrganizationId")?
        .strict_equals(&body.organization_id.as_str().into())
    {
        let _ = ctx
            .database
            .update_session_active_organization_by_token_value(
                &session.session_property("token")?,
                None,
            )
            .await?;
    }
    let organization = ctx
        .database
        .get_organization_by_id(&body.organization_id)
        .await?
        .ok_or_else(|| {
            AuthError::from_status("BAD_REQUEST", better_auth_core::FieldValue::Undefined)
        })?;
    let organization_view = crate::plugins::organization::fields::organization(&organization, ctx)?;

    if let Some(hooks) = &config.hooks {
        hooks
            .before_delete_organization(
                OrganizationUser {
                    organization: &organization_view,
                    user: &session.user_value()?,
                },
                OrganizationEndpoint::new(ctx, request),
            )
            .await?;
    }
    ctx.database
        .delete_organization(&body.organization_id)
        .await?;

    if let Some(hooks) = &config.hooks {
        hooks
            .after_delete_organization(
                OrganizationUser {
                    organization: &organization_view,
                    user: &session.user_value()?,
                },
                OrganizationEndpoint::new(ctx, request),
            )
            .await?;
    }
    Ok(organization_view)
}

pub(crate) async fn list_organizations_core(
    session: &NativeSessionData,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<FieldValue>> {
    user_organizations(&session.user_property("id")?, ctx).await
}

async fn user_organizations(
    user_id: &FieldValue,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<FieldValue>> {
    let organizations = ctx.database.list_user_organizations_value(user_id).await?;
    organizations
        .into_iter()
        .map(|organization| super::super::fields::organization_value(organization.into(), ctx))
        .collect()
}

pub(crate) async fn get_full_organization_core(
    query: &GetFullOrganizationQuery,
    session: &NativeSessionData,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Option<FieldValue>> {
    use better_auth_core::store::{OrganizationDetailsQuery, OrganizationKey};

    let active_id;
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
        } else {
            active_id = session.session_property("activeOrganizationId")?;
            if !active_id.is_truthy() {
                return Ok(None);
            }
            OrganizationKey::IdValue(&active_id)
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
        .ok_or_else(|| {
            AuthError::from_code(
                "BAD_REQUEST",
                "ORGANIZATION_NOT_FOUND",
                "Organization not found",
            )
        })?;
    let organization = details.into_public_value(&config.schema)?;
    if ctx
        .database
        .get_member_value(
            &organization.model_property("id")?,
            &session.user_property("id")?,
        )
        .await?
        .is_none()
    {
        let _ = ctx
            .database
            .update_session_active_organization_by_token_value(
                &session.session_property("token")?,
                None,
            )
            .await?;
        return Err(AuthError::from_code(
            "FORBIDDEN",
            "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
            "User is not a member of the organization",
        ));
    }
    Ok(Some(organization))
}

pub(crate) async fn check_slug_core(
    body: &CheckSlugRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<CheckSlugResponse> {
    if ctx
        .database
        .get_organization_by_slug(&body.slug)
        .await?
        .as_ref()
        .map(|organization| super::super::fields::organization(organization, ctx))
        .transpose()?
        .is_some()
    {
        return Err(AuthError::from_code(
            "BAD_REQUEST",
            "ORGANIZATION_SLUG_ALREADY_TAKEN",
            "Organization slug already taken",
        ));
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
            .session_property("activeOrganizationId")?
            .is_truthy()
        {
            return Ok(None);
        }

        let updated = ctx
            .database
            .update_session_active_organization_by_token_value(
                &session.session_property("token")?,
                None,
            )
            .await?;
        let manager = ctx.session_manager();
        manager
            .set_native_session_cookie(req, session.with_session(updated)?, None)
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
            .ok_or_else(|| {
                AuthError::from_code(
                    "BAD_REQUEST",
                    "ORGANIZATION_NOT_FOUND",
                    "Organization not found",
                )
            })?;
        let organization = super::super::fields::organization(&organization, ctx)?;
        organization.id().field_value()
    } else {
        let active_id = session.session_property("activeOrganizationId")?;
        if !active_id.is_truthy() {
            return Ok(None);
        }
        active_id
    };
    if !org_id.is_truthy() {
        return Err(AuthError::from_code(
            "BAD_REQUEST",
            "ORGANIZATION_NOT_FOUND",
            "Organization not found",
        ));
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
                &session.session_property("token")?,
                None,
            )
            .await?;
        return Err(AuthError::from_code(
            "FORBIDDEN",
            "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
            "User is not a member of the organization",
        ));
    }

    let organization = ctx
        .database
        .get_organization_by_id_value(&org_id)
        .await?
        .ok_or_else(|| {
            AuthError::from_code(
                "BAD_REQUEST",
                "ORGANIZATION_NOT_FOUND",
                "Organization not found",
            )
        })?;
    let organization = super::super::fields::organization(&organization, ctx)?;

    let updated = ctx
        .database
        .update_session_active_organization_by_token_value(
            &session.session_property("token")?,
            Some(&organization.id.field_value()),
        )
        .await?;
    let manager = ctx.session_manager();
    manager
        .set_native_session_cookie(req, session.with_session(updated)?, None)
        .await?;

    Ok(Some(organization))
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
        .ok_or_else(|| {
            AuthError::from_code("BAD_REQUEST", "MEMBER_NOT_FOUND", "Member not found")
        })?;

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
            return Err(AuthError::from_code(
                "BAD_REQUEST",
                "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
                "You cannot leave the organization as the only owner",
            ));
        }
    }

    ctx.database
        .delete_member_for_user_value(
            &member.id().field_value(),
            &body.organization_id.as_str().into(),
            &session.user_property("id")?,
        )
        .await?;

    if session
        .session_property("activeOrganizationId")?
        .strict_equals(&body.organization_id.as_str().into())
    {
        let _ = ctx
            .database
            .update_session_active_organization_by_token_value(
                &session.session_property("token")?,
                None,
            )
            .await?;
    }

    Ok(MemberResponse::from(joined))
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
        return Err(AuthError::from_status(
            "UNAUTHORIZED",
            better_auth_core::FieldValue::Undefined,
        ));
    }
    let body: CreateOrganizationRequest = super::super::request::read(req, &config.schema)?;
    let (mut response, default_team_id) =
        create_organization_core(&body, session.as_ref(), config, ctx, Some(req)).await?;
    if !body.keep_current_active_organization.unwrap_or(false)
        && let Some(session) = session
    {
        let _ = ctx
            .database
            .update_session_active_organization_by_token_value(
                &session.session_property("token")?,
                Some(&response.organization.id.field_value()),
            )
            .await?;
        if let Some(team_id) = default_team_id {
            let _ = ctx
                .database
                .update_session_active_team_by_token_value(
                    &session.session_property("token")?,
                    Some(&team_id),
                )
                .await?;
        }
    }
    let metadata = response.organization.metadata.field_value();
    if metadata.is_truthy() && metadata.is_string() {
        response.organization.metadata =
            SchemaValue::from_field(super::super::native_json::parse_json(&metadata)?);
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
        Err(error) if matches!(error.original(), AuthError::Unauthenticated) => {
            return Err(AuthError::from_status(
                "UNAUTHORIZED",
                better_auth_core::FieldMap::from([("message".into(), "User not found".into())])
                    .into(),
            ));
        }
        Err(error) => return Err(error),
    };
    let body: UpdateOrganizationRequest = super::super::request::read(req, &config.schema)?;
    let updated = update_organization_core(&body, &session, config, ctx).await?;
    Ok(AuthResponse::native(None, updated.field_values()?.into()))
}

/// Handle delete organization request
pub async fn handle_delete_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    if config.disable_organization_deletion {
        return Err(AuthError::from_code(
            "NOT_FOUND",
            "ORGANIZATION_DELETION_DISABLED",
            "Organization deletion is disabled",
        ));
    }
    let session =
        ctx.require_native_session(req)
            .await
            .map_err(|error| match error.original() {
                AuthError::Unauthenticated => {
                    AuthError::from_status("UNAUTHORIZED", better_auth_core::FieldValue::Undefined)
                }
                _ => error,
            })?;
    let body: DeleteOrganizationRequest = super::super::request::read(req, &config.schema)?;
    let response = delete_organization_core(&body, &session, Some(req), config, ctx).await?;
    Ok(AuthResponse::native(None, response.field_values()?.into()))
}

/// Handle list organizations request
pub async fn handle_list_organizations(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let organizations = list_organizations_core(&session, ctx).await?;
    Ok(AuthResponse::native(None, organizations.into()))
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
        ctx.database.get_organization_by_slug(&slug).await?
    } else {
        let id = nonempty("organizationId")?
            .map(better_auth_core::FieldValue::from)
            .map(Ok)
            .unwrap_or_else(|| session.session_property("activeOrganizationId"))?;
        if !id.is_truthy() {
            return AuthResponse::json(None, &serde_json::Value::Null);
        }
        ctx.database.get_organization_by_id_value(&id).await?
    }
    .ok_or_else(|| {
        AuthError::from_code(
            "BAD_REQUEST",
            "ORGANIZATION_NOT_FOUND",
            "Organization not found",
        )
    })?;
    let organization = super::super::fields::organization(&organization, ctx)?;

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
                &session.session_property("token")?,
                None,
            )
            .await?;
        return Err(AuthError::from_code(
            "FORBIDDEN",
            "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
            "User is not a member of the organization",
        ));
    }
    Ok(AuthResponse::native(
        None,
        organization.field_values()?.into(),
    ))
}

/// Handle get full organization request
pub async fn handle_get_full_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let query = crate::plugins::query_input::parse::<GetFullOrganizationQuery>(req)?;
    let response = get_full_organization_core(&query, &session, config, ctx).await?;
    Ok(AuthResponse::native(
        None,
        response.unwrap_or(FieldValue::Null),
    ))
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
    Ok(AuthResponse::native(
        None,
        organization
            .map(|value| value.field_values().map(FieldValue::from))
            .transpose()?
            .unwrap_or(FieldValue::Null),
    ))
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
    Ok(AuthResponse::native(None, response.field_values()?.into()))
}

#[cfg(test)]
mod tests;
