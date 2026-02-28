use super::{require_session, resolve_organization_id};
use crate::plugins::organization::config::OrganizationConfig;
use crate::plugins::organization::rbac::{Action, Resource, has_permission_any};
use crate::plugins::organization::types::{
    CheckSlugRequest, CheckSlugResponse, CreateOrganizationRequest, CreateOrganizationResponse,
    DeleteOrganizationRequest, FullOrganizationResponse, GetFullOrganizationQuery,
    LeaveOrganizationRequest, MemberResponse, SetActiveOrganizationRequest, SuccessResponse,
    UpdateOrganizationRequest,
};
use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthMember, AuthOrganization, AuthSession, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::types::{
    AuthRequest, AuthResponse, CreateMember, CreateOrganization, UpdateOrganization,
};

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

pub(crate) async fn create_organization_core<DB: DatabaseAdapter>(
    body: &CreateOrganizationRequest,
    user: &DB::User,
    config: &OrganizationConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<CreateOrganizationResponse<DB::Organization, MemberResponse>> {
    if !config.allow_user_to_create_organization {
        return Err(AuthError::forbidden("Organization creation is not allowed"));
    }

    if let Some(limit) = config.organization_limit {
        let user_orgs = ctx.database.list_user_organizations(user.id()).await?;
        if user_orgs.len() >= limit {
            return Err(AuthError::bad_request(format!(
                "Organization limit of {} reached",
                limit
            )));
        }
    }

    if ctx
        .database
        .get_organization_by_slug(&body.slug)
        .await?
        .is_some()
    {
        return Err(AuthError::bad_request("Slug is already taken"));
    }

    let org_data = CreateOrganization {
        id: None,
        name: body.name.clone(),
        slug: body.slug.clone(),
        logo: body.logo.clone(),
        metadata: body.metadata.clone(),
    };

    let organization = ctx.database.create_organization(org_data).await?;

    let member_data = CreateMember {
        organization_id: organization.id().to_string(),
        user_id: user.id().to_string(),
        role: config.creator_role.clone(),
    };

    let member = ctx.database.create_member(member_data).await?;
    let member_response = MemberResponse::from_member_and_user(&member, user);

    Ok(CreateOrganizationResponse {
        organization,
        members: vec![member_response],
    })
}

pub(crate) async fn update_organization_core<DB: DatabaseAdapter>(
    body: &UpdateOrganizationRequest,
    user: &DB::User,
    session: &DB::Session,
    config: &OrganizationConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<DB::Organization> {
    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, session, ctx).await?;

    let member = ctx
        .database
        .get_member(&org_id, user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    if !has_permission_any(
        member.role(),
        &Resource::Organization,
        &Action::Update,
        &config.roles,
    ) {
        return Err(AuthError::forbidden(
            "You don't have permission to update this organization",
        ));
    }

    if let Some(ref new_slug) = body.slug
        && let Some(existing) = ctx.database.get_organization_by_slug(new_slug).await?
        && existing.id() != org_id
    {
        return Err(AuthError::bad_request("Slug is already taken"));
    }

    let update_data = UpdateOrganization {
        name: body.name.clone(),
        slug: body.slug.clone(),
        logo: body.logo.clone(),
        metadata: body.metadata.clone(),
    };

    let updated = ctx
        .database
        .update_organization(&org_id, update_data)
        .await?;

    Ok(updated)
}

pub(crate) async fn delete_organization_core<DB: DatabaseAdapter>(
    body: &DeleteOrganizationRequest,
    user: &DB::User,
    config: &OrganizationConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<SuccessResponse> {
    if config.disable_organization_deletion {
        return Err(AuthError::forbidden("Organization deletion is disabled"));
    }

    let member = ctx
        .database
        .get_member(&body.organization_id, user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    if !has_permission_any(
        member.role(),
        &Resource::Organization,
        &Action::Delete,
        &config.roles,
    ) {
        return Err(AuthError::forbidden(
            "You don't have permission to delete this organization",
        ));
    }

    ctx.database
        .delete_organization(&body.organization_id)
        .await?;

    Ok(SuccessResponse { success: true })
}

pub(crate) async fn list_organizations_core<DB: DatabaseAdapter>(
    user: &DB::User,
    ctx: &AuthContext<DB>,
) -> AuthResult<Vec<DB::Organization>> {
    let organizations = ctx.database.list_user_organizations(user.id()).await?;
    Ok(organizations)
}

pub(crate) async fn get_full_organization_core<DB: DatabaseAdapter>(
    query: &GetFullOrganizationQuery,
    user: &DB::User,
    session: &DB::Session,
    ctx: &AuthContext<DB>,
) -> AuthResult<FullOrganizationResponse<DB::Organization, DB::Invitation>> {
    let org_id = resolve_organization_id(
        query.organization_id.as_deref(),
        query.organization_slug.as_deref(),
        session,
        ctx,
    )
    .await?;

    ctx.database
        .get_member(&org_id, user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    let organization = ctx
        .database
        .get_organization_by_id(&org_id)
        .await?
        .ok_or_else(|| AuthError::not_found("Organization not found"))?;

    let members_raw = ctx.database.list_organization_members(&org_id).await?;
    let mut members = Vec::with_capacity(members_raw.len());

    for member in &members_raw {
        if let Some(user_info) = ctx.database.get_user_by_id(member.user_id()).await? {
            members.push(MemberResponse::from_member_and_user(member, &user_info));
        }
    }

    let invitations = ctx.database.list_organization_invitations(&org_id).await?;

    Ok(FullOrganizationResponse {
        organization,
        members,
        invitations,
    })
}

pub(crate) async fn check_slug_core<DB: DatabaseAdapter>(
    body: &CheckSlugRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<CheckSlugResponse> {
    let exists = ctx
        .database
        .get_organization_by_slug(&body.slug)
        .await?
        .is_some();

    Ok(CheckSlugResponse { status: !exists })
}

pub(crate) async fn set_active_organization_core<DB: DatabaseAdapter>(
    body: &SetActiveOrganizationRequest,
    user: &DB::User,
    session: &DB::Session,
    ctx: &AuthContext<DB>,
) -> AuthResult<DB::Session> {
    let org_id = if body.organization_id.is_some() || body.organization_slug.is_some() {
        Some(
            resolve_organization_id(
                body.organization_id.as_deref(),
                body.organization_slug.as_deref(),
                session,
                ctx,
            )
            .await?,
        )
    } else {
        None
    };

    if let Some(ref oid) = org_id {
        ctx.database
            .get_member(oid, user.id())
            .await?
            .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;
    }

    let updated_session = ctx
        .database
        .update_session_active_organization(session.token(), org_id.as_deref())
        .await?;

    Ok(updated_session)
}

pub(crate) async fn leave_organization_core<DB: DatabaseAdapter>(
    body: &LeaveOrganizationRequest,
    user: &DB::User,
    session: &DB::Session,
    ctx: &AuthContext<DB>,
) -> AuthResult<SuccessResponse> {
    let member = ctx
        .database
        .get_member(&body.organization_id, user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    if member.role().contains("owner") {
        let all_members = ctx
            .database
            .list_organization_members(&body.organization_id)
            .await?;
        let owner_count = all_members
            .iter()
            .filter(|m| m.role().contains("owner"))
            .count();

        if owner_count <= 1 {
            return Err(AuthError::bad_request(
                "Cannot leave organization as the last owner. Delete the organization or transfer ownership first.",
            ));
        }
    }

    ctx.database.delete_member(member.id()).await?;

    if session.active_organization_id() == Some(&body.organization_id) {
        ctx.database
            .update_session_active_organization(session.token(), None)
            .await?;
    }

    Ok(SuccessResponse { success: true })
}

// ---------------------------------------------------------------------------
// Old handlers (rewritten to call core)
// ---------------------------------------------------------------------------

/// Handle create organization request
pub async fn handle_create_organization<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: CreateOrganizationRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let response = create_organization_core(&body, &user, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle update organization request
pub async fn handle_update_organization<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: UpdateOrganizationRequest = req
        .body_as_json()
        .map_err(|e| AuthError::bad_request(format!("Invalid request body: {}", e)))?;
    let updated = update_organization_core(&body, &user, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &updated)?)
}

/// Handle delete organization request
pub async fn handle_delete_organization<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: DeleteOrganizationRequest = req
        .body_as_json()
        .map_err(|e| AuthError::bad_request(format!("Invalid request body: {}", e)))?;
    let response = delete_organization_core(&body, &user, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle list organizations request
pub async fn handle_list_organizations<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let organizations = list_organizations_core(&user, ctx).await?;
    Ok(AuthResponse::json(200, &organizations)?)
}

/// Handle get full organization request
pub async fn handle_get_full_organization<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let query = parse_query::<GetFullOrganizationQuery>(&req.query);
    let response = get_full_organization_core(&query, &user, &session, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle check slug request
pub async fn handle_check_slug<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let _session = require_session(req, ctx).await?;
    let body: CheckSlugRequest = req
        .body_as_json()
        .map_err(|e| AuthError::bad_request(format!("Invalid request body: {}", e)))?;
    let response = check_slug_core(&body, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle set active organization request
pub async fn handle_set_active_organization<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: SetActiveOrganizationRequest = req
        .body_as_json()
        .map_err(|e| AuthError::bad_request(format!("Invalid request body: {}", e)))?;
    let updated_session = set_active_organization_core(&body, &user, &session, ctx).await?;
    Ok(AuthResponse::json(200, &updated_session)?)
}

/// Handle leave organization request
pub async fn handle_leave_organization<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: LeaveOrganizationRequest = req
        .body_as_json()
        .map_err(|e| AuthError::bad_request(format!("Invalid request body: {}", e)))?;
    let response = leave_organization_core(&body, &user, &session, ctx).await?;
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
