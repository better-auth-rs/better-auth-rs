use super::{require_session, resolve_organization_id};
use crate::plugins::organization::OrganizationConfig;
use crate::plugins::organization::rbac::{Action, Resource, has_permission_any};
use crate::plugins::organization::types::{
    BasicMemberResponse, CheckSlugRequest, CheckSlugResponse, CreateOrganizationRequest,
    CreateOrganizationResponse, CreatedOrganizationResponse, DeleteOrganizationRequest,
    FullOrganizationResponse, GetFullOrganizationQuery, LeaveOrganizationRequest, MemberResponse,
    NullableStringField, OrganizationResponse, SetActiveOrganizationRequest,
    UpdateOrganizationRequest,
};
use better_auth_core::entity::{AuthMember, AuthOrganization, AuthSession, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::store::ListOrganizationMembersParams;
use better_auth_core::types::{
    AuthRequest, AuthResponse, CreateMember, CreateOrganization, UpdateOrganization,
};
use better_auth_core::utils::cookie_utils::create_session_cookie;
use better_auth_core::wire::InvitationView;
use std::collections::HashMap;

fn has_role(member: &impl AuthMember, role: &str) -> bool {
    member
        .role()
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == role)
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

pub(crate) async fn create_organization_core(
    body: &CreateOrganizationRequest,
    user: &impl AuthUser,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<CreateOrganizationResponse<CreatedOrganizationResponse, BasicMemberResponse>> {
    if !config.allow_user_to_create_organization {
        return Err(AuthError::forbidden("Organization creation is not allowed"));
    }

    if let Some(limit) = config.organization_limit {
        let user_orgs = ctx.database.list_user_organizations(&user.id()).await?;
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
        return Err(AuthError::bad_request("Organization already exists"));
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
    let member_response = BasicMemberResponse::from_member(&member);

    Ok(CreateOrganizationResponse {
        organization: CreatedOrganizationResponse::from_organization(&organization),
        members: vec![member_response],
    })
}

pub(crate) async fn update_organization_core(
    body: &UpdateOrganizationRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<OrganizationResponse> {
    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, session, ctx).await?;

    let member = ctx
        .database
        .get_member(&org_id, &user.id())
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

    if let Some(ref new_slug) = body.data.slug
        && let Some(existing) = ctx.database.get_organization_by_slug(new_slug).await?
        && existing.id() != org_id
    {
        return Err(AuthError::bad_request("Organization slug already taken"));
    }

    let update_data = UpdateOrganization {
        name: body.data.name.clone(),
        slug: body.data.slug.clone(),
        logo: body.data.logo.clone(),
        metadata: body.data.metadata.clone(),
    };

    let updated = ctx
        .database
        .update_organization(&org_id, update_data)
        .await?;

    Ok(OrganizationResponse::from_organization(&updated))
}

pub(crate) async fn delete_organization_core(
    body: &DeleteOrganizationRequest,
    user: &impl AuthUser,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<OrganizationResponse> {
    if config.disable_organization_deletion {
        return Err(AuthError::forbidden("Organization deletion is disabled"));
    }

    let member = ctx
        .database
        .get_member(&body.organization_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::bad_request("User is not a member of the organization"))?;

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

    let organization = ctx
        .database
        .get_organization_by_id(&body.organization_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;

    ctx.database
        .delete_organization(&body.organization_id)
        .await?;

    Ok(OrganizationResponse::from_organization(&organization))
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

    let members_limit = query.members_limit.or(config.membership_limit);
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
        .map(|member| member.user_id.clone())
        .collect::<Vec<_>>();
    let users_by_id = ctx
        .database
        .list_users_by_ids(&user_ids)
        .await?
        .into_iter()
        .map(|user| (user.id().to_string(), user))
        .collect::<HashMap<_, _>>();
    let mut members = Vec::with_capacity(members_raw.len());

    for member in &members_raw {
        if let Some(user_info) = users_by_id.get(&member.user_id) {
            members.push(MemberResponse::from_member_and_user(member, user_info));
        }
    }

    let invitations = ctx.database.list_organization_invitations(&org_id).await?;

    Ok(Some(FullOrganizationResponse {
        organization: OrganizationResponse::from_organization(&organization),
        members,
        invitations: invitations.iter().map(InvitationView::from).collect(),
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
        return Err(AuthError::bad_request("slug is taken"));
    }

    Ok(CheckSlugResponse { status: true })
}

pub(crate) async fn set_active_organization_core(
    body: &SetActiveOrganizationRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Option<OrganizationResponse>> {
    if matches!(body.organization_id, NullableStringField::Null) {
        if session.active_organization_id().is_none() {
            return Ok(None);
        }

        let _ = ctx
            .database
            .update_session_active_organization(session.token(), None)
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

    let _ = ctx
        .database
        .update_session_active_organization(session.token(), Some(&org_id))
        .await?;

    let organization = ctx
        .database
        .get_organization_by_id(&org_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;

    Ok(Some(OrganizationResponse::from_organization(&organization)))
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

    if has_role(&member, &config.creator_role) {
        let all_members = ctx
            .database
            .list_organization_members(&body.organization_id)
            .await?;
        let owner_count = all_members
            .iter()
            .filter(|candidate| has_role(*candidate, &config.creator_role))
            .count();

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
    let body: CreateOrganizationRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let response = create_organization_core(&body, &user, config, ctx).await?;
    if !body.keep_current_active_organization.unwrap_or(false) {
        let _ = ctx
            .database
            .update_session_active_organization(
                session.token(),
                Some(response.organization.id.as_str()),
            )
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
    let body: UpdateOrganizationRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
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
    let response = delete_organization_core(&body, &user, config, ctx).await?;
    if session.active_organization_id() == Some(&body.organization_id) {
        let _ = ctx
            .database
            .update_session_active_organization(session.token(), None)
            .await?;
    }
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
    let organization = set_active_organization_core(&body, &user, &session, ctx).await?;
    let cookie_header = create_session_cookie(session.token(), &ctx.config);
    Ok(AuthResponse::json(200, &organization)?.with_header("Set-Cookie", cookie_header))
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
    use std::collections::HashMap;

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
            roles: HashMap::new(),
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
                id: None,
                name: "Existing".to_string(),
                slug: "existing".to_string(),
                logo: None,
                metadata: None,
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
                id: None,
                name: "Team".to_string(),
                slug: "team".to_string(),
                logo: None,
                metadata: None,
            })
            .await
            .expect("organization should be created");
        ctx.database
            .create_member(better_auth_core::types::CreateMember {
                organization_id: organization.id.clone(),
                user_id: user.id.clone(),
                role: config.creator_role.clone(),
            })
            .await
            .expect("owner member should be created");

        let extra_user = create_user(&ctx, test_user("member@example.com", "Member")).await;
        ctx.database
            .create_member(better_auth_core::types::CreateMember {
                organization_id: organization.id.clone(),
                user_id: extra_user.id.clone(),
                role: "member".to_string(),
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
