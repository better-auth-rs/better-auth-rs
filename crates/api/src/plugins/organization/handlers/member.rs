use better_auth_core::FieldValue;
use better_auth_core::entity::{AuthMember, AuthOrganization, AuthRecordFields, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::session::NativeSessionData;
use better_auth_core::store::ListOrganizationMembersParams;
use better_auth_core::types::{AuthRequest, AuthResponse};

use super::{require_native_session, resolve_organization_id};
use crate::plugins::organization::rbac::check_permission;
use crate::plugins::organization::types::{
    BasicMemberResponse, GetActiveMemberRoleQuery, GetActiveMemberRoleResponse, ListMembersQuery,
    ListMembersResponse, MemberResponse, RemoveMemberRequest, RemovedMember, RemovedMemberResponse,
    UpdateMemberRoleRequest,
};
use crate::plugins::organization::{OrganizationConfig, hooks::*};

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

pub(crate) async fn get_active_member_core(
    session: &NativeSessionData,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<MemberResponse> {
    let org_id = session.session.active_organization_id.field_value();
    if !org_id.is_truthy() {
        return Err(AuthError::bad_request("No active organization"));
    }

    let joined = ctx
        .database
        .get_member_with_user_value(&org_id, session.user_property("id")?)
        .await?
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    Ok(MemberResponse::from_member_and_user(
        &joined.member,
        &joined.user,
    ))
}

pub(crate) async fn list_members_core(
    query: &ListMembersQuery,
    config: &OrganizationConfig,
    session: &NativeSessionData,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ListMembersResponse> {
    let org_id = if let Some(slug) = query
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
        resolve_organization_id(
            query.organization_id.as_deref(),
            None,
            &session.session,
            ctx,
        )
        .await?
    };
    if !org_id.is_truthy() {
        return Err(AuthError::bad_request("No active organization"));
    }

    let _ = ctx
        .database
        .get_member_with_user_value(&org_id, session.user_property("id")?)
        .await?
        .ok_or_else(|| AuthError::forbidden("You are not a member of this organization"))?;

    let member_params = ListOrganizationMembersParams {
        organization_id: better_auth_core::SchemaValue::from_field(org_id),
        limit: query
            .limit
            .filter(|limit| *limit != 0.0 && !limit.is_nan())
            .or(Some(config.member_list_limit() as f64)),
        offset: query.offset,
        sort_by: query.sort_by.clone(),
        sort_direction: query.sort_direction.clone(),
        filter_field: query.filter_field.clone(),
        filter_value: query
            .filter_value
            .clone()
            .map(better_auth_core::FieldValue::from_json)
            .transpose()?,
        filter_operator: query.filter_operator.clone(),
    };
    let (members_raw, total) = ctx
        .database
        .query_organization_members(&member_params)
        .await?;
    let user_ids = members_raw
        .iter()
        .map(|member| member.user_id.field_value())
        .collect::<Vec<_>>();
    let users = ctx
        .database
        .list_users_by_id_values(&user_ids, members_raw.len() as f64)
        .await?;
    let mut members = Vec::with_capacity(members_raw.len());
    for member in &members_raw {
        let user_info = users
            .iter()
            .find(|user| {
                user.id
                    .field_value()
                    .strict_equals(&member.user_id.field_value())
            })
            .ok_or_else(|| AuthError::internal("Unexpected error: User not found for member"))?;
        members.push(MemberResponse::from_member_and_user(
            member,
            &better_auth_core::MemberUserView::from_user(user_info),
        ));
    }

    Ok(ListMembersResponse { members, total })
}

pub(crate) async fn get_active_member_role_core(
    query: &GetActiveMemberRoleQuery,
    session: &NativeSessionData,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<GetActiveMemberRoleResponse> {
    let org_id = if let Some(slug) = query
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
        resolve_organization_id(
            query.organization_id.as_deref(),
            None,
            &session.session,
            ctx,
        )
        .await?
    };
    if !org_id.is_truthy() {
        return Err(AuthError::bad_request("No active organization"));
    }

    let requester_member = ctx
        .database
        .get_member_with_user_value(&org_id, session.user_property("id")?)
        .await?
        .map(|joined| joined.member)
        .ok_or_else(|| AuthError::forbidden("You are not a member of this organization"))?;

    if let Some(user_id) = query.user_id.as_deref().filter(|id| !id.is_empty()) {
        let target_member = ctx
            .database
            .get_member_with_user_value(&org_id, &user_id.into())
            .await?
            .map(|joined| joined.member)
            .ok_or_else(|| AuthError::forbidden("You are not a member of this organization"))?;
        return Ok(GetActiveMemberRoleResponse {
            role: target_member.role,
        });
    }

    Ok(GetActiveMemberRoleResponse {
        role: requester_member.role,
    })
}

pub(crate) async fn remove_member_core(
    body: &RemoveMemberRequest,
    session: &NativeSessionData,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<RemovedMemberResponse> {
    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, &session.session, ctx)
            .await?;

    let requester_member = ctx
        .database
        .get_member_with_user_value(&org_id, session.user_property("id")?)
        .await?
        .map(|joined| joined.member)
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    let target_member = if body.member_id_or_email.contains('@') {
        let target_user = ctx
            .database
            .get_user_by_email(&body.member_id_or_email)
            .await?
            .ok_or_else(|| AuthError::bad_request("Member not found"))?;
        ctx.database
            .get_member_value(&org_id, &target_user.id().field_value())
            .await?
            .ok_or_else(|| AuthError::bad_request("Member not found"))?
    } else {
        ctx.database
            .get_member_by_id_with_user(&body.member_id_or_email)
            .await?
            .map(|joined| joined.member)
            .ok_or_else(|| AuthError::bad_request("Member not found"))?
    };
    let creator_role = config.creator_role();
    if has_role(&target_member, creator_role)? {
        if !requester_member
            .role()
            .typed()?
            .split(',')
            .map(str::trim)
            .any(|role| role == creator_role)
        {
            return Err(AuthError::bad_request(
                "You cannot leave the organization as the only owner",
            ));
        }
        let all_members = ctx
            .database
            .list_organization_members_value(&org_id)
            .await?;
        let owner_count =
            all_members
                .iter()
                .try_fold(0, |count, candidate| -> AuthResult<usize> {
                    Ok(count + usize::from(has_role(candidate, creator_role)?))
                })?;

        if owner_count <= 1 {
            return Err(AuthError::bad_request(
                "You cannot leave the organization as the only owner",
            ));
        }
    }

    if !check_permission(
        requester_member.role().typed()?,
        &org_id,
        "member",
        &["delete"],
        config,
        ctx,
    )
    .await?
    {
        return Err(AuthError::Upstream {
            status: 401,
            code: "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER",
            message: "You are not allowed to delete this member",
        });
    }
    if !target_member
        .organization_id
        .field_value()
        .strict_equals(&org_id)
    {
        return Err(AuthError::bad_request("Member not found"));
    }
    let organization = ctx
        .database
        .get_organization_by_id_value(&org_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = crate::plugins::organization::fields::organization(&organization, ctx);
    let target_user = ctx
        .database
        .get_user_by_id_value(&target_member.user_id.field_value())
        .await?
        .ok_or_else(|| AuthError::bad_request("User not found"))?;
    let user_value = FieldValue::from(target_user.field_values()?);
    let event = OrganizationMemberEvent {
        member: &target_member,
        user: &user_value,
        organization: &organization_view,
    };
    if let Some(hooks) = &config.hooks {
        hooks.before_remove_member(event).await?;
    }
    let response = RemovedMemberResponse {
        member: RemovedMember {
            member: BasicMemberResponse::from_member(&target_member),
            user: body
                .member_id_or_email
                .contains('@')
                .then(|| better_auth_core::entity::MemberUserView::from_user(&target_user)),
        },
    };

    ctx.database
        .delete_member_for_user_value(
            &target_member.id().field_value(),
            &org_id,
            &target_member.user_id().field_value(),
        )
        .await?;

    if session
        .user_property("id")?
        .strict_equals(&target_member.user_id().field_value())
        && session
            .session
            .active_organization_id
            .field_value()
            .strict_equals(&target_member.organization_id.field_value())
    {
        let _ = ctx
            .database
            .update_session_active_organization_by_token_value(
                &session.session.token.field_value(),
                None,
            )
            .await?;
    }

    if let Some(hooks) = &config.hooks {
        hooks.after_remove_member(event).await?;
    }
    Ok(response)
}

pub(crate) async fn update_member_role_core(
    body: &UpdateMemberRoleRequest,
    session: &NativeSessionData,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<BasicMemberResponse> {
    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, &session.session, ctx)
            .await?;

    let requester_member = ctx
        .database
        .get_member_with_user_value(&org_id, session.user_property("id")?)
        .await?
        .map(|joined| joined.member)
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    let target_member = if requester_member
        .id
        .field_value()
        .strict_equals(&body.member_id.as_str().into())
    {
        requester_member.clone()
    } else {
        ctx.database
            .get_member_by_id_with_user(&body.member_id)
            .await?
            .map(|joined| joined.member)
            .ok_or_else(|| AuthError::bad_request("Member not found"))?
    };

    if !target_member
        .organization_id()
        .field_value()
        .strict_equals(&org_id)
    {
        return Err(AuthError::forbidden(
            "You are not allowed to update this member",
        ));
    }

    let creator_role = config.creator_role();
    let requester_is_owner = has_role(&requester_member, creator_role)?;
    let target_is_owner = has_role(&target_member, creator_role)?;
    let new_role = body.role.joined();
    let new_role_contains_owner = new_role
        .split(',')
        .map(str::trim)
        .any(|role| role == creator_role);

    if (new_role_contains_owner || target_is_owner) && !requester_is_owner {
        return Err(AuthError::forbidden(
            "You are not allowed to update this member",
        ));
    }

    if requester_is_owner
        && requester_member
            .id()
            .field_value()
            .strict_equals(&target_member.id().field_value())
    {
        let all_members = ctx
            .database
            .list_organization_members_value(&org_id)
            .await?;
        let owner_count =
            all_members
                .iter()
                .try_fold(0, |count, candidate| -> AuthResult<usize> {
                    Ok(count + usize::from(has_role(candidate, creator_role)?))
                })?;

        if owner_count <= 1 && !new_role_contains_owner {
            return Err(AuthError::bad_request(
                "You cannot leave the organization without an owner",
            ));
        }
    }

    if !requester_is_owner
        && !check_permission(
            requester_member.role().typed()?,
            &org_id,
            "member",
            &["update"],
            config,
            ctx,
        )
        .await?
    {
        return Err(AuthError::forbidden(
            "You are not allowed to update this member",
        ));
    }

    let unknown_static_roles = body
        .role
        .roles()
        .into_iter()
        .filter(|role| {
            !["owner", "admin", "member"].contains(role)
                && !config
                    .roles
                    .as_ref()
                    .is_some_and(|roles| roles.contains_key(*role))
        })
        .collect::<Vec<_>>();
    let dynamic_roles = if config.dynamic_access_control && !unknown_static_roles.is_empty() {
        ctx.database
            .query_organization_roles_value(
                &org_id,
                &unknown_static_roles
                    .iter()
                    .map(|role| (*role).to_owned())
                    .collect::<Vec<_>>(),
            )
            .await?
    } else {
        Vec::new()
    };
    let unknown_roles = unknown_static_roles
        .into_iter()
        .filter(|role| {
            !dynamic_roles.iter().any(|stored| {
                stored
                    .role
                    .field_value()
                    .strict_equals(&FieldValue::from(*role))
            })
        })
        .collect::<Vec<_>>();
    if !unknown_roles.is_empty() {
        return Err(AuthError::bad_request(format!(
            "ROLE_NOT_FOUND: {}",
            unknown_roles.join(", ")
        )));
    }

    let organization = ctx
        .database
        .get_organization_by_id_value(&org_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let organization_view = crate::plugins::organization::fields::organization(&organization, ctx);
    let target_user = ctx
        .database
        .get_user_by_id_value(&target_member.user_id.field_value())
        .await?
        .ok_or_else(|| AuthError::bad_request("User not found"))?;
    let user_value =
        better_auth_core::FieldValue::from(better_auth_core::FieldMap::from(target_user));
    let event = OrganizationMemberEvent {
        member: &target_member,
        user: &user_value,
        organization: &organization_view,
    };
    let mut overridden_role = new_role.clone();
    if let Some(hooks) = &config.hooks {
        hooks
            .before_update_member_role(&mut overridden_role, event)
            .await?;
    }
    let new_role = if overridden_role.is_empty() {
        new_role
    } else {
        overridden_role
    };
    let updated = ctx
        .database
        .update_member_role(&body.member_id, &new_role)
        .await?;

    if let Some(hooks) = &config.hooks {
        hooks
            .after_update_member_role(
                target_member.role.typed()?,
                OrganizationMemberEvent {
                    member: &updated,
                    ..event
                },
            )
            .await?;
    }
    Ok(BasicMemberResponse::from_member(&updated))
}

// ---------------------------------------------------------------------------
// Old handlers (rewritten to call core)
// ---------------------------------------------------------------------------

/// Handle get active member request
pub async fn handle_get_active_member(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let response = get_active_member_core(&session, ctx).await?;
    Ok(AuthResponse::json(None, &response)?)
}

/// Handle list members request
pub async fn handle_list_members(
    req: &AuthRequest,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let query = crate::plugins::query_input::parse::<ListMembersQuery>(&req.query)?;
    let response = list_members_core(&query, config, &session, ctx).await?;
    Ok(AuthResponse::json(None, &response)?)
}

/// Handle get active member role request
pub async fn handle_get_active_member_role(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let query = crate::plugins::query_input::parse::<GetActiveMemberRoleQuery>(&req.query)?;
    let response = get_active_member_role_core(&query, &session, ctx).await?;
    Ok(AuthResponse::json(None, &response)?)
}

/// Handle remove member request
pub async fn handle_remove_member(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let body: RemoveMemberRequest = super::super::request::read(req, &config.schema)?;
    let response = remove_member_core(&body, &session, config, ctx).await?;
    Ok(AuthResponse::json(None, &response)?)
}

/// Handle update member role request
pub async fn handle_update_member_role(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let body: UpdateMemberRoleRequest = super::super::request::read(req, &config.schema)?;
    let response = match update_member_role_core(&body, &session, config, ctx).await {
        Err(AuthError::BadRequest(message)) if message.starts_with("ROLE_NOT_FOUND: ") => {
            return Err(AuthResponse::json(
                400,
                &serde_json::json!({ "code": "ROLE_NOT_FOUND", "message": message }),
            )?
            .into());
        }
        result => result?,
    };
    Ok(AuthResponse::json(None, &response)?)
}
