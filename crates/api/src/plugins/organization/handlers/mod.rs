pub mod invitation;
pub mod member;
pub mod org;
pub mod roles;
pub mod team;

pub use invitation::*;
pub use member::*;
pub use org::*;

use better_auth_core::entity::{AuthMember, AuthSession};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::session::NativeSessionData;
use better_auth_core::types::{AuthRequest, AuthResponse};

use super::OrganizationConfig;
use super::rbac::check_permissions;
use super::types::{HasPermissionRequest, HasPermissionResponse};

/// Helper function to require authenticated session
pub(crate) async fn require_session<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<(
    better_auth_core::wire::UserView,
    better_auth_core::wire::SessionView,
)> {
    ctx.require_session(req).await.map_err(|error| match error {
        AuthError::Unauthenticated => AuthError::Upstream {
            status: 401,
            code: "UNAUTHORIZED",
            message: "Unauthorized",
        },
        error => error,
    })
}

pub(crate) async fn require_native_session<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<NativeSessionData> {
    ctx.require_native_session(req)
        .await
        .map_err(|error| match error {
            AuthError::Unauthenticated => AuthError::Upstream {
                status: 401,
                code: "UNAUTHORIZED",
                message: "Unauthorized",
            },
            error => error,
        })
}

async fn optional_session<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<
    Option<(
        better_auth_core::wire::UserView,
        better_auth_core::wire::SessionView,
    )>,
> {
    match ctx.require_session(req).await {
        Ok(session) => Ok(Some(session)),
        Err(AuthError::Unauthenticated) => Ok(None),
        Err(error) => Err(error),
    }
}
fn request_present<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> bool {
    let endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        Some(req),
        better_auth_core::FieldValue::Null,
        ctx,
    );
    endpoint.request.is_some() || endpoint.headers().is_some()
}
async fn request_only_session<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<
    Option<(
        better_auth_core::wire::UserView,
        better_auth_core::wire::SessionView,
    )>,
> {
    let session = optional_session(req, ctx).await?;
    if session.is_none() && request_present(req, ctx) {
        return Err(AuthError::Upstream {
            status: 401,
            code: "UNAUTHORIZED",
            message: "Unauthorized",
        });
    }
    Ok(session)
}

/// Helper function to get organization ID from request or session
pub(crate) async fn resolve_organization_id(
    org_id: Option<&str>,
    org_slug: Option<&str>,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<better_auth_core::FieldValue> {
    if let Some(id) = org_id.filter(|id| !id.is_empty()) {
        return Ok(id.into());
    }

    if let Some(slug) = org_slug.filter(|slug| !slug.is_empty()) {
        if let Some(org) = ctx.database.get_organization_by_slug(slug).await? {
            use better_auth_core::entity::AuthOrganization;
            return Ok(org.id().field_value());
        }
        return Err(AuthError::not_found("Organization not found"));
    }

    let id = session.active_organization_id().field_value();
    id.is_truthy()
        .then_some(id)
        .ok_or_else(|| AuthError::bad_request("No active organization"))
}

// ---------------------------------------------------------------------------
// Core function
// ---------------------------------------------------------------------------

pub(crate) async fn has_permission_core(
    body: &HasPermissionRequest,
    session: &NativeSessionData,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<HasPermissionResponse> {
    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, &session.session, ctx)
            .await?;

    let member = ctx
        .database
        .get_member_with_user_value(&org_id, session.user_property("id")?)
        .await?
        .map(|joined| joined.member)
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    let has_all_permissions = check_permissions(
        member.role().typed()?,
        &org_id,
        body.permissions.as_ref(),
        config,
        ctx,
    )
    .await?;

    Ok(HasPermissionResponse {
        success: has_all_permissions,
        error: None,
    })
}

// ---------------------------------------------------------------------------
// Old handler (rewritten to call core)
// ---------------------------------------------------------------------------

/// Handle has-permission request
pub async fn handle_has_permission(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let body: HasPermissionRequest = super::request::read(req, &config.schema)?;
    let response = has_permission_core(&body, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

#[cfg(test)]
mod native_tests;
