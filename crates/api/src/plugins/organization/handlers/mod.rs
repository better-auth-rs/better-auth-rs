pub mod invitation;
pub mod member;
pub mod org;
pub mod roles;
pub mod team;

pub use invitation::*;
pub use member::*;
pub use org::*;

use better_auth_core::entity::{AuthMember, AuthSession, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
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

/// Helper function to get organization ID from request or session
pub(crate) async fn resolve_organization_id(
    org_id: Option<&str>,
    org_slug: Option<&str>,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<String> {
    if let Some(id) = org_id.filter(|id| !id.is_empty()) {
        return Ok(id.to_string());
    }

    if let Some(slug) = org_slug.filter(|slug| !slug.is_empty()) {
        if let Some(org) = ctx.database.get_organization_by_slug(slug).await? {
            use better_auth_core::entity::AuthOrganization;
            return Ok(org.id().to_string());
        }
        return Err(AuthError::not_found("Organization not found"));
    }

    session
        .active_organization_id()
        .map(|s| s.to_string())
        .ok_or_else(|| AuthError::bad_request("No active organization"))
}

// ---------------------------------------------------------------------------
// Core function
// ---------------------------------------------------------------------------

pub(crate) async fn has_permission_core(
    body: &HasPermissionRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<HasPermissionResponse> {
    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, session, ctx).await?;

    let member = ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    let has_all_permissions = check_permissions(
        member.role().typed()?,
        &org_id,
        &body.permissions,
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
    let (user, session) = require_session(req, ctx).await?;
    let body: HasPermissionRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let response = has_permission_core(&body, &user, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}
