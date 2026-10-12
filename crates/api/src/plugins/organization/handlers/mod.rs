pub mod invitation;
pub mod member;
pub mod org;
pub mod roles;
pub mod team;

pub use invitation::*;
pub use member::*;
pub use org::*;

use better_auth_core::entity::AuthMember;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::session::NativeSessionData;
use better_auth_core::types::{AuthRequest, AuthResponse};

use super::OrganizationConfig;
use super::rbac::check_permissions;
use super::types::{HasPermissionRequest, HasPermissionResponse};

pub(crate) async fn require_native_session<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<NativeSessionData> {
    ctx.require_native_session(req)
        .await
        .map_err(|error| match error.original() {
            AuthError::Unauthenticated => {
                AuthError::from_code("UNAUTHORIZED", "UNAUTHORIZED", "Unauthorized")
            }
            _ => error,
        })
}

async fn optional_session<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<Option<NativeSessionData>> {
    match ctx.require_native_session(req).await {
        Ok(session) => Ok(Some(session)),
        Err(error) if matches!(error.original(), AuthError::Unauthenticated) => Ok(None),
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
) -> AuthResult<Option<NativeSessionData>> {
    let session = optional_session(req, ctx).await?;
    if session.is_none() && request_present(req, ctx) {
        return Err(AuthError::from_code(
            "UNAUTHORIZED",
            "UNAUTHORIZED",
            "Unauthorized",
        ));
    }
    Ok(session)
}

/// Resolve the organization ID from the request or the session.
pub(crate) fn resolve_organization_id(
    org_id: Option<&str>,
    session: &NativeSessionData,
    missing: AuthError,
) -> AuthResult<better_auth_core::FieldValue> {
    if let Some(id) = org_id.filter(|id| !id.is_empty()) {
        return Ok(id.into());
    }

    let id = session.session_property("activeOrganizationId")?;
    id.is_truthy().then_some(id).ok_or(missing)
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
    let org_id = resolve_organization_id(
        body.organization_id.as_deref(),
        session,
        AuthError::from_code(
            "BAD_REQUEST",
            "NO_ACTIVE_ORGANIZATION",
            "No active organization",
        ),
    )?;

    let member = ctx
        .database
        .get_member_with_user_value(&org_id, &session.user_property("id")?)
        .await?
        .map(|joined| joined.member)
        .ok_or_else(|| {
            AuthError::from_code(
                "UNAUTHORIZED",
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
                "User is not a member of the organization",
            )
        })?;

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
    AuthResponse::json(None, &response)
}

#[cfg(test)]
mod native_cookie_transaction_tests;
#[cfg(test)]
mod native_mutation_tests;
#[cfg(test)]
mod native_tests;

#[cfg(test)]
mod native_email_tests;
