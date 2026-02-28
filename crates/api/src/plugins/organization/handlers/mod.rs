pub mod invitation;
pub mod member;
pub mod org;

pub use invitation::*;
pub use member::*;
pub use org::*;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthMember, AuthSession, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::types::{AuthRequest, AuthResponse};

use super::config::OrganizationConfig;
use super::rbac::{Action, Resource, has_permission_any};
use super::types::{HasPermissionRequest, HasPermissionResponse};

/// Helper function to require authenticated session
pub(crate) async fn require_session<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<(DB::User, DB::Session)> {
    let session_manager = ctx.session_manager();

    if let Some(token) = session_manager.extract_session_token(req)
        && let Some(session) = session_manager.get_session(&token).await?
        && let Some(user) = ctx.database.get_user_by_id(session.user_id()).await?
    {
        return Ok((user, session));
    }

    Err(AuthError::Unauthenticated)
}

/// Helper function to get organization ID from request or session
pub(crate) async fn resolve_organization_id<DB: DatabaseAdapter>(
    org_id: Option<&str>,
    org_slug: Option<&str>,
    session: &DB::Session,
    ctx: &AuthContext<DB>,
) -> AuthResult<String> {
    if let Some(id) = org_id {
        return Ok(id.to_string());
    }

    if let Some(slug) = org_slug {
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

pub(crate) async fn has_permission_core<DB: DatabaseAdapter>(
    body: &HasPermissionRequest,
    user: &DB::User,
    session: &DB::Session,
    config: &OrganizationConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<HasPermissionResponse> {
    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, session, ctx).await?;

    let member = ctx
        .database
        .get_member(&org_id, user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    let mut has_all_permissions = true;

    for (resource_str, actions) in &body.permissions {
        let resource = match Resource::parse(resource_str) {
            Some(r) => r,
            None => {
                has_all_permissions = false;
                break;
            }
        };

        for action_str in actions {
            let action = match Action::parse(action_str) {
                Some(a) => a,
                None => {
                    has_all_permissions = false;
                    break;
                }
            };

            if !has_permission_any(member.role(), &resource, &action, &config.roles) {
                has_all_permissions = false;
                break;
            }
        }

        if !has_all_permissions {
            break;
        }
    }

    Ok(HasPermissionResponse {
        success: has_all_permissions,
        error: if has_all_permissions {
            None
        } else {
            Some("Permission denied".to_string())
        },
    })
}

// ---------------------------------------------------------------------------
// Old handler (rewritten to call core)
// ---------------------------------------------------------------------------

/// Handle has-permission request
pub async fn handle_has_permission<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
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
