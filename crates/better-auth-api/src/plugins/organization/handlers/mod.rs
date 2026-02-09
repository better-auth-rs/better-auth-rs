pub mod invitation;
pub mod member;
pub mod org;

pub use invitation::*;
pub use member::*;
pub use org::*;

use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::session::SessionManager;
use better_auth_core::types::{AuthRequest, AuthResponse, Session, User};

use super::config::OrganizationConfig;
use super::rbac::{Action, Resource, has_permission_any};
use super::types::{HasPermissionRequest, HasPermissionResponse};

/// Helper function to require authenticated session
pub(crate) async fn require_session(
    req: &AuthRequest,
    ctx: &AuthContext,
) -> AuthResult<(User, Session)> {
    let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());

    if let Some(token) = session_manager.extract_session_token(req)
        && let Some(session) = session_manager.get_session(&token).await?
        && let Some(user) = ctx.database.get_user_by_id(&session.user_id).await?
    {
        return Ok((user, session));
    }

    Err(AuthError::Unauthenticated)
}

/// Helper function to get organization ID from request or session
pub(crate) async fn resolve_organization_id(
    org_id: Option<&str>,
    org_slug: Option<&str>,
    session: &Session,
    ctx: &AuthContext,
) -> AuthResult<String> {
    // If org_id is provided, use it
    if let Some(id) = org_id {
        return Ok(id.to_string());
    }

    // If org_slug is provided, resolve it
    if let Some(slug) = org_slug {
        if let Some(org) = ctx.database.get_organization_by_slug(slug).await? {
            return Ok(org.id);
        }
        return Err(AuthError::not_found("Organization not found"));
    }

    // Fall back to active organization from session
    session
        .active_organization_id
        .clone()
        .ok_or_else(|| AuthError::bad_request("No active organization"))
}

/// Handle has-permission request
pub async fn handle_has_permission(
    req: &AuthRequest,
    ctx: &AuthContext,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;

    // Manually deserialize since HasPermissionRequest doesn't need validation
    let body: HasPermissionRequest = req
        .body_as_json()
        .map_err(|e| AuthError::bad_request(format!("Invalid request body: {}", e)))?;

    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, &session, ctx).await?;

    // Get member to check their role
    let member = ctx
        .database
        .get_member(&org_id, &user.id)
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    // Check all requested permissions
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

            if !has_permission_any(&member.role, &resource, &action, &config.roles) {
                has_all_permissions = false;
                break;
            }
        }

        if !has_all_permissions {
            break;
        }
    }

    let response = HasPermissionResponse {
        success: has_all_permissions,
        error: if has_all_permissions {
            None
        } else {
            Some("Permission denied".to_string())
        },
    };

    Ok(AuthResponse::json(200, &response)?)
}
