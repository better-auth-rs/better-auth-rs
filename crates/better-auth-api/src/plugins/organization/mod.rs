pub mod config;
pub mod handlers;
pub mod rbac;
pub mod types;

use async_trait::async_trait;
use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::error::AuthResult;
use better_auth_core::plugin::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::types::{AuthRequest, AuthResponse, HttpMethod};
pub use config::OrganizationConfig;

/// Organization plugin for multi-tenancy support
pub struct OrganizationPlugin {
    config: OrganizationConfig,
}

impl OrganizationPlugin {
    pub fn new() -> Self {
        Self {
            config: OrganizationConfig::default(),
        }
    }

    pub fn with_config(config: OrganizationConfig) -> Self {
        Self { config }
    }

    // Builder methods
    pub fn allow_user_to_create_organization(mut self, allow: bool) -> Self {
        self.config.allow_user_to_create_organization = allow;
        self
    }

    pub fn organization_limit(mut self, limit: usize) -> Self {
        self.config.organization_limit = Some(limit);
        self
    }

    pub fn membership_limit(mut self, limit: usize) -> Self {
        self.config.membership_limit = Some(limit);
        self
    }

    pub fn creator_role(mut self, role: impl Into<String>) -> Self {
        self.config.creator_role = role.into();
        self
    }

    pub fn invitation_expires_in(mut self, seconds: u64) -> Self {
        self.config.invitation_expires_in = seconds;
        self
    }

    pub fn invitation_limit(mut self, limit: usize) -> Self {
        self.config.invitation_limit = Some(limit);
        self
    }

    pub fn disable_organization_deletion(mut self, disable: bool) -> Self {
        self.config.disable_organization_deletion = disable;
        self
    }
}

impl Default for OrganizationPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for OrganizationPlugin {
    fn name(&self) -> &'static str {
        "organization"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            // Organization CRUD
            AuthRoute::post("/organization/create", "create_organization"),
            AuthRoute::post("/organization/update", "update_organization"),
            AuthRoute::post("/organization/delete", "delete_organization"),
            AuthRoute::get("/organization/list", "list_organizations"),
            AuthRoute::get(
                "/organization/get-full-organization",
                "get_full_organization",
            ),
            AuthRoute::post("/organization/check-slug", "check_slug"),
            AuthRoute::post("/organization/set-active", "set_active_organization"),
            AuthRoute::post("/organization/leave", "leave_organization"),
            // Member management
            AuthRoute::get("/organization/get-active-member", "get_active_member"),
            AuthRoute::get("/organization/list-members", "list_members"),
            AuthRoute::post("/organization/remove-member", "remove_member"),
            AuthRoute::post("/organization/update-member-role", "update_member_role"),
            // Invitations
            AuthRoute::post("/organization/invite-member", "invite_member"),
            AuthRoute::get("/organization/get-invitation", "get_invitation"),
            AuthRoute::get("/organization/list-invitations", "list_invitations"),
            AuthRoute::get(
                "/organization/list-user-invitations",
                "list_user_invitations",
            ),
            AuthRoute::post("/organization/accept-invitation", "accept_invitation"),
            AuthRoute::post("/organization/reject-invitation", "reject_invitation"),
            AuthRoute::post("/organization/cancel-invitation", "cancel_invitation"),
            // Permission check
            AuthRoute::post("/organization/has-permission", "has_permission"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            // Organization CRUD
            (HttpMethod::Post, "/organization/create") => Ok(Some(
                handlers::org::handle_create_organization(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/update") => Ok(Some(
                handlers::org::handle_update_organization(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/delete") => Ok(Some(
                handlers::org::handle_delete_organization(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Get, "/organization/list") => Ok(Some(
                handlers::org::handle_list_organizations(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/get-full-organization") => Ok(Some(
                handlers::org::handle_get_full_organization(req, ctx).await?,
            )),
            (HttpMethod::Post, "/organization/check-slug") => {
                Ok(Some(handlers::org::handle_check_slug(req, ctx).await?))
            }
            (HttpMethod::Post, "/organization/set-active") => Ok(Some(
                handlers::org::handle_set_active_organization(req, ctx).await?,
            )),
            (HttpMethod::Post, "/organization/leave") => Ok(Some(
                handlers::org::handle_leave_organization(req, ctx).await?,
            )),
            // Member management
            (HttpMethod::Get, "/organization/get-active-member") => Ok(Some(
                handlers::member::handle_get_active_member(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/list-members") => {
                Ok(Some(handlers::member::handle_list_members(req, ctx).await?))
            }
            (HttpMethod::Post, "/organization/remove-member") => Ok(Some(
                handlers::member::handle_remove_member(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/update-member-role") => Ok(Some(
                handlers::member::handle_update_member_role(req, ctx, &self.config).await?,
            )),
            // Invitations
            (HttpMethod::Post, "/organization/invite-member") => Ok(Some(
                handlers::invitation::handle_invite_member(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Get, "/organization/get-invitation") => Ok(Some(
                handlers::invitation::handle_get_invitation(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/list-invitations") => Ok(Some(
                handlers::invitation::handle_list_invitations(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/list-user-invitations") => Ok(Some(
                handlers::invitation::handle_list_user_invitations(req, ctx).await?,
            )),
            (HttpMethod::Post, "/organization/accept-invitation") => Ok(Some(
                handlers::invitation::handle_accept_invitation(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/reject-invitation") => Ok(Some(
                handlers::invitation::handle_reject_invitation(req, ctx).await?,
            )),
            (HttpMethod::Post, "/organization/cancel-invitation") => Ok(Some(
                handlers::invitation::handle_cancel_invitation(req, ctx, &self.config).await?,
            )),
            // Permission check
            (HttpMethod::Post, "/organization/has-permission") => Ok(Some(
                handlers::handle_has_permission(req, ctx, &self.config).await?,
            )),
            _ => Ok(None),
        }
    }
}
