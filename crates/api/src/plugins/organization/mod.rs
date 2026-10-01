mod fields;
pub mod handlers;
pub mod hooks;
mod input;
mod native_json;
mod policy;
mod server_api;
pub use better_auth_core::organization_fields::OrganizationFields;
pub use server_api::AddMemberInput;
pub mod rbac;
pub mod types;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::entity::AuthSession;
use better_auth_core::error::AuthResult;
use better_auth_core::plugin::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::types::{AuthRequest, AuthResponse, HttpMethod};

/// Data supplied when an invitation is created or resent.
pub struct InvitationEmail {
    /// The persisted invitation, including its current expiration.
    pub invitation: better_auth_core::wire::InvitationView,
    /// The organization receiving the invited member.
    pub organization: types::OrganizationResponse,
    /// The member sending the invitation.
    pub member: better_auth_core::types::Member,
    /// The user sending the invitation.
    pub inviter: better_auth_core::wire::UserView,
    /// HTTP request that initiated delivery, absent for requestless server calls.
    pub request: Option<AuthRequest>,
}

/// Application callback for invitation email delivery.
#[async_trait]
pub trait SendInvitationEmail: Send + Sync {
    /// Send the invitation email. The plugin logs delivery errors without failing the request.
    async fn send(&self, email: &InvitationEmail) -> AuthResult<()>;
}

/// Permission definitions for a role
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct RolePermissions {
    pub organization: Vec<String>,
    pub member: Vec<String>,
    pub invitation: Vec<String>,
    /// Actions this role may perform on organization-owned API keys. Upstream's
    /// default statements define none, so only the creator role can manage them
    /// until an application grants this explicitly.
    pub api_key: Vec<String>,
    pub team: Vec<String>,
    pub ac: Vec<String>,
    #[serde(flatten)]
    pub additional: HashMap<String, Vec<String>>,
}

/// Team creation and membership limits.
#[derive(Clone)]
pub struct OrganizationTeamsConfig {
    pub enabled: bool,
    pub default_team: bool,
    pub allow_removing_all_teams: bool,
    pub maximum_teams: Option<usize>,
    pub maximum_members_per_team: Option<usize>,
    /// Dynamic capacity. Trusted server calls require a session when this callback is configured.
    pub maximum_members_per_team_callback: Option<Arc<dyn hooks::TeamMemberLimitPolicy>>,
}

impl std::fmt::Debug for OrganizationTeamsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrganizationTeamsConfig")
            .field("enabled", &self.enabled)
            .field("default_team", &self.default_team)
            .field("allow_removing_all_teams", &self.allow_removing_all_teams)
            .field("maximum_teams", &self.maximum_teams)
            .field("maximum_members_per_team", &self.maximum_members_per_team)
            .field(
                "maximum_members_per_team_callback",
                &self
                    .maximum_members_per_team_callback
                    .as_ref()
                    .map(|_| "custom"),
            )
            .finish()
    }
}

impl Default for OrganizationTeamsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_team: true,
            allow_removing_all_teams: false,
            maximum_teams: None,
            maximum_members_per_team: None,
            maximum_members_per_team_callback: None,
        }
    }
}

/// Configuration for the Organization plugin
#[derive(Clone, better_auth_core::PluginConfig)]
#[plugin(name = "OrganizationPlugin")]
pub struct OrganizationConfig {
    /// Application fields for organization entities.
    #[config(default = better_auth_core::organization_fields::OrganizationFields::default(), skip)]
    pub schema: OrganizationFields,

    /// Application lifecycle hooks.
    #[config(default = None, skip)]
    pub hooks: Option<Arc<dyn hooks::OrganizationHooks>>,
    /// Asynchronous organization configuration.
    #[config(default = None, skip)]
    pub policy: Option<Arc<dyn hooks::OrganizationPolicy>>,
    /// Enable teams and configure team limits.
    #[config(default = OrganizationTeamsConfig::default(), skip)]
    pub teams: OrganizationTeamsConfig,
    /// Enable persisted organization roles.
    #[config(default = false)]
    pub dynamic_access_control: bool,
    /// Maximum persisted roles per organization.
    #[config(default = None)]
    pub maximum_roles_per_organization: Option<usize>,
    /// Resource statements for dynamic access control.
    #[config(default = None, skip)]
    pub ac: Option<HashMap<String, Vec<String>>>,
    /// Allow users to create organizations (default: true)
    #[config(default = true)]
    pub allow_user_to_create_organization: bool,
    /// Maximum organizations per user (None = unlimited)
    #[config(default = None)]
    pub organization_limit: Option<usize>,
    /// Maximum members per organization (None or zero uses upstream default 100)
    #[config(default = Some(100))]
    pub membership_limit: Option<usize>,
    /// Dynamic membership capacity, replacing the static admission limit.
    #[config(default = None, skip)]
    pub membership_limit_callback: Option<Arc<dyn hooks::MembershipLimitPolicy>>,
    /// Role assigned to organization creator (default: "owner")
    #[config(default = "owner".to_string())]
    pub creator_role: String,
    /// Invitation expiration in seconds (default: 48 hours)
    #[config(default = 60 * 60 * 48)]
    pub invitation_expires_in: u64,
    /// Maximum pending invitations per organization (None uses upstream default 100)
    #[config(default = Some(100))]
    pub invitation_limit: Option<usize>,
    /// Cancel the previous pending invitation before creating a replacement.
    #[config(default = false)]
    pub cancel_pending_invitations_on_re_invite: bool,
    /// Require a verified recipient email for invitation lookup, acceptance, and rejection.
    #[config(default = false)]
    pub require_email_verification_on_invitation: bool,
    /// Disable organization deletion (default: false)
    #[config(default = false)]
    pub disable_organization_deletion: bool,
    /// Static role definitions. An explicit map, including an empty map, replaces defaults.
    #[config(default = None, skip)]
    pub roles: Option<HashMap<String, RolePermissions>>,
    /// Optional delivery callback used for new and resent invitations.
    #[config(default = None, skip)]
    pub send_invitation_email: Option<Arc<dyn SendInvitationEmail>>,
}

impl std::fmt::Debug for OrganizationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrganizationConfig")
            .field(
                "allow_user_to_create_organization",
                &self.allow_user_to_create_organization,
            )
            .field("organization_limit", &self.organization_limit)
            .field("membership_limit", &self.membership_limit)
            .field("creator_role", &self.creator_role)
            .field("invitation_expires_in", &self.invitation_expires_in)
            .field("invitation_limit", &self.invitation_limit)
            .field(
                "cancel_pending_invitations_on_re_invite",
                &self.cancel_pending_invitations_on_re_invite,
            )
            .field(
                "require_email_verification_on_invitation",
                &self.require_email_verification_on_invitation,
            )
            .field(
                "disable_organization_deletion",
                &self.disable_organization_deletion,
            )
            .field("roles", &self.roles)
            .field("teams", &self.teams)
            .field("dynamic_access_control", &self.dynamic_access_control)
            .field(
                "maximum_roles_per_organization",
                &self.maximum_roles_per_organization,
            )
            .field("ac", &self.ac)
            .field(
                "send_invitation_email",
                &self.send_invitation_email.as_ref().map(|_| "custom"),
            )
            .finish()
    }
}

/// Organization plugin for multi-tenancy support
#[derive(Clone)]
pub struct OrganizationPlugin {
    config: OrganizationConfig,
}

impl OrganizationPlugin {
    /// Configure dynamic organization capacity. Listing retains the upstream default page size.
    pub fn membership_limit_callback(
        mut self,
        callback: Arc<dyn hooks::MembershipLimitPolicy>,
    ) -> Self {
        self.config.membership_limit_callback = Some(callback);
        self
    }
    /// Configure application lifecycle hooks.
    pub fn hooks(mut self, hooks: Arc<dyn hooks::OrganizationHooks>) -> Self {
        self.config.hooks = Some(hooks);
        self
    }
    /// Configure asynchronous organization options.
    pub fn policy(mut self, policy: Arc<dyn hooks::OrganizationPolicy>) -> Self {
        self.config.policy = Some(policy);
        self
    }
    /// Configure organization teams.
    pub fn teams(mut self, teams: OrganizationTeamsConfig) -> Self {
        self.config.teams = teams;
        self
    }
    /// Configure access-control resource statements.
    pub fn access_control(mut self, ac: HashMap<String, Vec<String>>) -> Self {
        self.config.ac = Some(ac);
        self
    }
    /// Configure delivery for new and resent invitations.
    pub fn custom_send_invitation_email(mut self, sender: Arc<dyn SendInvitationEmail>) -> Self {
        self.config.send_invitation_email = Some(sender);
        self
    }
}

/// Metadata key announcing that the organization plugin is installed.
pub(crate) const METADATA_DYNAMIC_ACCESS_CONTROL: &str = "organization.dynamic_access_control";
pub(crate) const METADATA_AC: &str = "organization.ac";
pub(crate) const METADATA_ENABLED: &str = "organization.enabled";
/// Metadata key carrying the configured custom roles, so other plugins can run
/// the organization's access control without depending on this plugin's config.
pub(crate) const METADATA_ROLES: &str = "organization.roles";
/// Metadata key carrying the creator role, which is allowed every action.
pub(crate) const METADATA_CREATOR_ROLE: &str = "organization.creator_role";

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for OrganizationPlugin {
    fn name(&self) -> &'static str {
        "organization"
    }

    fn openapi(
        &self,
    ) -> better_auth_core::AuthResult<better_auth_core::openapi::OpenApiPluginMetadata> {
        better_auth_core::openapi::OpenApiPluginMetadata::from_routes(
            <Self as better_auth_core::AuthPlugin<S>>::name(self),
            <Self as better_auth_core::AuthPlugin<S>>::routes(self),
        )?
        .organization_fields(&self.config.schema)
    }

    async fn on_init(
        &self,
        ctx: &mut better_auth_core::AuthInitContext<S>,
    ) -> better_auth_core::AuthResult<()> {
        ctx.database
            .configure_organization_fields(self.config.schema.clone())?;
        ctx.extensions.insert(self.config.schema.clone());

        S::Session::require_plugin_fields("organization", &["active_organization_id"])?;
        if self.config.teams.enabled {
            S::Session::require_plugin_fields("organization", &["active_team_id"])?;
        }
        ctx.set_metadata(
            METADATA_DYNAMIC_ACCESS_CONTROL,
            serde_json::json!(self.config.dynamic_access_control),
        );
        ctx.set_metadata(METADATA_AC, serde_json::json!(self.config.ac));
        ctx.set_metadata(
            "organization.teams_enabled",
            serde_json::json!(self.config.teams.enabled),
        );
        ctx.set_metadata(METADATA_ENABLED, serde_json::Value::Bool(true));
        ctx.set_metadata(
            METADATA_ROLES,
            serde_json::to_value(&self.config.roles).unwrap_or_default(),
        );
        ctx.set_metadata(
            METADATA_CREATOR_ROLE,
            serde_json::Value::String(self.config.creator_role.clone()),
        );
        Ok(())
    }

    fn routes(&self) -> Vec<AuthRoute> {
        let mut routes = vec![
            // Organization CRUD
            AuthRoute::post("/organization/create", "create_organization"),
            AuthRoute::post("/organization/update", "update_organization"),
            AuthRoute::post("/organization/delete", "delete_organization"),
            AuthRoute::get("/organization/list", "list_organizations"),
            AuthRoute::get("/organization/get-organization", "get_organization"),
            AuthRoute::get(
                "/organization/get-full-organization",
                "get_full_organization",
            ),
            AuthRoute::post("/organization/check-slug", "check_slug"),
            AuthRoute::post("/organization/set-active", "set_active_organization"),
            AuthRoute::post("/organization/leave", "leave_organization"),
            // Member management
            AuthRoute::get("/organization/get-active-member", "get_active_member"),
            AuthRoute::get(
                "/organization/get-active-member-role",
                "get_active_member_role",
            ),
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
        ];
        if self.config.teams.enabled {
            routes.extend(handlers::team::routes());
        }
        if self.config.dynamic_access_control {
            for (path, method) in [
                ("create-role", HttpMethod::Post),
                ("get-role", HttpMethod::Get),
                ("list-roles", HttpMethod::Get),
                ("update-role", HttpMethod::Post),
                ("delete-role", HttpMethod::Post),
            ] {
                routes.push(match method {
                    HttpMethod::Get => AuthRoute::get(format!("/organization/{path}"), path),
                    _ => AuthRoute::post(format!("/organization/{path}"), path),
                });
            }
        }
        routes
    }

    async fn after_request(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        if !response
            .headers
            .get("content-type")
            .is_some_and(|value| value.starts_with("application/json"))
            || response.body.is_empty()
        {
            return Ok(());
        }
        let mut value = serde_json::from_slice(&response.body)?;
        let changed = fields::shape_session_teams(&mut value, self.config.teams.enabled)?;
        if response.status < 400 && req.path().starts_with("/organization/") {
            let mut value = serde_json::from_str(value.get())?;
            fields::filter_response(req.path(), &mut value, &self.config.schema);
            response.body = serde_json::to_vec(&value)?;
        } else if changed {
            response.body = serde_json::to_vec(&value)?;
        }
        Ok(())
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if self.config.teams.enabled
            && handlers::team::routes()
                .iter()
                .any(|route| route.path == req.path())
        {
            return handlers::team::handle_team_request(req, ctx, &self.config).await;
        }
        if self.config.dynamic_access_control
            && matches!(
                req.path(),
                "/organization/create-role"
                    | "/organization/get-role"
                    | "/organization/list-roles"
                    | "/organization/update-role"
                    | "/organization/delete-role"
            )
        {
            return handlers::roles::handle_role_request(req, ctx, &self.config).await;
        }
        let response: AuthResult<Option<AuthResponse>> = match (req.method(), req.path()) {
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
            (HttpMethod::Get, "/organization/get-organization") => Ok(Some(
                handlers::org::handle_get_organization(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/get-full-organization") => Ok(Some(
                handlers::org::handle_get_full_organization(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/check-slug") => {
                Ok(Some(handlers::org::handle_check_slug(req, ctx).await?))
            }
            (HttpMethod::Post, "/organization/set-active") => Ok(Some(
                handlers::org::handle_set_active_organization(req, ctx).await?,
            )),
            (HttpMethod::Post, "/organization/leave") => Ok(Some(
                handlers::org::handle_leave_organization(req, ctx, &self.config).await?,
            )),
            // Member management
            (HttpMethod::Get, "/organization/get-active-member") => Ok(Some(
                handlers::member::handle_get_active_member(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/get-active-member-role") => Ok(Some(
                handlers::member::handle_get_active_member_role(req, ctx).await?,
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
                handlers::invitation::handle_get_invitation(req, ctx, &self.config).await?,
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
                handlers::invitation::handle_reject_invitation(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/cancel-invitation") => Ok(Some(
                handlers::invitation::handle_cancel_invitation(req, ctx, &self.config).await?,
            )),
            // Permission check
            (HttpMethod::Post, "/organization/has-permission") => Ok(Some(
                handlers::handle_has_permission(req, ctx, &self.config).await?,
            )),
            _ => Ok(None),
        };
        response?
            .map(|mut response| {
                shape_invitation_output(req.path(), &mut response, self.config.teams.enabled)?;
                Ok(response)
            })
            .transpose()
    }
}

fn shape_invitation_output(
    path: &str,
    response: &mut AuthResponse,
    teams_enabled: bool,
) -> AuthResult<()> {
    if response.status >= 400
        || !matches!(
            path,
            "/organization/invite-member"
                | "/organization/get-invitation"
                | "/organization/list-invitations"
                | "/organization/list-user-invitations"
                | "/organization/accept-invitation"
                | "/organization/reject-invitation"
                | "/organization/cancel-invitation"
                | "/organization/get-full-organization"
        )
    {
        return Ok(());
    }
    let mut value: serde_json::Value = serde_json::from_slice(&response.body)?;
    let shape = |invitation: &mut serde_json::Value| {
        if let Some(object) = invitation.as_object_mut() {
            if teams_enabled {
                let _ = object.entry("teamId").or_insert(serde_json::Value::Null);
            } else {
                let _ = object.remove("teamId");
            }
        }
    };
    match path {
        "/organization/list-invitations" | "/organization/list-user-invitations" => {
            if let Some(invitations) = value.as_array_mut() {
                invitations.iter_mut().for_each(shape);
            }
        }
        "/organization/get-full-organization" => {
            if let Some(invitations) = value
                .get_mut("invitations")
                .and_then(serde_json::Value::as_array_mut)
            {
                invitations.iter_mut().for_each(shape);
            }
        }
        "/organization/accept-invitation" | "/organization/reject-invitation" => {
            if let Some(invitation) = value.get_mut("invitation") {
                shape(invitation);
            }
        }
        _ => shape(&mut value),
    }
    response.body = serde_json::to_vec(&value)?;
    Ok(())
}
