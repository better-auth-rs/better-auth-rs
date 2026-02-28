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

#[cfg(feature = "axum")]
use better_auth_core::plugin::{AuthState, AxumPlugin};

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

// ---------------------------------------------------------------------------
// Axum-native routing (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "axum")]
mod axum_impl {
    use super::*;
    use std::sync::Arc;

    use axum::Json;
    use axum::extract::{Extension, Query, State};
    use better_auth_core::error::AuthError;
    use better_auth_core::extractors::{CurrentSession, ValidatedJson};

    use super::handlers::has_permission_core;
    use super::handlers::invitation::{
        accept_invitation_core, cancel_invitation_core, get_invitation_core, invite_member_core,
        list_invitations_core, list_user_invitations_core, reject_invitation_core,
    };
    use super::handlers::member::{
        get_active_member_core, list_members_core, remove_member_core, update_member_role_core,
    };
    use super::handlers::org::{
        check_slug_core, create_organization_core, delete_organization_core,
        get_full_organization_core, leave_organization_core, list_organizations_core,
        set_active_organization_core, update_organization_core,
    };
    use super::types::*;

    #[derive(Clone)]
    struct PluginState {
        config: OrganizationConfig,
    }

    // -- Organization CRUD --

    async fn handle_create_organization<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<CreateOrganizationRequest>,
    ) -> Result<Json<CreateOrganizationResponse<DB::Organization, MemberResponse>>, AuthError> {
        let ctx = state.to_context();
        let result = create_organization_core(&body, &user, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_update_organization<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, session, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<UpdateOrganizationRequest>,
    ) -> Result<Json<DB::Organization>, AuthError> {
        let ctx = state.to_context();
        let result = update_organization_core(&body, &user, &session, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_delete_organization<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        Json(body): Json<DeleteOrganizationRequest>,
    ) -> Result<Json<SuccessResponse>, AuthError> {
        let ctx = state.to_context();
        let result = delete_organization_core(&body, &user, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_list_organizations<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
    ) -> Result<Json<Vec<DB::Organization>>, AuthError> {
        let ctx = state.to_context();
        let result = list_organizations_core(&user, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_get_full_organization<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { user, session, .. }: CurrentSession<DB>,
        Query(query): Query<GetFullOrganizationQuery>,
    ) -> Result<Json<FullOrganizationResponse<DB::Organization, DB::Invitation>>, AuthError> {
        let ctx = state.to_context();
        let result = get_full_organization_core(&query, &user, &session, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_check_slug<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { .. }: CurrentSession<DB>,
        Json(body): Json<CheckSlugRequest>,
    ) -> Result<Json<CheckSlugResponse>, AuthError> {
        let ctx = state.to_context();
        let result = check_slug_core(&body, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_set_active_organization<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { user, session, .. }: CurrentSession<DB>,
        Json(body): Json<SetActiveOrganizationRequest>,
    ) -> Result<Json<DB::Session>, AuthError> {
        let ctx = state.to_context();
        let result = set_active_organization_core(&body, &user, &session, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_leave_organization<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { user, session, .. }: CurrentSession<DB>,
        Json(body): Json<LeaveOrganizationRequest>,
    ) -> Result<Json<SuccessResponse>, AuthError> {
        let ctx = state.to_context();
        let result = leave_organization_core(&body, &user, &session, &ctx).await?;
        Ok(Json(result))
    }

    // -- Member management --

    async fn handle_get_active_member<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { user, session, .. }: CurrentSession<DB>,
    ) -> Result<Json<MemberResponse>, AuthError> {
        let ctx = state.to_context();
        let result = get_active_member_core(&user, &session, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_list_members<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { user, session, .. }: CurrentSession<DB>,
        Query(query): Query<ListMembersQuery>,
    ) -> Result<Json<ListMembersResponse>, AuthError> {
        let ctx = state.to_context();
        let result = list_members_core(&query, &user, &session, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_remove_member<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, session, .. }: CurrentSession<DB>,
        Json(body): Json<RemoveMemberRequest>,
    ) -> Result<Json<RemovedMemberResponse>, AuthError> {
        let ctx = state.to_context();
        let result = remove_member_core(&body, &user, &session, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_update_member_role<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, session, .. }: CurrentSession<DB>,
        Json(body): Json<UpdateMemberRoleRequest>,
    ) -> Result<Json<MemberWrappedResponse>, AuthError> {
        let ctx = state.to_context();
        let result = update_member_role_core(&body, &user, &session, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    // -- Invitations --

    async fn handle_invite_member<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, session, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<InviteMemberRequest>,
    ) -> Result<Json<DB::Invitation>, AuthError> {
        let ctx = state.to_context();
        let result = invite_member_core(&body, &user, &session, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_get_invitation<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Query(query): Query<GetInvitationQuery>,
    ) -> Result<Json<GetInvitationResponse<DB::Invitation>>, AuthError> {
        let ctx = state.to_context();
        let result = get_invitation_core(&query, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_list_invitations<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { user, session, .. }: CurrentSession<DB>,
        Query(query): Query<ListInvitationsQuery>,
    ) -> Result<Json<Vec<DB::Invitation>>, AuthError> {
        let ctx = state.to_context();
        let result = list_invitations_core(&query, &user, &session, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_list_user_invitations<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
    ) -> Result<Json<Vec<DB::Invitation>>, AuthError> {
        let ctx = state.to_context();
        let result = list_user_invitations_core(&user, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_accept_invitation<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, session, .. }: CurrentSession<DB>,
        Json(body): Json<AcceptInvitationRequest>,
    ) -> Result<Json<AcceptInvitationResponse<DB::Invitation>>, AuthError> {
        let ctx = state.to_context();
        let result = accept_invitation_core(&body, &user, &session, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_reject_invitation<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        Json(body): Json<RejectInvitationRequest>,
    ) -> Result<Json<SuccessResponse>, AuthError> {
        let ctx = state.to_context();
        let result = reject_invitation_core(&body, &user, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_cancel_invitation<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        Json(body): Json<CancelInvitationRequest>,
    ) -> Result<Json<SuccessResponse>, AuthError> {
        let ctx = state.to_context();
        let result = cancel_invitation_core(&body, &user, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    // -- Permission check --

    async fn handle_has_permission<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, session, .. }: CurrentSession<DB>,
        Json(body): Json<HasPermissionRequest>,
    ) -> Result<Json<HasPermissionResponse>, AuthError> {
        let ctx = state.to_context();
        let result = has_permission_core(&body, &user, &session, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    // -- AxumPlugin impl --

    #[async_trait]
    impl<DB: DatabaseAdapter> AxumPlugin<DB> for OrganizationPlugin {
        fn name(&self) -> &'static str {
            "organization"
        }

        fn router(&self) -> axum::Router<AuthState<DB>> {
            use axum::routing::{get, post};

            let plugin_state = Arc::new(PluginState {
                config: self.config.clone(),
            });

            axum::Router::new()
                // Organization CRUD
                .route(
                    "/organization/create",
                    post(handle_create_organization::<DB>),
                )
                .route(
                    "/organization/update",
                    post(handle_update_organization::<DB>),
                )
                .route(
                    "/organization/delete",
                    post(handle_delete_organization::<DB>),
                )
                .route("/organization/list", get(handle_list_organizations::<DB>))
                .route(
                    "/organization/get-full-organization",
                    get(handle_get_full_organization::<DB>),
                )
                .route("/organization/check-slug", post(handle_check_slug::<DB>))
                .route(
                    "/organization/set-active",
                    post(handle_set_active_organization::<DB>),
                )
                .route("/organization/leave", post(handle_leave_organization::<DB>))
                // Member management
                .route(
                    "/organization/get-active-member",
                    get(handle_get_active_member::<DB>),
                )
                .route("/organization/list-members", get(handle_list_members::<DB>))
                .route(
                    "/organization/remove-member",
                    post(handle_remove_member::<DB>),
                )
                .route(
                    "/organization/update-member-role",
                    post(handle_update_member_role::<DB>),
                )
                // Invitations
                .route(
                    "/organization/invite-member",
                    post(handle_invite_member::<DB>),
                )
                .route(
                    "/organization/get-invitation",
                    get(handle_get_invitation::<DB>),
                )
                .route(
                    "/organization/list-invitations",
                    get(handle_list_invitations::<DB>),
                )
                .route(
                    "/organization/list-user-invitations",
                    get(handle_list_user_invitations::<DB>),
                )
                .route(
                    "/organization/accept-invitation",
                    post(handle_accept_invitation::<DB>),
                )
                .route(
                    "/organization/reject-invitation",
                    post(handle_reject_invitation::<DB>),
                )
                .route(
                    "/organization/cancel-invitation",
                    post(handle_cancel_invitation::<DB>),
                )
                // Permission check
                .route(
                    "/organization/has-permission",
                    post(handle_has_permission::<DB>),
                )
                .layer(Extension(plugin_state))
        }
    }
}
