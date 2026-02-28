use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use validator::Validate;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};

use better_auth_core::utils::cookie_utils::create_clear_session_cookie;
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};

use super::StatusResponse;

/// Session management plugin for handling session operations
pub struct SessionManagementPlugin {
    config: SessionManagementConfig,
}

#[derive(Debug, Clone)]
pub struct SessionManagementConfig {
    pub enable_session_listing: bool,
    pub enable_session_revocation: bool,
    pub require_authentication: bool,
}

// Request structures for session endpoints
#[derive(Debug, Deserialize, Validate)]
struct RevokeSessionRequest {
    #[validate(length(min = 1, message = "Token is required"))]
    token: String,
}

// Response structures
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SignOutResponse {
    success: bool,
}

#[derive(Debug, Serialize)]
struct GetSessionResponse<S: Serialize, U: Serialize> {
    session: S,
    user: U,
}

impl SessionManagementPlugin {
    pub fn new() -> Self {
        Self {
            config: SessionManagementConfig::default(),
        }
    }

    pub fn with_config(config: SessionManagementConfig) -> Self {
        Self { config }
    }

    pub fn enable_session_listing(mut self, enable: bool) -> Self {
        self.config.enable_session_listing = enable;
        self
    }

    pub fn enable_session_revocation(mut self, enable: bool) -> Self {
        self.config.enable_session_revocation = enable;
        self
    }

    pub fn require_authentication(mut self, require: bool) -> Self {
        self.config.require_authentication = require;
        self
    }
}

impl Default for SessionManagementPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SessionManagementConfig {
    fn default() -> Self {
        Self {
            enable_session_listing: true,
            enable_session_revocation: true,
            require_authentication: true,
        }
    }
}

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for SessionManagementPlugin {
    fn name(&self) -> &'static str {
        "session-management"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/get-session", "get_session"),
            AuthRoute::post("/get-session", "get_session_post"),
            AuthRoute::post("/sign-out", "sign_out"),
            AuthRoute::get("/list-sessions", "list_sessions"),
            AuthRoute::post("/revoke-session", "revoke_session"),
            AuthRoute::post("/revoke-sessions", "revoke_sessions"),
            AuthRoute::post("/revoke-other-sessions", "revoke_other_sessions"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get | HttpMethod::Post, "/get-session") => {
                Ok(Some(self.handle_get_session(req, ctx).await?))
            }
            (HttpMethod::Post, "/sign-out") => Ok(Some(self.handle_sign_out(req, ctx).await?)),
            (HttpMethod::Get, "/list-sessions") if self.config.enable_session_listing => {
                Ok(Some(self.handle_list_sessions(req, ctx).await?))
            }
            (HttpMethod::Post, "/revoke-session") if self.config.enable_session_revocation => {
                Ok(Some(self.handle_revoke_session(req, ctx).await?))
            }
            (HttpMethod::Post, "/revoke-sessions") if self.config.enable_session_revocation => {
                Ok(Some(self.handle_revoke_sessions(req, ctx).await?))
            }
            (HttpMethod::Post, "/revoke-other-sessions")
                if self.config.enable_session_revocation =>
            {
                Ok(Some(self.handle_revoke_other_sessions(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Core functions — framework-agnostic business logic
// ---------------------------------------------------------------------------

pub(crate) async fn sign_out_core<DB: DatabaseAdapter>(
    session: &DB::Session,
    ctx: &AuthContext<DB>,
) -> AuthResult<SignOutResponse> {
    ctx.database.delete_session(session.token()).await?;
    Ok(SignOutResponse { success: true })
}

pub(crate) async fn list_sessions_core<DB: DatabaseAdapter>(
    user_id: &str,
    ctx: &AuthContext<DB>,
) -> AuthResult<Vec<DB::Session>> {
    ctx.database.get_user_sessions(user_id).await
}

pub(crate) async fn revoke_session_core<DB: DatabaseAdapter>(
    user: &DB::User,
    token: &str,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    // Verify the session belongs to the current user before revoking
    let session_manager = ctx.session_manager();
    if let Some(session_to_revoke) = session_manager.get_session(token).await?
        && session_to_revoke.user_id() != user.id()
    {
        return Err(AuthError::forbidden(
            "Cannot revoke session that belongs to another user",
        ));
    }

    ctx.database.delete_session(token).await?;
    Ok(StatusResponse { status: true })
}

pub(crate) async fn revoke_sessions_core<DB: DatabaseAdapter>(
    user_id: &str,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    ctx.database.delete_user_sessions(user_id).await?;
    Ok(StatusResponse { status: true })
}

pub(crate) async fn revoke_other_sessions_core<DB: DatabaseAdapter>(
    user_id: &str,
    current_session: &DB::Session,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    let all_sessions: Vec<DB::Session> = ctx.database.get_user_sessions(user_id).await?;
    for session in all_sessions {
        if session.token() != current_session.token() {
            ctx.database.delete_session(session.token()).await?;
        }
    }
    Ok(StatusResponse { status: true })
}

// ---------------------------------------------------------------------------
// Old handler methods — delegate to core functions
// ---------------------------------------------------------------------------

impl SessionManagementPlugin {
    async fn handle_get_session<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, session) = ctx.require_session(req).await?;
        let response = GetSessionResponse { session, user };
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_sign_out<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (_user, session) = ctx.require_session(req).await?;
        let response = sign_out_core(&session, ctx).await?;
        let clear_cookie = create_clear_session_cookie(&ctx.config);
        Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", clear_cookie))
    }

    async fn handle_list_sessions<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx.require_session(req).await?;
        let sessions = list_sessions_core(user.id(), ctx).await?;
        Ok(AuthResponse::json(200, &sessions)?)
    }

    async fn handle_revoke_session<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx.require_session(req).await?;

        let revoke_req: RevokeSessionRequest = req
            .body_as_json()
            .map_err(|e| AuthError::bad_request(format!("Invalid JSON: {}", e)))?;

        let response = revoke_session_core(&user, &revoke_req.token, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_revoke_sessions<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx.require_session(req).await?;
        let response = revoke_sessions_core(user.id(), ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_revoke_other_sessions<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, current_session) = ctx.require_session(req).await?;
        let response = revoke_other_sessions_core(user.id(), &current_session, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }
}

#[cfg(feature = "axum")]
mod axum_impl {
    use super::*;
    use std::sync::Arc;

    use axum::Json;
    use axum::extract::{Extension, State};
    use axum::http::header;
    use better_auth_core::{AuthState, CurrentSession, ValidatedJson};

    #[derive(Clone)]
    struct PluginState {
        config: SessionManagementConfig,
    }

    // get_session is trivially simple: just construct the response directly.
    async fn handle_get_session<DB: DatabaseAdapter>(
        CurrentSession { user, session }: CurrentSession<DB>,
    ) -> Result<Json<GetSessionResponse<DB::Session, DB::User>>, AuthError> {
        Ok(Json(GetSessionResponse { session, user }))
    }

    async fn handle_sign_out<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { session, .. }: CurrentSession<DB>,
    ) -> Result<([(header::HeaderName, String); 1], Json<SignOutResponse>), AuthError> {
        let ctx = state.to_context();
        let response = sign_out_core(&session, &ctx).await?;
        let cookie = state.clear_session_cookie();
        Ok(([(header::SET_COOKIE, cookie)], Json(response)))
    }

    async fn handle_list_sessions<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
    ) -> Result<Json<Vec<DB::Session>>, AuthError> {
        if !ps.config.enable_session_listing {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let sessions = list_sessions_core(user.id(), &ctx).await?;
        Ok(Json(sessions))
    }

    async fn handle_revoke_session<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<RevokeSessionRequest>,
    ) -> Result<Json<StatusResponse>, AuthError> {
        if !ps.config.enable_session_revocation {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let response = revoke_session_core(&user, &body.token, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_revoke_sessions<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
    ) -> Result<Json<StatusResponse>, AuthError> {
        if !ps.config.enable_session_revocation {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let response = revoke_sessions_core(user.id(), &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_revoke_other_sessions<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, session }: CurrentSession<DB>,
    ) -> Result<Json<StatusResponse>, AuthError> {
        if !ps.config.enable_session_revocation {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let response = revoke_other_sessions_core(user.id(), &session, &ctx).await?;
        Ok(Json(response))
    }

    impl<DB: DatabaseAdapter> better_auth_core::AxumPlugin<DB> for SessionManagementPlugin {
        fn name(&self) -> &'static str {
            "session-management"
        }

        fn router(&self) -> axum::Router<AuthState<DB>> {
            use axum::routing::{get, post};

            let plugin_state = Arc::new(PluginState {
                config: self.config.clone(),
            });
            axum::Router::new()
                .route(
                    "/get-session",
                    get(handle_get_session::<DB>).post(handle_get_session::<DB>),
                )
                .route("/sign-out", post(handle_sign_out::<DB>))
                .route("/list-sessions", get(handle_list_sessions::<DB>))
                .route("/revoke-session", post(handle_revoke_session::<DB>))
                .route("/revoke-sessions", post(handle_revoke_sessions::<DB>))
                .route(
                    "/revoke-other-sessions",
                    post(handle_revoke_other_sessions::<DB>),
                )
                .layer(Extension(plugin_state))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers;
    use better_auth_core::adapters::{MemoryDatabaseAdapter, SessionOps, UserOps};
    use better_auth_core::{CreateSession, CreateUser, Session};
    use chrono::{Duration, Utc};

    #[tokio::test]
    async fn test_get_session_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/get-session",
            Some(&session.token),
            None,
        );
        let response = plugin.handle_get_session(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(
            response_data["session"]["token"].as_str().unwrap(),
            session.token
        );
        assert_eq!(
            response_data["user"]["email"]
                .as_str()
                .map(|s| s.to_string()),
            Some("test@example.com".to_string())
        );
    }

    #[tokio::test]
    async fn test_get_session_unauthorized() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user, _session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let req =
            test_helpers::create_auth_request_no_query(HttpMethod::Get, "/get-session", None, None);
        let err = plugin.handle_get_session(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn test_sign_out_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/sign-out",
            Some(&session.token),
            Some(b"{}".to_vec()),
        );
        let response = plugin.handle_sign_out(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: SignOutResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.success);

        let session_check = ctx.database.get_session(&session.token).await.unwrap();
        assert!(session_check.is_none());
    }

    #[tokio::test]
    async fn test_list_sessions_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let create_session2 = CreateSession {
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("another-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        };
        ctx.database.create_session(create_session2).await.unwrap();

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/list-sessions",
            Some(&session.token),
            None,
        );
        let response = plugin.handle_list_sessions(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let sessions: Vec<Session> = serde_json::from_str(&body_str).unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn test_revoke_session_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let create_session2 = CreateSession {
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("another-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        };
        let session2 = ctx.database.create_session(create_session2).await.unwrap();

        let body = serde_json::json!({ "token": session2.token });
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/revoke-session",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_revoke_session(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let session2_check = ctx.database.get_session(&session2.token).await.unwrap();
        assert!(session2_check.is_none());

        let session1_check = ctx.database.get_session(&session.token).await.unwrap();
        assert!(session1_check.is_some());
    }

    #[tokio::test]
    async fn test_revoke_session_forbidden_different_user() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user1, session1) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let create_user2 = CreateUser::new()
            .with_email("user2@example.com")
            .with_name("User Two");
        let user2 = ctx.database.create_user(create_user2).await.unwrap();

        let create_session2 = CreateSession {
            user_id: user2.id,
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("another-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        };
        let session2 = ctx.database.create_session(create_session2).await.unwrap();

        let body = serde_json::json!({ "token": session2.token });
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/revoke-session",
            Some(&session1.token),
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_revoke_session(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 403);
    }

    #[tokio::test]
    async fn test_revoke_sessions_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, user, session1) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let create_session2 = CreateSession {
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("another-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        };
        ctx.database.create_session(create_session2).await.unwrap();

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/revoke-sessions",
            Some(&session1.token),
            Some(b"{}".to_vec()),
        );
        let response = plugin.handle_revoke_sessions(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);

        let user_sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert_eq!(user_sessions.len(), 0);
    }

    #[tokio::test]
    async fn test_plugin_routes() {
        let plugin = SessionManagementPlugin::new();
        let routes = AuthPlugin::<MemoryDatabaseAdapter>::routes(&plugin);

        assert_eq!(routes.len(), 7);
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/get-session" && r.method == HttpMethod::Get)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/sign-out" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/list-sessions" && r.method == HttpMethod::Get)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/revoke-session" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/revoke-sessions" && r.method == HttpMethod::Post)
        );
    }

    #[tokio::test]
    async fn test_plugin_on_request_routing() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        // Test valid route
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/get-session",
            Some(&session.token),
            None,
        );
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_some());
        assert_eq!(response.unwrap().status, 200);

        // Test invalid route
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/invalid-route",
            Some(&session.token),
            None,
        );
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_none());
    }

    #[tokio::test]
    async fn test_configuration() {
        let plugin = SessionManagementPlugin::new()
            .enable_session_listing(false)
            .enable_session_revocation(false)
            .require_authentication(false);

        assert!(!plugin.config.enable_session_listing);
        assert!(!plugin.config.enable_session_revocation);
        assert!(!plugin.config.require_authentication);

        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/list-sessions",
            Some(&session.token),
            None,
        );
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_none());

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/revoke-session",
            Some(&session.token),
            Some(b"{}".to_vec()),
        );
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_none());
    }
}
