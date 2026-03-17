use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use validator::Validate;

use better_auth_core::config::AuthConfig;
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};

use better_auth_core::AuthResult;
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};

use super::StatusResponse;
use better_auth_core::SuccessResponse;

/// Session management plugin for handling session operations
pub struct SessionManagementPlugin {
    config: SessionManagementConfig,
}

#[derive(Debug, Clone, better_auth_core::PluginConfig)]
#[plugin(name = "SessionManagementPlugin")]
pub struct SessionManagementConfig {
    #[config(default = true)]
    pub enable_session_listing: bool,
    #[config(default = true)]
    pub enable_session_revocation: bool,
    #[config(default = true)]
    pub require_authentication: bool,
}

// Request structures for session endpoints
#[derive(Debug, Deserialize, Validate)]
struct RevokeSessionRequest {
    #[validate(length(min = 1, message = "Token is required"))]
    token: String,
}

#[derive(Debug, Serialize)]
struct GetSessionResponse<S: Serialize, U: Serialize> {
    session: S,
    user: U,
}

#[async_trait]
impl AuthPlugin for SessionManagementPlugin {
    fn name(&self) -> &'static str {
        "session-management"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/get-session", "get_session"),
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
        ctx: &AuthContext,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, "/get-session") => Ok(Some(self.handle_get_session(req, ctx).await?)),
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

pub(crate) async fn sign_out_core(
    session: &better_auth_core::Session,
    ctx: &AuthContext,
) -> AuthResult<SuccessResponse> {
    ctx.database.delete_session(session.token()).await?;
    Ok(SuccessResponse { success: true })
}

pub(crate) async fn list_sessions_core(
    user_id: &str,
    ctx: &AuthContext,
) -> AuthResult<Vec<better_auth_core::Session>> {
    ctx.session_manager().list_user_sessions(user_id).await
}

pub(crate) async fn revoke_session_core(
    user: &better_auth_core::User,
    token: &str,
    ctx: &AuthContext,
) -> AuthResult<StatusResponse> {
    let session_manager = ctx.session_manager();
    if let Some(session_to_revoke) = session_manager.get_session(token).await?
        && session_to_revoke.user_id() == user.id()
    {
        ctx.database.delete_session(token).await?;
    }
    Ok(StatusResponse { status: true })
}

pub(crate) async fn revoke_sessions_core(
    user_id: &str,
    ctx: &AuthContext,
) -> AuthResult<StatusResponse> {
    ctx.database.delete_user_sessions(user_id).await?;
    Ok(StatusResponse { status: true })
}

pub(crate) async fn revoke_other_sessions_core(
    user_id: &str,
    current_session: &better_auth_core::Session,
    ctx: &AuthContext,
) -> AuthResult<StatusResponse> {
    let all_sessions: Vec<better_auth_core::Session> =
        ctx.session_manager().list_user_sessions(user_id).await?;
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
    async fn handle_get_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        // Returns 200 with null body when unauthenticated (never an error status).
        match ctx.require_session(req).await {
            Ok((user, session)) => {
                let response = GetSessionResponse { session, user };
                Ok(AuthResponse::json(200, &response)?)
            }
            Err(_) => Ok(AuthResponse::json(200, &serde_json::Value::Null)?),
        }
    }

    async fn handle_sign_out(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        if let Ok((_user, session)) = ctx.require_session(req).await {
            let _ = sign_out_core(&session, ctx).await;
        }

        let mut response = AuthResponse::json(200, &SuccessResponse { success: true })?;
        for cookie in sign_out_cookies(&ctx.config) {
            response.headers.append("Set-Cookie", cookie);
        }
        Ok(response)
    }

    async fn handle_list_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx.require_session(req).await?;
        let sessions = list_sessions_core(user.id(), ctx).await?;
        Ok(AuthResponse::json(200, &sessions)?)
    }

    async fn handle_revoke_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx.require_session(req).await?;

        let revoke_req: RevokeSessionRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let response = revoke_session_core(&user, &revoke_req.token, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_revoke_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx.require_session(req).await?;
        let response = revoke_sessions_core(user.id(), ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_revoke_other_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        let (user, current_session) = ctx.require_session(req).await?;
        let response = revoke_other_sessions_core(user.id(), &current_session, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }
}

fn related_cookie_name(config: &AuthConfig, suffix: &str) -> String {
    config
        .session
        .cookie_name
        .strip_suffix("session_token")
        .map(|prefix| format!("{}{}", prefix, suffix))
        .unwrap_or_else(|| format!("better-auth.{}", suffix))
}

fn sign_out_cookies(config: &AuthConfig) -> Vec<String> {
    let mut cookies = vec![
        better_auth_core::utils::cookie_utils::create_clear_session_cookie(config),
        better_auth_core::utils::cookie_utils::create_clear_cookie(
            &related_cookie_name(config, "session_data"),
            config,
        ),
        better_auth_core::utils::cookie_utils::create_clear_cookie(
            &related_cookie_name(config, "dont_remember"),
            config,
        ),
    ];

    if config.account.store_account_cookie {
        cookies.push(better_auth_core::utils::cookie_utils::create_clear_cookie(
            &related_cookie_name(config, "account_data"),
            config,
        ));
    }

    cookies
}

#[cfg(feature = "axum")]
mod axum_impl {
    use super::*;
    use std::sync::Arc;

    use axum::Json;
    use axum::extract::{Extension, State};
    use axum::http::{HeaderValue, header};
    use axum::response::IntoResponse;
    use better_auth_core::{AuthError, AuthState, CurrentSession, OptionalSession, ValidatedJson};

    #[derive(Clone)]
    struct PluginState {
        config: SessionManagementConfig,
    }

    // get_session is trivially simple: just construct the response directly.
    async fn handle_get_session(
        CurrentSession { user, session }: CurrentSession,
    ) -> Result<
        Json<GetSessionResponse<better_auth_core::Session, better_auth_core::User>>,
        AuthError,
    > {
        Ok(Json(GetSessionResponse { session, user }))
    }

    async fn handle_sign_out(
        State(state): State<AuthState>,
        OptionalSession(session): OptionalSession,
    ) -> Result<axum::response::Response, AuthError> {
        let response = if let Some(CurrentSession { session, .. }) = session {
            let ctx = state.to_context();
            sign_out_core(&session, &ctx).await?
        } else {
            SuccessResponse { success: true }
        };

        let mut headers = axum::http::HeaderMap::new();
        for cookie in sign_out_cookies(&state.config) {
            let header_value = HeaderValue::from_str(&cookie).map_err(|error| {
                AuthError::internal(format!("Invalid cookie header: {}", error))
            })?;
            _ = headers.append(header::SET_COOKIE, header_value);
        }

        Ok((headers, Json(response)).into_response())
    }

    async fn handle_list_sessions(
        State(state): State<AuthState>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession,
    ) -> Result<Json<Vec<better_auth_core::Session>>, AuthError> {
        if !ps.config.enable_session_listing {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let sessions = list_sessions_core(user.id(), &ctx).await?;
        Ok(Json(sessions))
    }

    async fn handle_revoke_session(
        State(state): State<AuthState>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession,
        ValidatedJson(body): ValidatedJson<RevokeSessionRequest>,
    ) -> Result<Json<StatusResponse>, AuthError> {
        if !ps.config.enable_session_revocation {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let response = revoke_session_core(&user, &body.token, &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_revoke_sessions(
        State(state): State<AuthState>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession,
    ) -> Result<Json<StatusResponse>, AuthError> {
        if !ps.config.enable_session_revocation {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let response = revoke_sessions_core(user.id(), &ctx).await?;
        Ok(Json(response))
    }

    async fn handle_revoke_other_sessions(
        State(state): State<AuthState>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, session }: CurrentSession,
    ) -> Result<Json<StatusResponse>, AuthError> {
        if !ps.config.enable_session_revocation {
            return Err(AuthError::not_found("Not found"));
        }
        let ctx = state.to_context();
        let response = revoke_other_sessions_core(user.id(), &session, &ctx).await?;
        Ok(Json(response))
    }

    impl better_auth_core::AxumPlugin for SessionManagementPlugin {
        fn name(&self) -> &'static str {
            "session-management"
        }

        fn router(&self) -> axum::Router<AuthState> {
            use axum::routing::{get, post};

            let plugin_state = Arc::new(PluginState {
                config: self.config.clone(),
            });
            axum::Router::new()
                .route("/get-session", get(handle_get_session))
                .route("/sign-out", post(handle_sign_out))
                .route("/list-sessions", get(handle_list_sessions))
                .route("/revoke-session", post(handle_revoke_session))
                .route("/revoke-sessions", post(handle_revoke_sessions))
                .route("/revoke-other-sessions", post(handle_revoke_other_sessions))
                .layer(Extension(plugin_state))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers;
    use better_auth_core::config::AccountConfig;
    use better_auth_core::{CreateSession, CreateUser, Session};
    use chrono::{Duration, Utc};

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
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

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
    #[tokio::test]
    async fn test_get_session_unauthorized() {
        // /get-session returns 200 with null body when unauthenticated.
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
        let response = plugin.handle_get_session(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).expect("valid JSON");
        assert!(body.is_null());
    }

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
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
        let response_data: SuccessResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.success);

        let session_check = ctx.database.get_session(&session.token).await.unwrap();
        assert!(session_check.is_none());
    }

    #[tokio::test]
    async fn test_sign_out_clears_account_cookie_when_enabled() {
        let plugin = SessionManagementPlugin::new();
        let config = test_helpers::create_test_config().account(AccountConfig {
            store_account_cookie: true,
            ..Default::default()
        });
        let ctx = test_helpers::create_test_context_with_config(config).await;
        let (_user, session) = test_helpers::create_user_and_session(
            &ctx,
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

        let account_cookie_name = format!("{}=", related_cookie_name(&ctx.config, "account_data"));
        assert!(
            response
                .headers
                .get_all("Set-Cookie")
                .any(|cookie| cookie.starts_with(&account_cookie_name)),
            "sign-out should clear the account_data cookie when store_account_cookie is enabled"
        );
    }

    #[tokio::test]
    async fn test_sign_out_does_not_emit_account_cookie_when_disabled() {
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

        let account_cookie_name = format!("{}=", related_cookie_name(&ctx.config, "account_data"));
        assert!(
            !response
                .headers
                .get_all("Set-Cookie")
                .any(|cookie| cookie.starts_with(&account_cookie_name)),
            "sign-out should not emit account_data clearing cookies when store_account_cookie is disabled"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
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

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
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

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
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

        let response = plugin.handle_revoke_session(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["status"], true);

        let still_exists = ctx.database.get_session(&session2.token).await.unwrap();
        assert!(
            still_exists.is_some(),
            "other user's session must not be revoked"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
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

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
    #[tokio::test]
    async fn test_plugin_routes() {
        let plugin = SessionManagementPlugin::new();
        let routes = AuthPlugin::routes(&plugin);

        assert_eq!(routes.len(), 6);
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/get-session" && r.method == HttpMethod::Get)
        );
        assert!(
            !routes
                .iter()
                .any(|r| r.path == "/get-session" && r.method == HttpMethod::Post)
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

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
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

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/get-session",
            Some(&session.token),
            Some(b"{}".to_vec()),
        );
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_none());

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

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
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
