use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::core::{AuthPlugin, AuthRoute, AuthContext, SessionManager, PluginCapabilities};
use crate::types::{AuthRequest, AuthResponse, HttpMethod, User, Session};
use crate::error::AuthResult;

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
#[derive(Debug, Deserialize)]
struct RevokeSessionRequest {
    token: String,
}

// Response structures
#[derive(Debug, Serialize, Deserialize)]
struct GetSessionResponse {
    session: Session,
    user: User,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignOutResponse {
    success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct StatusResponse {
    status: bool,
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
        ]
    }

    fn capabilities(&self) -> PluginCapabilities {
        PluginCapabilities {
            needs_database: true,
            ..PluginCapabilities::default()
        }
    }
    
    async fn on_request(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, "/get-session") => {
                Ok(Some(self.handle_get_session(req, ctx).await?))
            },
            (HttpMethod::Post, "/sign-out") => {
                Ok(Some(self.handle_sign_out(req, ctx).await?))
            },
            (HttpMethod::Get, "/list-sessions") if self.config.enable_session_listing => {
                Ok(Some(self.handle_list_sessions(req, ctx).await?))
            },
            (HttpMethod::Post, "/revoke-session") if self.config.enable_session_revocation => {
                Ok(Some(self.handle_revoke_session(req, ctx).await?))
            },
            (HttpMethod::Post, "/revoke-sessions") if self.config.enable_session_revocation => {
                Ok(Some(self.handle_revoke_sessions(req, ctx).await?))
            },
            _ => Ok(None),
        }
    }
}

// Implementation methods outside the trait
impl SessionManagementPlugin {
    async fn handle_get_session(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        // Get current user and session
        let (user, session) = match self.get_current_user_and_session(req, ctx).await? {
            Some((user, session)) => (user, session),
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Unauthorized",
                    "message": "No valid session found"
                }))?);
            }
        };
        
        let response = GetSessionResponse { session, user };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn handle_sign_out(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        // Get current session
        let (_user, current_session) = match self.get_current_user_and_session(req, ctx).await? {
            Some((user, session)) => (user, session),
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Unauthorized",
                    "message": "No valid session found"
                }))?);
            }
        };
        
        // Delete the current session
        ctx.database.delete_session(&current_session.token).await?;
        let _ = ctx.emit_session_deleted(&current_session.token).await;
        
        let response = SignOutResponse { success: true };
        // Clear session cookie
        let clear_cookie_header = self.create_clear_session_cookie(ctx);
        
        Ok(AuthResponse::json(200, &response)?
            .with_header("Set-Cookie", clear_cookie_header))
    }
    
    fn create_clear_session_cookie(&self, ctx: &AuthContext) -> String {
        let session_config = &ctx.config.session;
        let secure = if session_config.cookie_secure { "; Secure" } else { "" };
        let http_only = if session_config.cookie_http_only { "; HttpOnly" } else { "" };
        let same_site = match session_config.cookie_same_site {
            crate::core::config::SameSite::Strict => "; SameSite=Strict",
            crate::core::config::SameSite::Lax => "; SameSite=Lax", 
            crate::core::config::SameSite::None => "; SameSite=None",
        };
        
        format!("{}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT{}{}{}",
                session_config.cookie_name,
                secure,
                http_only,
                same_site)
    }
    
    async fn handle_list_sessions(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        // Get current user
        let (user, _current_session) = match self.get_current_user_and_session(req, ctx).await? {
            Some((user, session)) => (user, session),
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Unauthorized",
                    "message": "No valid session found"
                }))?);
            }
        };
        
        // Get all user sessions from database
        let sessions = self.get_user_sessions(&user.id, ctx).await?;
        
        // Return sessions as an array directly (matching OpenAPI spec)
        Ok(AuthResponse::json(200, &sessions)?)
    }
    
    async fn handle_revoke_session(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        // Get current user to ensure they're authenticated
        let (user, _current_session) = match self.get_current_user_and_session(req, ctx).await? {
            Some((user, session)) => (user, session),
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Unauthorized",
                    "message": "No valid session found"
                }))?);
            }
        };
        
        let revoke_req: RevokeSessionRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Get the session token to revoke
        let session_token = &revoke_req.token;
        
        // Verify the session belongs to the current user before revoking
        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
        if let Some(session_to_revoke) = session_manager.get_session(session_token).await? {
            if session_to_revoke.user_id != user.id {
                return Ok(AuthResponse::json(403, &serde_json::json!({
                    "error": "Forbidden",
                    "message": "Cannot revoke session that belongs to another user"
                }))?);
            }
        }
        
        // Revoke the session
        ctx.database.delete_session(session_token).await?;
        let _ = ctx.emit_session_deleted(session_token).await;
        
        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn handle_revoke_sessions(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        // Get current user to ensure they're authenticated
        let (user, _current_session) = match self.get_current_user_and_session(req, ctx).await? {
            Some((user, session)) => (user, session),
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Unauthorized",
                    "message": "No valid session found"
                }))?);
            }
        };
        
        // Revoke all sessions for the user
        let sessions = ctx.database.get_user_sessions(&user.id).await?;
        ctx.database.delete_user_sessions(&user.id).await?;
        for session in sessions {
            let _ = ctx.emit_session_deleted(&session.token).await;
        }
        
        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    #[allow(dead_code)]
    async fn handle_revoke_other_sessions(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        // Get current user and session
        let (user, current_session) = match self.get_current_user_and_session(req, ctx).await? {
            Some((user, session)) => (user, session),
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Unauthorized",
                    "message": "No valid session found"
                }))?);
            }
        };
        
        // Get all sessions for the user
        let all_sessions = self.get_user_sessions(&user.id, ctx).await?;
        
        // Revoke all sessions except the current one
        for session in all_sessions {
            if session.token != current_session.token {
                ctx.database.delete_session(&session.token).await?;
                let _ = ctx.emit_session_deleted(&session.token).await;
            }
        }
        
        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn get_current_user_and_session(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<(User, Session)>> {
        // Extract session token from Authorization header
        let token = if let Some(auth_header) = req.headers.get("authorization") {
            if auth_header.starts_with("Bearer ") {
                Some(&auth_header[7..])
            } else {
                None
            }
        } else {
            None
        };
        
        if let Some(token) = token {
            let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
            if let Some(session) = session_manager.get_session(token).await? {
                if let Some(user) = ctx.database.get_user_by_id(&session.user_id).await? {
                    return Ok(Some((user, session)));
                }
            }
        }
        
        Ok(None)
    }
    
    async fn get_user_sessions(&self, user_id: &str, ctx: &AuthContext) -> AuthResult<Vec<Session>> {
        ctx.database.get_user_sessions(user_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::AuthConfig;
    use crate::adapters::{MemoryDatabaseAdapter, DatabaseAdapter};
    use crate::types::{CreateUser, CreateSession};
    use chrono::{Utc, Duration};
    use std::collections::HashMap;
    use std::sync::Arc;
    
    async fn create_test_context_with_user() -> (AuthContext, User, Session) {
        let config = Arc::new(AuthConfig::new("test-secret-key-at-least-32-chars-long"));
        let database = Arc::new(MemoryDatabaseAdapter::new());
        let ctx = AuthContext::new(config.clone(), database.clone());
        
        // Create test user
        let create_user = CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User");
        let user = database.create_user(create_user).await.unwrap();
        
        // Create test session
        let create_session = CreateSession {
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        };
        let session = database.create_session(create_session).await.unwrap();
        
        (ctx, user, session)
    }
    
    fn create_auth_request(method: HttpMethod, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> AuthRequest {
        let mut headers = HashMap::new();
        if let Some(token) = token {
            headers.insert("authorization".to_string(), format!("Bearer {}", token));
        }
        
        AuthRequest {
            method,
            path: path.to_string(),
            headers,
            body,
            query: HashMap::new(),
        }
    }
    
    #[tokio::test]
    async fn test_get_session_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;
        
        let req = create_auth_request(HttpMethod::Get, "/get-session", Some(&session.token), None);
        let response = plugin.handle_get_session(&req, &ctx).await.unwrap();
        
        assert_eq!(response.status, 200);
        
        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: GetSessionResponse = serde_json::from_str(&body_str).unwrap();
        assert_eq!(response_data.session.token, session.token);
        assert_eq!(response_data.user.email, Some("test@example.com".to_string()));
    }
    
    #[tokio::test]
    async fn test_get_session_unauthorized() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;
        
        let req = create_auth_request(HttpMethod::Get, "/get-session", None, None);
        let response = plugin.handle_get_session(&req, &ctx).await.unwrap();
        
        assert_eq!(response.status, 401);
    }
    
    #[tokio::test]
    async fn test_sign_out_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;
        
        let req = create_auth_request(HttpMethod::Post, "/sign-out", Some(&session.token), Some(b"{}".to_vec()));
        let response = plugin.handle_sign_out(&req, &ctx).await.unwrap();
        
        assert_eq!(response.status, 200);
        
        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: SignOutResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.success);
        
        // Verify session was deleted
        let session_check = ctx.database.get_session(&session.token).await.unwrap();
        assert!(session_check.is_none());
    }
    
    #[tokio::test]
    async fn test_list_sessions_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, user, session) = create_test_context_with_user().await;
        
        // Create additional session for the same user
        let create_session2 = CreateSession {
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("another-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        };
        ctx.database.create_session(create_session2).await.unwrap();
        
        let req = create_auth_request(HttpMethod::Get, "/list-sessions", Some(&session.token), None);
        let response = plugin.handle_list_sessions(&req, &ctx).await.unwrap();
        
        assert_eq!(response.status, 200);
        
        let body_str = String::from_utf8(response.body).unwrap();
        let sessions: Vec<Session> = serde_json::from_str(&body_str).unwrap();
        assert_eq!(sessions.len(), 2);
    }
    
    #[tokio::test]
    async fn test_revoke_session_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, user, session) = create_test_context_with_user().await;
        
        // Create another session to revoke
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
        let req = create_auth_request(
            HttpMethod::Post, 
            "/revoke-session", 
            Some(&session.token), 
            Some(body.to_string().into_bytes())
        );
        
        let response = plugin.handle_revoke_session(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        
        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);
        
        // Verify session2 was deleted but session1 still exists
        let session2_check = ctx.database.get_session(&session2.token).await.unwrap();
        assert!(session2_check.is_none());
        
        let session1_check = ctx.database.get_session(&session.token).await.unwrap();
        assert!(session1_check.is_some());
    }
    
    #[tokio::test]
    async fn test_revoke_session_forbidden_different_user() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user1, session1) = create_test_context_with_user().await;
        
        // Create another user and session
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
        
        // Try to revoke user2's session using user1's session
        let body = serde_json::json!({ "token": session2.token });
        let req = create_auth_request(
            HttpMethod::Post, 
            "/revoke-session", 
            Some(&session1.token), 
            Some(body.to_string().into_bytes())
        );
        
        let response = plugin.handle_revoke_session(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 403);
    }
    
    #[tokio::test]
    async fn test_revoke_sessions_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, user, session1) = create_test_context_with_user().await;
        
        // Create additional sessions for the same user
        let create_session2 = CreateSession {
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("another-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        };
        ctx.database.create_session(create_session2).await.unwrap();
        
        let req = create_auth_request(HttpMethod::Post, "/revoke-sessions", Some(&session1.token), Some(b"{}".to_vec()));
        let response = plugin.handle_revoke_sessions(&req, &ctx).await.unwrap();
        
        assert_eq!(response.status, 200);
        
        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);
        
        // Verify all sessions for the user were deleted
        let user_sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert_eq!(user_sessions.len(), 0);
    }
    
    #[tokio::test]
    async fn test_plugin_routes() {
        let plugin = SessionManagementPlugin::new();
        let routes = plugin.routes();
        
        assert_eq!(routes.len(), 5);
        assert!(routes.iter().any(|r| r.path == "/get-session" && r.method == HttpMethod::Get));
        assert!(routes.iter().any(|r| r.path == "/sign-out" && r.method == HttpMethod::Post));
        assert!(routes.iter().any(|r| r.path == "/list-sessions" && r.method == HttpMethod::Get));
        assert!(routes.iter().any(|r| r.path == "/revoke-session" && r.method == HttpMethod::Post));
        assert!(routes.iter().any(|r| r.path == "/revoke-sessions" && r.method == HttpMethod::Post));
    }
    
    #[tokio::test]
    async fn test_plugin_on_request_routing() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;
        
        // Test valid route
        let req = create_auth_request(HttpMethod::Get, "/get-session", Some(&session.token), None);
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_some());
        assert_eq!(response.unwrap().status, 200);
        
        // Test invalid route
        let req = create_auth_request(HttpMethod::Get, "/invalid-route", Some(&session.token), None);
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
        
        let (ctx, _user, session) = create_test_context_with_user().await;
        
        // Test that disabled features return None
        let req = create_auth_request(HttpMethod::Get, "/list-sessions", Some(&session.token), None);
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_none());
        
        let req = create_auth_request(HttpMethod::Post, "/revoke-session", Some(&session.token), Some(b"{}".to_vec()));
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_none());
    }
}
