use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use better_auth_core::config::AuthConfig;
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::wire::SessionView;
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};

use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};

use super::StatusResponse;
use super::helpers::admin_plugin_enabled;
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
#[derive(Debug, Clone, Deserialize)]
struct RevokeSessionRequest {
    token: String,
}

fn revoke_session_body(
    req: &AuthRequest,
) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let (typed, projection) =
        super::json_body::string_input::<RevokeSessionRequest>(req, &[("token", true)])?;
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        Some(projection),
        typed,
    ))
}

#[derive(Debug, Serialize)]
struct GetSessionResponse<S: Serialize, U: Serialize> {
    session: S,
    user: U,
    #[serde(rename = "needsRefresh", skip_serializing_if = "Option::is_none")]
    needs_refresh: Option<bool>,
}

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for SessionManagementPlugin {
    fn name(&self) -> &'static str {
        "session-management"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/get-session", "getSession")
                .query_validator(better_auth_core::query::session_query),
            // Upstream declares `/get-session` as `method: ["GET", "POST"]`;
            // the POST form requires `session.defer_session_refresh`.
            AuthRoute::post("/get-session", "getSession")
                .query_validator(better_auth_core::query::session_query),
            AuthRoute::post("/sign-out", "signOut").body_validator(super::json_body::sign_out_body),
            AuthRoute::post("/update-session", "updateSession")
                .body_validator(better_auth_core::endpoint_input::record_body),
            AuthRoute::get("/list-sessions", "listUserSessions"),
            AuthRoute::post("/revoke-session", "revokeSession").body_validator(revoke_session_body),
            AuthRoute::post("/revoke-sessions", "revokeSessions"),
            AuthRoute::post("/revoke-other-sessions", "revokeOtherSessions"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.path() == "/get-session"
            && let Some(custom) = ctx
                .extensions
                .get::<super::custom_session::CustomSessionPlugin<S>>()
        {
            return custom.on_request(req, ctx).await;
        }
        if req.path() == "/get-session" {
            req.append_response_header("Cache-Control", "no-store".into())?;
            req.append_response_header("Pragma", "no-cache".into())?;
        }
        match (req.method(), req.path()) {
            (HttpMethod::Get, "/get-session") => Ok(Some(self.handle_get_session(req, ctx).await?)),
            (HttpMethod::Post, "/get-session") => {
                if !ctx.config.session.defer_session_refresh {
                    return Err(AuthError::method_not_allowed(
                        "POST method requires deferSessionRefresh to be enabled in session config",
                    ));
                }
                Ok(Some(self.handle_get_session(req, ctx).await?))
            }
            (HttpMethod::Post, "/update-session") => {
                Ok(Some(super::session_update::handle(req, ctx).await?))
            }
            (HttpMethod::Post, "/sign-out") => {
                Ok(Some(super::oauth::handle_sign_out(req, ctx).await?))
            }
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

pub(crate) async fn list_sessions_core(
    user_id: impl AsRef<str>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<SessionView>> {
    ctx.session_manager().list_user_session_views(user_id).await
}

pub(crate) async fn revoke_session_core(
    user: &impl AuthUser,
    token: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
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
    user_id: impl AsRef<str>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    ctx.database.delete_user_sessions(user_id.as_ref()).await?;
    Ok(StatusResponse { status: true })
}

pub(crate) async fn revoke_other_sessions_core(
    user_id: impl AsRef<str>,
    current_session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let all_sessions = ctx.session_manager().list_user_sessions(user_id).await?;
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
    pub(crate) async fn handle_get_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let resolved = ctx
            .session_manager()
            .resolve(req, better_auth_core::session::SessionRead::Cached)
            .await;
        let resolved = match resolved {
            Ok(value) => value,
            Err(error) if error.status_code() < 500 => return Err(error),
            Err(error) => {
                better_auth_core::observability::logger::current().error(
                    "Failed to read session",
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                );
                return Err(AuthError::Upstream {
                    status: 500,
                    code: "FAILED_TO_GET_SESSION",
                    message: "Failed to get session",
                });
            }
        };
        let mut response = match resolved.data {
            Some(data) => AuthResponse::json(
                200,
                &GetSessionResponse {
                    session: data.session,
                    user: data.user,
                    needs_refresh: resolved.needs_refresh,
                },
            )?,
            None => AuthResponse::json(200, &serde_json::Value::Null)?,
        };
        let _ = response.headers.insert("Cache-Control", "no-store");
        let _ = response.headers.insert("Pragma", "no-cache");
        for (name, value) in req.take_response_headers()? {
            response.headers.append(name, value);
        }
        Ok(response)
    }

    async fn handle_list_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx.require_authoritative_session(req).await?;
        let mut sessions = list_sessions_core(user.id().typed()?, ctx).await?;
        if admin_plugin_enabled(ctx) {
            sessions.retain(|session| session.impersonated_by.is_none());
        }
        Ok(AuthResponse::json(200, &sessions)?)
    }

    async fn handle_revoke_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx.require_authoritative_session(req).await?;

        let revoke_req: RevokeSessionRequest = match req.validated_body::<RevokeSessionRequest>() {
            Some(body) => body.clone(),
            None => super::json_body::string_input(req, &[("token", true)])?.0,
        };

        let response = revoke_session_core(&user, &revoke_req.token, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_revoke_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx.require_authoritative_session(req).await?;
        let response = revoke_sessions_core(user.id().typed()?, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_revoke_other_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, current_session) = ctx.require_authoritative_session(req).await?;
        let response =
            revoke_other_sessions_core(user.id().typed()?, &current_session, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }
}

#[cfg(test)]
fn related_cookie_name(config: &AuthConfig, suffix: &str) -> String {
    better_auth_core::utils::cookie_utils::related_cookie_name(config, suffix)
}

/// Clear the local session before a provider-specific logout redirect is applied.
pub(crate) async fn handle_sign_out(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    if let Some(token) = ctx.session_manager().extract_session_token(req)
        && let Err(error) = ctx.database.delete_session(&token).await
    {
        // Upstream completes browser logout even when deleting the stored session fails.
        better_auth_core::observability::logger::current().error(
            "Failed to delete session during sign-out",
            &[better_auth_core::observability::LogArgument::Error(&error)],
        );
    }
    ctx.session_manager().clear_cookies(req)?;
    let mut response = AuthResponse::json(200, &SuccessResponse { success: true })?;
    for (name, value) in req.take_response_headers()? {
        response.headers.append(name, value);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers;
    use better_auth_core::config::AccountConfig;
    use better_auth_core::wire::SessionView;
    use better_auth_core::{CreateSession, CreateUser};
    use chrono::{Duration, Utc};

    #[tokio::test]
    async fn invalid_sign_out_body_preserves_session_without_oauth_plugin() {
        let (ctx, _, session) = test_helpers::create_test_context_with_user(
            CreateUser::new().with_email("logout-body@example.com"),
            Duration::hours(24),
        )
        .await;
        let plugin = SessionManagementPlugin::new();
        for body in [
            serde_json::json!({"disableRedirect": null}),
            serde_json::json!({"state": 5}),
        ] {
            let req = test_helpers::create_auth_json_request_no_query(
                HttpMethod::Post,
                "/sign-out",
                Some(&session.token),
                Some(body),
            );
            let response = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
            assert_eq!(response.status, 400);
            let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body["code"], "VALIDATION_ERROR");
            assert!(
                ctx.database
                    .get_session(&session.token)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[tokio::test]
    async fn storage_failure_returns_500_and_disables_http_caching() {
        use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
        use better_auth_seaorm::{Database, SeaOrmStore};
        use std::sync::Arc;

        let connection = Database::connect("sqlite::memory:").await.unwrap();
        let config = Arc::new(test_helpers::create_test_config());
        let store = Arc::new(SeaOrmStore::<BundledSchema>::new(
            config.clone(),
            connection.clone(),
        ));
        let ctx = AuthContext::new(config, store);
        connection.close().await.unwrap();
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/get-session",
            Some("unavailable-store-token"),
            None,
        );
        let error = SessionManagementPlugin::new()
            .on_request(&req, &ctx)
            .await
            .unwrap_err();
        let mut response = error.to_auth_response();
        ctx.session_manager()
            .finish_response(&req, &mut response)
            .unwrap();
        assert_eq!(response.status, 500);
        assert_eq!(
            response.headers.get("Cache-Control").map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            response.headers.get("Pragma").map(String::as_str),
            Some("no-cache")
        );
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["code"], "FAILED_TO_GET_SESSION");
        assert_eq!(body["message"], "Failed to get session");
    }

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
        let response = handle_sign_out(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: SuccessResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.success);

        let session_check = ctx.database.get_session(&session.token).await.unwrap();
        assert!(session_check.is_none());
    }

    #[tokio::test]
    async fn test_sign_out_clears_account_cookie_when_enabled() {
        let config = test_helpers::create_test_config().account(AccountConfig {
            store_account_cookie: Some(true),
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
        let response = handle_sign_out(&req, &ctx).await.unwrap();

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
        let response = handle_sign_out(&req, &ctx).await.unwrap();

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
            additional_fields: Default::default(),
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
        let sessions: Vec<SessionView> = serde_json::from_str(&body_str).unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn test_list_sessions_filters_impersonated_sessions_when_admin_plugin_is_enabled() {
        let plugin = SessionManagementPlugin::new();
        let (mut ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;
        ctx.set_metadata("admin.enabled", serde_json::Value::Bool(true));

        let direct_session = CreateSession {
            additional_fields: Default::default(),
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("another-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        };
        ctx.database.create_session(direct_session).await.unwrap();

        let impersonated_session = CreateSession {
            additional_fields: Default::default(),
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("10.0.0.5".to_string()),
            user_agent: Some("impersonated-agent".to_string()),
            impersonated_by: Some("admin-user".to_string()),
            active_organization_id: None,
        };
        let impersonated = ctx
            .database
            .create_session(impersonated_session)
            .await
            .unwrap();

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/list-sessions",
            Some(&session.token),
            None,
        );
        let response = plugin.handle_list_sessions(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let sessions: Vec<SessionView> = serde_json::from_str(&body_str).unwrap();
        assert_eq!(sessions.len(), 2);
        assert!(
            sessions
                .iter()
                .all(|session| session.token != impersonated.token),
            "impersonated sessions should not be returned from /list-sessions"
        );
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
            additional_fields: Default::default(),
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
            additional_fields: Default::default(),
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
            additional_fields: Default::default(),
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

        let user_sessions = ctx
            .database
            .get_user_sessions(user.id.typed().unwrap())
            .await
            .unwrap();
        assert_eq!(user_sessions.len(), 0);
    }

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
    #[tokio::test]
    async fn test_plugin_routes() {
        let plugin = SessionManagementPlugin::new();
        let routes = AuthPlugin::<
            better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema,
        >::routes(&plugin);

        assert_eq!(routes.len(), 8);
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/get-session" && r.method == HttpMethod::Get)
        );
        // Upstream serves `/get-session` on both methods.
        assert!(
            routes
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

        // POST /get-session is served, but rejected with 405 until
        // `session.defer_session_refresh` is enabled.
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/get-session",
            Some(&session.token),
            Some(b"{}".to_vec()),
        );
        let err = plugin.on_request(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 405);

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
