use async_trait::async_trait;
use serde::Deserialize;

#[cfg(test)]
use better_auth_core::config::AuthConfig;
use better_auth_core::session::NativeSessionData;
use better_auth_core::store::JoinValue;
use better_auth_core::wire::SessionView;
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};

use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, FieldMap, FieldValue, HttpMethod};

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

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for SessionManagementPlugin {
    fn name(&self) -> &'static str {
        "session-management"
    }

    fn telemetry_plugin_id(&self) -> Option<&'static str> {
        None
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/get-session", "getSession")
                .require_headers(true)
                .query_validator(better_auth_core::query::session_query),
            // Upstream declares `/get-session` as `method: ["GET", "POST"]`;
            // the POST form requires `session.defer_session_refresh`.
            AuthRoute::post("/get-session", "getSession")
                .require_headers(true)
                .query_validator(better_auth_core::query::session_query),
            AuthRoute::post("/sign-out", "signOut")
                .require_headers(true)
                .body_validator(super::json_body::sign_out_body),
            AuthRoute::post("/update-session", "updateSession")
                .body_validator(better_auth_core::endpoint_input::record_body),
            AuthRoute::get("/list-sessions", "listUserSessions").require_headers(true),
            AuthRoute::post("/revoke-session", "revokeSession")
                .require_headers(true)
                .body_validator(revoke_session_body),
            AuthRoute::post("/revoke-sessions", "revokeSessions").require_headers(true),
            AuthRoute::post("/revoke-other-sessions", "revokeOtherSessions").require_headers(true),
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

fn session_user_id(data: &NativeSessionData) -> AuthResult<FieldValue> {
    let nullish = match &data.user {
        FieldValue::Null => "null",
        FieldValue::Undefined => "undefined",
        _ => return data.user_property("id"),
    };
    Err(AuthError::TypeError(format!(
        "{nullish} is not an object (evaluating 'ctx.context.session.user.id')"
    )))
}

pub(crate) async fn list_sessions_core(
    user_id: &FieldValue,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<SessionView>> {
    let mut sessions = Vec::new();
    for (session, cached) in ctx
        .database
        .get_user_session_snapshots_value(user_id, true)
        .await?
    {
        let mut session = if let Some(mut cached) = cached {
            cached.filter_returned_fields(&ctx.config.session)?;
            cached
        } else {
            session
        };
        if !session.expires_at.is_after(chrono::Utc::now())? {
            continue;
        }
        session.filter_returned_fields(&ctx.config.session)?;
        sessions.push(session);
    }
    Ok(sessions)
}

pub(crate) async fn revoke_session_core(
    data: &NativeSessionData,
    token: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let target = match ctx.database.get_session_snapshot(token).await? {
        Some((_, Some(snapshot))) => match snapshot.user {
            JoinValue::One(None) => None,
            _ => Some(snapshot.session),
        },
        Some((session, None)) => ctx
            .database
            .get_user_by_id_field(&session.user_id)
            .await?
            .map(|_| session),
        None => None,
    };
    let target_user = match target {
        Some(mut session) => {
            session.filter_returned_fields(&ctx.config.session)?;
            session.user_id.field_value()
        }
        None => FieldValue::Undefined,
    };
    if target_user.strict_equals(&session_user_id(data)?) {
        ctx.database
            .delete_session(token)
            .await
            .map_err(revocation_error)?;
    }
    Ok(StatusResponse { status: true })
}

pub(crate) async fn revoke_sessions_core(
    data: &NativeSessionData,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let result = async {
        ctx.database
            .delete_user_sessions_by_user_value(&session_user_id(data)?)
            .await
    }
    .await;
    result.map_err(revocation_error)?;
    Ok(StatusResponse { status: true })
}

pub(crate) async fn revoke_other_sessions_core(
    data: &NativeSessionData,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    if !data.user.is_truthy() {
        return Err(AuthError::Unauthenticated);
    }
    let mut tokens = Vec::new();
    for (session, cached) in ctx
        .database
        .get_user_session_snapshots_value(&session_user_id(data)?, false)
        .await?
    {
        let session = if let Some(mut cached) = cached {
            cached.filter_returned_fields(&ctx.config.session)?;
            cached
        } else {
            session
        };
        if session.expires_at.is_after(chrono::Utc::now())?
            && !session
                .token
                .field_value()
                .strict_equals(&data.session.token.field_value())
        {
            tokens.push(session.token.field_value());
        }
    }
    let results = futures_util::future::join_all(
        tokens
            .iter()
            .map(|token| ctx.database.delete_session_by_token_value(token)),
    )
    .await;
    for result in results {
        result?;
    }
    Ok(StatusResponse { status: true })
}

fn revocation_error(error: AuthError) -> AuthError {
    better_auth_core::observability::logger::current().error(
        "Failed to revoke Sessions",
        &[better_auth_core::observability::LogArgument::Error(&error)],
    );
    AuthError::Upstream {
        status: 500,
        code: "INTERNAL_SERVER_ERROR",
        message: "Internal Server Error",
    }
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
            .resolve_native_for_endpoint(req, better_auth_core::session::SessionRead::Cached)
            .await?;
        let mut response = match resolved.data {
            Some(data) => {
                let mut fields = FieldMap::from(data);
                if let Some(needs_refresh) = resolved.needs_refresh {
                    let _ = fields.insert("needsRefresh".into(), needs_refresh.into());
                }
                AuthResponse::native(None, fields.into())
            }
            None => AuthResponse::native(None, FieldValue::Null),
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
        let data = ctx.require_native_session(req).await?;
        if !super::helpers::session_is_fresh(&data.session, &ctx.config)? {
            return Err(AuthError::Upstream {
                status: 403,
                code: "SESSION_NOT_FRESH",
                message: "Session is not fresh",
            });
        }
        let result = async { list_sessions_core(&session_user_id(&data)?, ctx).await }.await;
        let mut sessions = result.map_err(|error| {
            better_auth_core::observability::logger::current().error(
                "Failed to list Sessions",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
            AuthError::from(AuthResponse::new(500))
        })?;
        if admin_plugin_enabled(ctx) {
            sessions.retain(|session| !session.impersonated_by.field_value().is_truthy());
        }
        Ok(AuthResponse::native(
            None,
            sessions
                .into_iter()
                .map(|session| FieldMap::from(session).into())
                .collect::<Vec<FieldValue>>()
                .into(),
        ))
    }

    async fn handle_revoke_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let data = ctx.require_authoritative_native_session(req).await?;

        let revoke_req: RevokeSessionRequest = match req.validated_body::<RevokeSessionRequest>() {
            Some(body) => body.clone(),
            None => super::json_body::string_input(req, &[("token", true)])?.0,
        };

        let response = revoke_session_core(&data, &revoke_req.token, ctx).await?;
        AuthResponse::json(None, &response)
    }

    async fn handle_revoke_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let data = ctx.require_authoritative_native_session(req).await?;
        let response = revoke_sessions_core(&data, ctx).await?;
        AuthResponse::json(None, &response)
    }

    async fn handle_revoke_other_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let data = ctx.require_authoritative_native_session(req).await?;
        let response = revoke_other_sessions_core(&data, ctx).await?;
        AuthResponse::json(None, &response)
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
    let mut response = AuthResponse::json(None, &SuccessResponse { success: true })?;
    for (name, value) in req.take_response_headers()? {
        response.headers.append(name, value);
    }
    Ok(response)
}

#[cfg(test)]
mod native_contract_tests;
#[cfg(test)]
mod native_query_tests;
#[cfg(test)]
mod tests;
