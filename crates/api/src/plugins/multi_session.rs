//! Multiple signed device sessions with explicit active-session selection.

use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema,
    utils::cookie_utils::{
        create_clear_cookie, create_cookie, get_cookie, sign_cookie_value, verify_cookie_value,
    },
    wire::{SessionView, UserView},
};
use chrono::Utc;

use super::{
    helpers::delete_session_cookie_headers,
    one_time_token::{find_session, response_session_token, session_required, token_body},
};

/// Device session configuration.
#[derive(better_auth_core::PluginConfig)]
#[plugin(name = "MultiSessionPlugin")]
pub struct MultiSessionConfig {
    /// Maximum remembered accounts in one browser.
    #[config(default = 5)]
    pub maximum_sessions: usize,
}

/// Keep one signed device cookie for each remembered account.
pub struct MultiSessionPlugin {
    config: MultiSessionConfig,
}

better_auth_core::impl_auth_plugin! {
    MultiSessionPlugin, "multi-session";
    routes {
        get "/multi-session/list-device-sessions" => handle_list, "listDeviceSessions";
        post "/multi-session/set-active" => handle_set_active, "setActiveSession";
        post "/multi-session/revoke" => handle_revoke, "revokeDeviceSession";
    }
    extra {
        async fn after_request(&self, req: &AuthRequest, response: &mut AuthResponse, ctx: &AuthContext<S>) -> AuthResult<()> {
            better_auth_core::observability::instrumentation::with_endpoint_hook(&ctx.config, req, "after", "plugin:multi-session", self.remember_session(req, response, ctx)).await?;
            if req.path() == "/sign-out" {
                better_auth_core::observability::instrumentation::with_endpoint_hook(&ctx.config, req, "after", "plugin:multi-session", async {
                let mut tokens = Vec::new();
                for (name, token) in device_cookies(req, &ctx.config) {
                    response.headers.append("Set-Cookie", create_clear_cookie(&name, &ctx.config));
                    tokens.push(token);
                }
                if !tokens.is_empty() {
                    ctx.database.delete_sessions(&tokens).await?;
                }
                Ok(()) }).await?;
            }
            Ok(())
        }
    }
}

impl MultiSessionPlugin {
    async fn handle_list<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let sessions = list_sessions(req, ctx).await?;
        let mut users = std::collections::HashSet::new();
        let sessions: Vec<_> = sessions
            .into_iter()
            .filter(|(_, user)| users.insert(user.id.clone()))
            .map(|(session, user)| serde_json::json!({ "session": session, "user": user }))
            .collect();
        Ok(AuthResponse::json(200, &sessions)?)
    }

    async fn handle_set_active<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let token = match token_body(req, "sessionToken") {
            Ok(token) => token,
            Err(response) => return Ok(response),
        };
        let name = cookie_name(&token, &ctx.config);
        let token = signed_device_token(req, &name, &ctx.config).ok_or_else(invalid_session)?;
        let session = find_session(ctx, &token).await?;
        let Some((session, user)) = session.filter(|(session, _)| session.expires_at >= Utc::now())
        else {
            req.append_response_header("Set-Cookie", create_clear_cookie(&name, &ctx.config))?;
            return Err(invalid_session());
        };
        let response = AuthResponse::json(
            200,
            &serde_json::json!({ "session": session, "user": user }),
        )?;
        ctx.session_manager()
            .set_session_cookie(
                req,
                better_auth_core::session::SessionData { session, user },
                None,
            )
            .await?;
        Ok(response)
    }

    async fn handle_revoke<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let token = match token_body(req, "sessionToken") {
            Ok(token) => token,
            Err(response) => return Ok(response),
        };
        let (_, current) = ctx.require_session(req).await.map_err(session_required)?;
        let name = cookie_name(&token, &ctx.config);
        let token = signed_device_token(req, &name, &ctx.config).ok_or_else(invalid_session)?;
        ctx.database.delete_session(&token).await?;
        let mut response = AuthResponse::json(200, &serde_json::json!({ "status": true }))?
            .with_header("Set-Cookie", create_clear_cookie(&name, &ctx.config));
        if token != current.token {
            return Ok(response);
        }
        if let Some((session, user)) = list_sessions(req, ctx).await?.into_iter().next() {
            ctx.session_manager()
                .set_session_cookie(
                    req,
                    better_auth_core::session::SessionData { session, user },
                    None,
                )
                .await?;
        } else {
            for cookie in delete_session_cookie_headers(req, &ctx.config) {
                response.headers.append("Set-Cookie", cookie);
            }
        }
        Ok(response)
    }

    async fn remember_session<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        let Some(token) = response_session_token(response, &ctx.config) else {
            return Ok(());
        };
        let Some((_, user)) = find_session(ctx, &token).await? else {
            return Ok(());
        };
        let name = cookie_name(&token, &ctx.config);
        if get_cookie(req, &name).is_some()
            || response
                .headers
                .get_all("set-cookie")
                .any(|value| value.split_once('=').is_some_and(|(key, _)| key == name))
        {
            return Ok(());
        }
        let multi_count = req
            .headers
            .get("cookie")
            .map(|header| {
                cookie::Cookie::split_parse(header)
                    .flatten()
                    .filter(|cookie| cookie.name().contains("_multi-"))
                    .map(|cookie| cookie.name().to_owned())
                    .collect::<std::collections::HashSet<_>>()
                    .len()
            })
            .unwrap_or_default();
        let mut tokens_to_delete = Vec::new();
        for (name, previous_token) in device_cookies(req, &ctx.config) {
            if find_session(ctx, &previous_token)
                .await?
                .is_some_and(|(_, previous)| previous.id == user.id)
            {
                response
                    .headers
                    .append("Set-Cookie", create_clear_cookie(&name, &ctx.config));
                tokens_to_delete.push(previous_token);
            }
        }
        if !tokens_to_delete.is_empty() {
            ctx.database.delete_sessions(&tokens_to_delete).await?;
        }
        if multi_count - tokens_to_delete.len() + 1 > self.config.maximum_sessions {
            return Ok(());
        }
        response.headers.append(
            "Set-Cookie",
            create_cookie(
                &name,
                &sign_cookie_value(&token, ctx.config.signing_secret()),
                ctx.config.session.expires_in.num_seconds(),
                &ctx.config,
            ),
        );
        Ok(())
    }
}

fn cookie_name(token: &str, config: &better_auth_core::AuthConfig) -> String {
    format!(
        "{}_multi-{}",
        config.auth_cookie("session_token", Default::default()).name,
        token.to_lowercase()
    )
}

fn invalid_session() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "INVALID_SESSION_TOKEN",
        message: "Invalid session token",
    }
}

fn signed_device_token(
    req: &AuthRequest,
    name: &str,
    config: &better_auth_core::AuthConfig,
) -> Option<String> {
    get_cookie(req, name).and_then(|value| verify_cookie_value(&value, config.signing_secret()))
}

fn device_cookies(
    req: &AuthRequest,
    config: &better_auth_core::AuthConfig,
) -> Vec<(String, String)> {
    let mut seen = std::collections::HashSet::new();
    req.headers
        .get("cookie")
        .map(|header| {
            cookie::Cookie::split_parse(header)
                .flatten()
                .filter(|cookie| cookie.name().contains("_multi-"))
                .filter(|cookie| seen.insert(cookie.name().to_owned()))
                .filter_map(|cookie| {
                    verify_cookie_value(cookie.value(), config.signing_secret())
                        .map(|token| (cookie.name().to_owned(), token))
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn list_sessions<S: AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<Vec<(SessionView, UserView)>> {
    let mut sessions = Vec::new();
    for (_, token) in device_cookies(req, &ctx.config) {
        if let Some(pair) = find_session(ctx, &token)
            .await?
            .filter(|(session, _)| session.expires_at > Utc::now())
        {
            sessions.push(pair);
        }
    }
    Ok(sessions)
}
