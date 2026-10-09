//! Multiple signed device sessions with explicit active-session selection.

use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, FieldMap,
    FieldValue,
    session::NativeSessionData,
    utils::cookie_utils::{
        create_clear_cookie, create_cookie, get_cookie, sign_cookie_value, verify_cookie_value,
    },
};
use chrono::Utc;

use super::{
    helpers::delete_session_cookies,
    one_time_token::{find_session, session_required, session_token_body, token_body},
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
        get "/multi-session/list-device-sessions" => handle_list, "listDeviceSessions", require_headers = true;
        post "/multi-session/set-active" => handle_set_active, "setActiveSession", body = session_token_body, require_headers = true;
        post "/multi-session/revoke" => handle_revoke, "revokeDeviceSession", body = session_token_body, require_headers = true;
    }
    extra {
        async fn after_request(&self, req: &AuthRequest, response: &mut AuthResponse, ctx: &AuthContext<S>) -> AuthResult<()> {
            better_auth_core::observability::instrumentation::with_endpoint_hook(&ctx.config, req, "after", "plugin:multi-session", self.remember_session(req, response, ctx)).await?;
            if req.path() == "/sign-out" {
                better_auth_core::observability::instrumentation::with_endpoint_hook(&ctx.config, req, "after", "plugin:multi-session", async {
                let mut tokens = Vec::new();
                for (name, token) in device_cookies(req, &ctx.config) {
                    better_auth_core::utils::cookie_utils::remove_set_cookie_entries(req, Some(&mut response.headers), &name)?;
                    response.headers.append("Set-Cookie", create_clear_cookie(&name, &ctx.config)?);
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
        let sessions = list_sessions(req, ctx, true).await?;
        let mut users: Vec<FieldValue> = Vec::new();
        let mut output = Vec::new();
        for mut data in sessions {
            let id = data.user_field("id");
            if users.iter().any(|seen| seen.strict_equals(id)) {
                continue;
            }
            users.push(id.clone());
            data.session.filter_returned_fields(&ctx.config.session)?;
            data.user = data.public_user(&ctx.config.user)?;
            output.push(FieldValue::from(FieldMap::from(data)));
        }
        Ok(AuthResponse::native(None, output.into()))
    }

    async fn handle_set_active<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let token = token_body(req, "sessionToken")?;
        let name = cookie_name(&token, &ctx.config);
        let token = signed_device_token(req, &name, &ctx.config).ok_or_else(invalid_session)?;
        let session = match find_session(ctx, &token.into()).await? {
            Some(data) if !data.session.expires_at.is_before(Utc::now())? => Some(data),
            _ => None,
        };
        let Some(mut data) = session else {
            better_auth_core::utils::cookie_utils::remove_set_cookie_entries(req, None, &name)?;
            req.append_response_header("Set-Cookie", create_clear_cookie(&name, &ctx.config)?)?;
            return Err(invalid_session());
        };
        ctx.session_manager()
            .set_native_session_cookie(req, data.clone(), None)
            .await?;
        data.session.filter_returned_fields(&ctx.config.session)?;
        data.user = data.public_user(&ctx.config.user)?;
        Ok(AuthResponse::native(None, FieldMap::from(data).into()))
    }

    async fn handle_revoke<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let token = token_body(req, "sessionToken")?;
        let current = ctx
            .require_native_session(req)
            .await
            .map_err(session_required)?;
        let name = cookie_name(&token, &ctx.config);
        let token = signed_device_token(req, &name, &ctx.config).ok_or_else(invalid_session)?;
        ctx.database.delete_session(&token).await?;
        better_auth_core::utils::cookie_utils::remove_set_cookie_entries(req, None, &name)?;
        req.append_response_header("Set-Cookie", create_clear_cookie(&name, &ctx.config)?)?;
        let response = AuthResponse::json(None, &serde_json::json!({ "status": true }))?;
        if !current
            .session
            .token
            .field_value()
            .strict_equals(&token.into())
        {
            return Ok(response);
        }
        if let Some(data) = list_sessions(req, ctx, false).await?.into_iter().next() {
            ctx.session_manager()
                .set_native_session_cookie(req, data, None)
                .await?;
        } else {
            delete_session_cookies(req, &ctx.config, false, None)?;
        }
        Ok(response)
    }

    async fn remember_session<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        if !response.headers.contains_key("set-cookie") {
            return Ok(());
        }
        let cookie = ctx.config.auth_cookie("session_token", Default::default());
        let adds_session = response
            .headers
            .get_all("set-cookie")
            .any(|value| value.contains(&cookie.name));
        let Some(data) = req.new_session()? else {
            return Ok(());
        };
        let token = data.session.token.typed()?;
        let name = cookie_name(token, &ctx.config);
        if get_cookie(req, &name).is_some_and(|value| !value.is_empty())
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
            if previous_token.is_empty() {
                continue;
            }
            let previous_id = find_session(ctx, &previous_token.as_str().into())
                .await?
                .map(|previous| previous.user_field("id").clone())
                .unwrap_or_default();
            if previous_id.strict_equals(data.user_field("id")) {
                response
                    .headers
                    .append("Set-Cookie", create_clear_cookie(&name, &ctx.config)?);
                tokens_to_delete.push(previous_token);
            }
        }
        if !tokens_to_delete.is_empty() {
            ctx.database.delete_sessions(&tokens_to_delete).await?;
        }
        if multi_count - tokens_to_delete.len() + usize::from(adds_session)
            > self.config.maximum_sessions
        {
            return Ok(());
        }
        response.headers.append(
            "Set-Cookie",
            create_cookie(
                &name,
                &sign_cookie_value(token, ctx.config.signing_secret()),
                ctx.config.session.expires_in().as_seconds_f64(),
                &ctx.config,
            )?,
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
    get_cookie(req, name)
        .and_then(|value| verify_cookie_value(&value, config.signing_secret()))
        .filter(|token| !token.is_empty())
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
    only_active: bool,
) -> AuthResult<Vec<NativeSessionData>> {
    let tokens = device_cookies(req, &ctx.config)
        .into_iter()
        .map(|(_, token)| token)
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return Ok(Vec::new());
    }
    let mut sessions = Vec::new();
    let mut missing_user = false;
    for (session, snapshot) in ctx
        .database
        .get_session_snapshots(&tokens, only_active)
        .await?
    {
        let data = if let Some(data) = snapshot {
            NativeSessionData::from(data)
        } else {
            let user = ctx.database.get_user_by_id_field(&session.user_id).await?;
            NativeSessionData {
                session,
                user: user
                    .map(FieldMap::from)
                    .map(FieldValue::from)
                    .unwrap_or(FieldValue::Null),
            }
        };
        if data.user.is_truthy() {
            if data.session.expires_at.is_after(Utc::now())? {
                sessions.push(data);
            }
        } else {
            missing_user = true;
        }
    }
    if missing_user {
        sessions.clear();
    }
    Ok(sessions)
}

#[cfg(test)]
mod tests;
