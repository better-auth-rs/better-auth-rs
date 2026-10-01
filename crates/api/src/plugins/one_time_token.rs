//! Single-use exchange of an existing session.

use std::{future::Future, pin::Pin, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, AuthSession,
    AuthVerification, CreateVerification,
    utils::cookie_utils::{create_session_cookie, verify_cookie_value},
    wire::{SessionView, UserView},
};
use chrono::{Duration, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Asynchronous transformation for a token stored in the verification table.
pub type TokenHasher =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = AuthResult<String>> + Send>> + Send + Sync>;

/// Storage representation shared by magic-link and one-time-token verifiers.
#[derive(Clone, Default)]
pub enum TokenStorage {
    /// Store the original token, matching the upstream default.
    #[default]
    Plain,
    /// Store the unpadded base64url SHA-256 digest.
    Hashed,
    /// Apply an application-provided asynchronous hash.
    Custom(TokenHasher),
}

impl TokenStorage {
    pub(crate) async fn encode(&self, token: &str) -> AuthResult<String> {
        match self {
            Self::Plain => Ok(token.to_owned()),
            Self::Hashed => Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))),
            Self::Custom(hash) => hash(token.to_owned()).await,
        }
    }
}

/// Custom generation receives the authenticated session and user.
pub type OneTimeTokenGenerator = Arc<
    dyn Fn(SessionView, UserView) -> Pin<Box<dyn Future<Output = AuthResult<String>> + Send>>
        + Send
        + Sync,
>;

/// Configuration for single-use session transfer.
#[derive(better_auth_core::PluginConfig)]
#[plugin(name = "OneTimeTokenPlugin")]
pub struct OneTimeTokenConfig {
    /// Token lifetime. Upstream `expiresIn` is expressed in minutes.
    #[config(default = Duration::minutes(3))]
    pub expires_in: Duration,
    /// Deny generation through the HTTP endpoint.
    #[config(default = false)]
    pub disable_client_request: bool,
    /// Return the session without setting its cookie.
    #[config(default = false)]
    pub disable_set_session_cookie: bool,
    /// Emit a `set-ott` header whenever a response sets a session.
    #[config(default = false)]
    pub set_ott_header_on_new_session: bool,
    /// Representation used for token lookup.
    #[config(default = TokenStorage::Plain)]
    pub store_token: TokenStorage,
    /// Optional application token generator.
    #[config(default = None)]
    pub generate_token: Option<OneTimeTokenGenerator>,
}

/// Exchange a short-lived token for an existing authenticated session.
pub struct OneTimeTokenPlugin {
    config: OneTimeTokenConfig,
}

better_auth_core::impl_auth_plugin! {
    OneTimeTokenPlugin, "one-time-token";
    routes {
        get "/one-time-token/generate" => handle_generate, "generateOneTimeToken";
        post "/one-time-token/verify" => handle_verify, "verifyOneTimeToken";
    }
    extra {
        async fn after_request(
            &self,
            _req: &AuthRequest,
            response: &mut AuthResponse,
            ctx: &AuthContext<S>,
        ) -> AuthResult<()> {
            if !self.config.set_ott_header_on_new_session {
                return Ok(());
            }
            let Some(token) = response_session_token(response, &ctx.config) else {
                return Ok(());
            };
            let Some((session, user)) = find_session(ctx, &token).await? else {
                return Ok(());
            };
            let token = self.generate(ctx, session, user).await?;
            let _ = response.headers.insert("set-ott", token);
            let mut exposed: Vec<_> = response.headers.get("access-control-expose-headers")
                .map(|value| value.split(',').map(str::trim).filter(|value| !value.is_empty()).map(str::to_owned).collect())
                .unwrap_or_default();
            if !exposed.iter().any(|header| header == "set-ott") {
                exposed.push("set-ott".into());
            }
            let _ = response.headers.insert("Access-Control-Expose-Headers", exposed.join(", "));
            Ok(())
        }
    }
}

impl OneTimeTokenPlugin {
    /// Generate a token for a session supplied by trusted server code.
    pub async fn generate<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        session: SessionView,
        user: UserView,
    ) -> AuthResult<String> {
        let session_token = session.token.clone();
        let token = match &self.config.generate_token {
            Some(generate) => generate(session, user).await?,
            None => {
                let mut bytes = [0_u8; 24];
                rand::thread_rng().fill_bytes(&mut bytes);
                URL_SAFE_NO_PAD.encode(bytes)
            }
        };
        let stored = self.config.store_token.encode(&token).await?;
        let _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: format!("one-time-token:{stored}"),
                value: session_token,
                expires_at: Utc::now() + self.config.expires_in,
            })
            .await?;
        Ok(token)
    }

    async fn handle_generate<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let (user, session) = ctx.require_session(req).await.map_err(session_required)?;
        if self.config.disable_client_request {
            return message_error("Client requests are disabled");
        }
        let token = self.generate(ctx, session, user).await?;
        Ok(AuthResponse::json(
            200,
            &serde_json::json!({ "token": token }),
        )?)
    }

    async fn handle_verify<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let token = match token_body(req, "token") {
            Ok(token) => token,
            Err(response) => return Ok(response),
        };
        let stored = self.config.store_token.encode(&token).await?;
        let Some(verification) = ctx
            .database
            .consume_verification_by_identifier(&format!("one-time-token:{stored}"))
            .await?
        else {
            return message_error("Invalid token");
        };
        let Some((session, user)) = find_session(ctx, verification.value()).await? else {
            return message_error("Session not found");
        };
        let mut response = if session.expires_at < Utc::now() {
            message_error("Session expired")?
        } else {
            AuthResponse::json(
                200,
                &serde_json::json!({ "session": session, "user": user }),
            )?
        };
        if !self.config.disable_set_session_cookie {
            response.headers.append(
                "Set-Cookie",
                create_session_cookie(&session.token, &ctx.config),
            );
        }
        Ok(response)
    }
}

fn message_error(message: &str) -> AuthResult<AuthResponse> {
    Ok(AuthResponse::json(
        400,
        &serde_json::json!({ "message": message }),
    )?)
}

pub(crate) fn session_required(error: AuthError) -> AuthError {
    match error {
        AuthError::Unauthenticated => AuthError::Upstream {
            status: 401,
            code: "UNAUTHORIZED",
            message: "Unauthorized",
        },
        error => error,
    }
}

pub(crate) fn token_body(req: &AuthRequest, field: &str) -> Result<String, AuthResponse> {
    use super::json_body;
    let body = json_body::parse(req)?;
    let Some(serde_json::Value::Object(body)) = body.as_ref() else {
        return Err(json_body::validation_error(&json_body::invalid_type(
            "body",
            "object",
            body.as_ref(),
        )));
    };
    body.get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            json_body::validation_error(&json_body::invalid_type(
                &format!("body.{field}"),
                "string",
                body.get(field),
            ))
        })
}

pub(crate) async fn find_session<S: AuthSchema>(
    ctx: &AuthContext<S>,
    token: &str,
) -> AuthResult<Option<(SessionView, UserView)>> {
    let Some((session, snapshot)) = ctx.database.get_session_snapshot(token).await? else {
        return Ok(None);
    };
    if let Some(mut data) = snapshot {
        data.session.filter_returned_fields(&ctx.config.session);
        return Ok(Some((data.session, ctx.user_view(&data.user)?)));
    }
    let Some(user) = ctx.database.get_user_by_id(&session.user_id()).await? else {
        return Ok(None);
    };
    Ok(Some((
        ctx.session_view(&session).await?,
        ctx.user_view(&user)?,
    )))
}

pub(crate) fn response_session_token(
    response: &AuthResponse,
    config: &better_auth_core::AuthConfig,
) -> Option<String> {
    response
        .headers
        .get_all("set-cookie")
        .filter_map(|value| cookie::Cookie::parse(value.as_str()).ok())
        .filter(|cookie| cookie.name() == config.session.cookie_name)
        .last()
        .filter(|cookie| {
            !cookie.value().is_empty()
                && cookie.max_age().is_none_or(|age| age.whole_seconds() != 0)
        })
        .and_then(|cookie| verify_cookie_value(cookie.value(), config.signing_secret()))
}

#[cfg(test)]
mod tests;
