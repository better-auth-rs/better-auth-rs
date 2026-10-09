//! Single-use exchange of an existing session.

use std::{future::Future, pin::Pin, sync::Arc};

use super::endpoint_context::EndpointContext;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, AuthSession,
    CreateVerification, FieldMap, FieldValue,
    session::NativeSessionData,
    wire::{SessionView, UserView},
};
use chrono::{Duration, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};

mod callbacks;
pub use callbacks::{OneTimeTokenCallbacks, OneTimeTokenGeneratorFuture};

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
    dyn Fn(NativeSessionData) -> Pin<Box<dyn Future<Output = AuthResult<String>> + Send>>
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
        post "/one-time-token/verify" => handle_verify, "verifyOneTimeToken", body = verify_body;
    }
    extra {
        async fn after_request(
            &self,
            _req: &AuthRequest,
            response: &mut AuthResponse,
            ctx: &AuthContext<S>,
        ) -> AuthResult<()> {
better_auth_core::observability::instrumentation::with_endpoint_hook(
        &ctx.config, _req, "after", "plugin:one-time-token", async {
            if !self.config.set_ott_header_on_new_session {
                return Ok(());
            }
            let Some(data) = _req.new_session()? else {
                return Ok(());
            };
            let mut exposed = Vec::new();
            if let Some(value) = response.headers.get("access-control-expose-headers") {
                for header in value.split(',').map(str::trim).filter(|header| !header.is_empty()) {
                    if !exposed.iter().any(|existing| existing == header) {
                        exposed.push(header.to_owned());
                    }
                }
            }
            if !exposed.iter().any(|header| header == "set-ott") {
                exposed.push("set-ott".into());
            }
            let mut endpoint = EndpointContext::new(Some(_req), _req.input_field_value()?, ctx);
            endpoint.session = _req.native_session_snapshot()?;
            endpoint.response = Some(response);
            let token = self.generate_in_endpoint(data, &endpoint).await?;
            _req.set_response_header("set-ott", token.clone())?;
            _req.set_response_header("Access-Control-Expose-Headers", exposed.join(", "))?;
            let _ = response.headers.insert("set-ott", token);
            let _ = response.headers.insert("Access-Control-Expose-Headers", exposed.join(", "));
            Ok(())
         }
    ).await
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
        self.generate_native(ctx, (user, session).into()).await
    }

    /// Generate a token without narrowing the selected User relationship or callback values.
    pub async fn generate_native<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        data: NativeSessionData,
    ) -> AuthResult<String> {
        let mut endpoint = EndpointContext::native(None, None, FieldValue::Undefined, ctx);
        endpoint.session = Some(data.clone());
        self.generate_in_endpoint(data, &endpoint).await
    }

    /// Generate and persist a token within the supplied endpoint's active transaction.
    pub async fn generate_in_endpoint<S: AuthSchema>(
        &self,
        data: NativeSessionData,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<String> {
        let session_token = data.session.token.clone();
        let token = if let Some(callbacks) = endpoint
            .auth
            .extensions
            .get::<Arc<OneTimeTokenCallbacks<S>>>()
        {
            (callbacks.generator)(&data, endpoint).await?
        } else {
            match &self.config.generate_token {
                Some(generate) => generate(data).await?,
                None => {
                    let mut bytes = [0_u8; 24];
                    rand::thread_rng().fill_bytes(&mut bytes);
                    URL_SAFE_NO_PAD.encode(bytes)
                }
            }
        };
        let expires_at = Utc::now() + self.config.expires_in;
        let stored = self.config.store_token.encode(&token).await?;
        let verification = CreateVerification {
            identifier: (format!("one-time-token:{stored}")).into(),
            value: session_token,
            expires_at: expires_at.into(),
            ..Default::default()
        };
        let _ = match endpoint.transaction {
            Some(transaction) => {
                transaction
                    .create_verification_optional(verification)
                    .await?
            }
            None => {
                endpoint
                    .auth
                    .database
                    .create_verification_optional(verification)
                    .await?
            }
        };
        Ok(token)
    }

    async fn handle_generate<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let data = ctx
            .require_native_session(req)
            .await
            .map_err(session_required)?;
        let mut endpoint = EndpointContext::new(Some(req), FieldValue::Undefined, ctx);
        endpoint.session = Some(data.clone());
        if self.config.disable_client_request && endpoint.request.is_some() {
            return message_error("Client requests are disabled");
        }
        endpoint.body = req.input_field_value()?;
        let token = self.generate_in_endpoint(data, &endpoint).await?;
        AuthResponse::json(None, &serde_json::json!({ "token": token }))
    }

    async fn handle_verify<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let token = token_body(req, "token")?;
        let stored = self.config.store_token.encode(&token).await?;
        let Some(verification) = ctx
            .database
            .consume_verification_by_identifier(&format!("one-time-token:{stored}"))
            .await?
        else {
            return message_error("Invalid token");
        };
        let Some(data) = find_session(ctx, &verification.value.field_value()).await? else {
            return message_error("Session not found");
        };
        if !self.config.disable_set_session_cookie {
            ctx.session_manager()
                .set_native_session_cookie(req, data.clone(), None)
                .await?;
        }
        if data.session.expires_at.is_before(Utc::now())? {
            return message_error("Session expired");
        }
        Ok(AuthResponse::native(None, FieldMap::from(data).into()))
    }
}

fn message_error(message: &str) -> AuthResult<AuthResponse> {
    Err(AuthResponse::json(400, &serde_json::json!({ "message": message }))?.into())
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

#[derive(serde::Deserialize)]
struct TokenBody {
    #[serde(alias = "sessionToken")]
    token: String,
}
fn token_input(req: &AuthRequest, field: &str) -> AuthResult<(String, serde_json::Value)> {
    let (body, projection) = super::json_body::string_input::<TokenBody>(req, &[(field, true)])?;
    Ok((body.token, projection))
}
fn verify_body(req: &AuthRequest) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let (body, projection) = token_input(req, "token")?;
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        Some(projection),
        body,
    ))
}
pub(crate) fn session_token_body(
    req: &AuthRequest,
) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let (body, projection) = token_input(req, "sessionToken")?;
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        Some(projection),
        body,
    ))
}
pub(crate) fn token_body(req: &AuthRequest, field: &str) -> AuthResult<String> {
    match req.validated_body::<String>() {
        Some(body) => Ok(body.clone()),
        None => token_input(req, field).map(|(body, _)| body),
    }
}

pub(crate) async fn find_session<S: AuthSchema>(
    ctx: &AuthContext<S>,
    token: &FieldValue,
) -> AuthResult<Option<NativeSessionData>> {
    let Some((session, snapshot)) = ctx.database.get_session_snapshot_value(token).await? else {
        return Ok(None);
    };
    if let Some(data) = snapshot {
        let mut data = NativeSessionData::from(data);
        if !data.user.is_truthy() {
            return Ok(None);
        }
        data.session.filter_returned_fields(&ctx.config.session)?;
        data.user = data.public_user(&ctx.config.user)?;
        return Ok(Some(data));
    }
    let Some(user) = ctx
        .database
        .get_user_by_id_value(&session.user_id().field_value())
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(NativeSessionData {
        session: ctx.session_view(&session).await?,
        user: FieldMap::from(ctx.user_view(&user).await?).into(),
    }))
}

#[cfg(test)]
mod callback_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod transaction_tests;
