//! Email proof using an atomically consumed sign-in link.

use std::{future::Future, pin::Pin, sync::Arc};

use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, AuthSession,
    AuthUser, AuthVerification, CreateUser, CreateVerification, RequestMeta,
    middleware::EndpointRateLimit, utils::cookie_utils::create_session_cookie,
};
use chrono::{Duration, Utc};
use rand::Rng;
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};
use url::Url;

use super::{
    helpers::{SessionIssueError, apply_default_role, issue_user_session},
    one_time_token::TokenStorage,
};

/// Payload delivered by the configured magic-link sender.
#[derive(Debug, Clone, Serialize)]
pub struct MagicLinkMessage {
    /// Destination email address.
    pub email: String,
    /// Verification URL with callback parameters.
    pub url: String,
    /// Original, unstored verification token.
    pub token: String,
    /// Application data supplied by the sign-in request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Deliver magic links through the application's email service.
#[async_trait]
pub trait SendMagicLink: Send + Sync {
    /// Send one link. Delivery failures propagate to the endpoint.
    async fn send(&self, message: &MagicLinkMessage) -> AuthResult<()>;
}

/// Generate a token for the supplied email address.
pub type MagicLinkTokenGenerator =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = AuthResult<String>> + Send>> + Send + Sync>;

/// Magic-link options matching the upstream plugin.
#[derive(better_auth_core::PluginConfig)]
#[plugin(name = "MagicLinkPlugin")]
pub struct MagicLinkConfig {
    /// Verification lifetime. Zero uses the upstream five-minute default.
    #[config(default = Duration::minutes(5))]
    pub expires_in: Duration,
    /// Deny verification for email addresses without an existing user.
    #[config(default = false)]
    pub disable_sign_up: bool,
    /// Representation stored in the verification table.
    #[config(default = TokenStorage::Plain)]
    pub store_token: TokenStorage,
    /// Optional custom token generation.
    #[config(default = None)]
    pub generate_token: Option<MagicLinkTokenGenerator>,
    /// Required application email sender.
    #[config(default = None, skip)]
    pub send_magic_link: Option<Arc<dyn SendMagicLink>>,
    /// Plugin endpoint limit window in seconds.
    #[config(default = 60)]
    pub rate_limit_window: u64,
    /// Maximum requests in the limit window.
    #[config(default = 5)]
    pub rate_limit_max: u32,
}

/// Sign in or register after proving control of an email address.
pub struct MagicLinkPlugin {
    config: MagicLinkConfig,
}

better_auth_core::impl_auth_plugin! {
    MagicLinkPlugin, "magic-link";
    routes {
        post "/sign-in/magic-link" => handle_send, "signInWithMagicLink";
        get "/magic-link/verify" => handle_verify, "verifyMagicLink";
    }
    extra {
        fn rate_limits(&self) -> AuthResult<Vec<(String, EndpointRateLimit)>> {
            Ok(["/sign-in/magic-link", "/magic-link/verify"].into_iter().map(|path| (path.into(), EndpointRateLimit {
                window: std::time::Duration::from_secs(if self.config.rate_limit_window == 0 { 60 } else { self.config.rate_limit_window }),
                max_requests: if self.config.rate_limit_max == 0 { 5 } else { self.config.rate_limit_max },
            })).collect())
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendBody {
    email: String,
    name: Option<String>,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL")]
    new_user_callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    error_callback_url: Option<String>,
    metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Serialize, Deserialize)]
struct Proof {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

impl MagicLinkPlugin {
    /// Configure the application email sender.
    pub fn custom_send_magic_link(mut self, sender: Arc<dyn SendMagicLink>) -> Self {
        self.config.send_magic_link = Some(sender);
        self
    }

    async fn handle_send<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let body: SendBody = match parse_send(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        let sender = self
            .config
            .send_magic_link
            .as_ref()
            .ok_or_else(|| AuthError::config("Magic link requires a sender"))?;
        let token = match &self.config.generate_token {
            Some(generate) => generate(body.email.clone()).await?,
            None => rand::thread_rng()
                .sample_iter(Alphanumeric)
                .filter(u8::is_ascii_alphabetic)
                .take(32)
                .map(char::from)
                .collect(),
        };
        let stored = self.config.store_token.encode(&token).await?;
        let lifetime = if self.config.expires_in.is_zero() {
            Duration::minutes(5)
        } else {
            self.config.expires_in
        };
        let _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: stored,
                value: serde_json::to_string(&Proof {
                    email: body.email.clone(),
                    name: body.name,
                })?,
                expires_at: Utc::now() + lifetime,
            })
            .await?;
        let mut url = Url::parse(&ctx.config.base_url)
            .map_err(|error| AuthError::config(format!("Invalid base URL: {error}")))?;
        let base_path = if url.path() == "/" {
            ctx.config.base_path.as_str()
        } else {
            url.path()
        };
        url.set_path(&format!(
            "{}/magic-link/verify",
            base_path.trim_end_matches('/')
        ));
        {
            let mut query = url.query_pairs_mut();
            let _ = query.append_pair("token", &token);
            let _ = query.append_pair(
                "callbackURL",
                body.callback_url
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .unwrap_or("/"),
            );
            if let Some(value) = body.new_user_callback_url.filter(|value| !value.is_empty()) {
                let _ = query.append_pair("newUserCallbackURL", &value);
            }
            if let Some(value) = body.error_callback_url.filter(|value| !value.is_empty()) {
                let _ = query.append_pair("errorCallbackURL", &value);
            }
        }
        sender
            .send(&MagicLinkMessage {
                email: body.email,
                url: url.into(),
                token,
                metadata: body.metadata,
            })
            .await?;
        Ok(AuthResponse::json(
            200,
            &serde_json::json!({ "status": true }),
        )?)
    }

    async fn handle_verify<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let Some(token) = req.query.get("token") else {
            return Ok(super::json_body::validation_error(
                "[query.token] Invalid input: expected string, received undefined",
            ));
        };
        let base = Url::parse(&ctx.config.base_url)
            .map_err(|error| AuthError::config(format!("Invalid base URL: {error}")))?;
        let callback = callback_url(req, ctx, &base, "callbackURL", "/")?;
        let error_callback = callback_url(req, ctx, &base, "errorCallbackURL", callback.as_str())?;
        let new_user_callback =
            callback_url(req, ctx, &base, "newUserCallbackURL", callback.as_str())?;
        let stored = self.config.store_token.encode(token).await?;
        let Some(value) = ctx
            .database
            .consume_verification_by_identifier(&stored)
            .await?
        else {
            return Ok(error_redirect(error_callback, "INVALID_TOKEN"));
        };
        let proof: Proof = serde_json::from_str(value.value())?;
        let existing = ctx.database.get_user_by_email(&proof.email).await?;
        let is_new_user = existing.is_none();
        let user = match existing {
            Some(user) => user,
            None if self.config.disable_sign_up => {
                return Ok(error_redirect(error_callback, "new_user_signup_disabled"));
            }
            None => {
                let mut user = CreateUser::new()
                    .with_email(proof.email)
                    .with_name(proof.name.unwrap_or_default())
                    .with_email_verified(true);
                apply_default_role(ctx, &mut user);
                ctx.database.create_user(user).await?
            }
        };
        let user = if user.email_verified() {
            user
        } else {
            let Some(user) = ctx
                .database
                .verify_user_and_revoke_unproven_access(&user.id())
                .await?
            else {
                return Ok(error_redirect(error_callback, "user_not_found"));
            };
            user
        };
        let meta = RequestMeta::from_request(req);
        let issued = issue_user_session(ctx, &user.id(), meta.ip_address, meta.user_agent)
            .await
            .map_err(SessionIssueError::into_auth_error)?;
        let response = if req.query.get("callbackURL").is_none_or(String::is_empty) {
            AuthResponse::json(
                200,
                &serde_json::json!({ "token": issued.session.token(), "session": ctx.session_view(&issued.session).await?, "user": ctx.user_view(&issued.user)? }),
            )?
        } else {
            redirect(if is_new_user {
                new_user_callback
            } else {
                callback
            })
        };
        Ok(response.with_header(
            "Set-Cookie",
            create_session_cookie(issued.session.token(), &ctx.config),
        ))
    }
}

fn callback_url<S: AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
    base: &Url,
    key: &str,
    default: &str,
) -> AuthResult<Url> {
    let value = req
        .query
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .unwrap_or(default);
    let decoded = urlencoding::decode(value)
        .map_err(|error| AuthError::bad_request(format!("Invalid callback URL: {error}")))?;
    if !ctx.config.advanced.disable_origin_check && !ctx.config.is_redirect_target_trusted(&decoded)
    {
        return Err(AuthError::forbidden("Invalid callbackURL"));
    }
    base.join(&decoded)
        .map_err(|error| AuthError::bad_request(format!("Invalid callback URL: {error}")))
}

fn parse_send(req: &AuthRequest) -> Result<SendBody, AuthResponse> {
    use super::json_body;
    let value = json_body::parse(req)?;
    let Some(serde_json::Value::Object(body)) = value.as_ref() else {
        return Err(json_body::validation_error(&json_body::invalid_type(
            "body",
            "object",
            value.as_ref(),
        )));
    };
    let mut errors = Vec::new();
    for field in [
        "email",
        "name",
        "callbackURL",
        "newUserCallbackURL",
        "errorCallbackURL",
        "metadata",
    ] {
        let value = body.get(field);
        if field != "email" && value.is_none() {
            continue;
        }
        let expected = if field == "metadata" {
            "record"
        } else {
            "string"
        };
        if !value.is_some_and(|value| {
            if field == "metadata" {
                value.is_object()
            } else {
                value.is_string()
            }
        }) {
            errors.push(json_body::invalid_type(
                &format!("body.{field}"),
                expected,
                value,
            ));
        } else if field == "email"
            && !validator::ValidateEmail::validate_email(
                &value
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
            )
        {
            errors.push("[body.email] Invalid email address".into());
        }
    }
    if !errors.is_empty() {
        return Err(json_body::validation_error(&errors.join("; ")));
    }
    serde_json::from_value(value.unwrap_or_default())
        .map_err(|error| json_body::validation_error(&error.to_string()))
}

fn redirect(url: Url) -> AuthResponse {
    AuthResponse::new(302)
        .with_header("Location", url.to_string())
        .with_header("content-type", "application/json")
}

fn error_redirect(mut url: Url, error: &str) -> AuthResponse {
    let pairs: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| key != "error")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    let _ = url
        .query_pairs_mut()
        .clear()
        .extend_pairs(pairs)
        .append_pair("error", error);
    redirect(url)
}
