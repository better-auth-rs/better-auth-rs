//! Transfer verified OAuth profiles from a production callback to a preview.

use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, AuthSession, AuthVerification, BeforeRequestAction, HttpMethod, OAuthStateStrategy,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::{
    OAuthProvider, OAuthTokenSet, OAuthUserInfo, OAuthUserInfoRequest, handlers,
    state::{self, OAuthStatePayload},
};
use crate::plugins::{json_body, symmetric};

mod environment;

/// Production-to-preview callback configuration.
#[derive(Clone, better_auth_core::PluginConfig)]
#[plugin(name = "OAuthProxyPlugin")]
pub struct OAuthProxyConfig {
    /// Production callback base URL; also overrides the environment for proxy skip checks.
    #[config(default = None)]
    pub production_url: Option<String>,
    /// Explicit preview URL; otherwise use a trusted request host, hosting environment, or base URL.
    #[config(default = None)]
    pub current_url: Option<String>,
    /// Shared encryption secret; defaults to the authentication secret.
    #[config(default = None)]
    pub secret: Option<String>,
    /// Maximum profile age in seconds.
    #[config(default = 60)]
    pub max_age: i64,
}

/// Complete preview authentication without creating a production session.
pub struct OAuthProxyPlugin {
    config: OAuthProxyConfig,
}

pub(super) const REDIRECT_BASE_CONTEXT: &str = "oauthProxyRedirectBase";
const CALLBACK_CONTEXT: &str = "oauthProxyCallback";

pub(super) fn validate_callback_url<S: AuthSchema>(
    req: &AuthRequest,
    callback: &str,
    ctx: &AuthContext<S>,
) -> AuthResult<()> {
    // The proxy validates the original target before generating this configured receiver.
    // Exact equality keeps later hooks from substituting an untrusted target.
    if req
        .server_context(CALLBACK_CONTEXT)?
        .as_ref()
        .and_then(Value::as_str)
        == Some(callback)
    {
        return Ok(());
    }
    handlers::validate_redirect_target(callback, ctx, "Invalid callbackURL")
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatePackage {
    state: String,
    state_cookie: String,
    is_o_auth_proxy: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileUser {
    #[serde(default, flatten)]
    additional_fields: serde_json::Map<String, Value>,
    id: String,
    email: String,
    name: String,
    #[serde(default)]
    email_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileAccount {
    account_id: String,
    provider_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    user_info: ProfileUser,
    account: ProfileAccount,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<serde_json::Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<Vec<String>>,
    state: String,
    #[serde(rename = "callbackURL")]
    callback_url: String,
    #[serde(rename = "newUserURL", skip_serializing_if = "Option::is_none")]
    new_user_url: Option<String>,
    #[serde(rename = "errorURL", skip_serializing_if = "Option::is_none")]
    error_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disable_sign_up: Option<bool>,
    timestamp: f64,
}

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for OAuthProxyPlugin {
    fn name(&self) -> &'static str {
        "oauth-proxy"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/callback/{provider}/oauth-proxy", "oauthProxyCompletion"),
            AuthRoute::get("/oauth-proxy-callback", "oauthProxyCallback"),
        ]
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.method() != &HttpMethod::Get {
            return Ok(None);
        }
        if req.path() == "/oauth-proxy-callback" {
            return self.complete(None, req, ctx).await.map(Some);
        }
        if let Some(provider) = req
            .path()
            .strip_prefix("/callback/")
            .and_then(|path| path.strip_suffix("/oauth-proxy"))
            .filter(|provider| !provider.is_empty() && !provider.contains('/'))
        {
            return self.complete(Some(provider), req, ctx).await.map(Some);
        }
        Ok(None)
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if req.method() == &HttpMethod::Post
            && matches!(req.path(), "/sign-in/social" | "/link-social")
        {
            return self.initiate(req, ctx);
        }
        if let Some(provider) = req
            .path()
            .strip_prefix("/callback/")
            .filter(|provider| !provider.is_empty() && !provider.contains('/'))
        {
            return Ok(self
                .production_callback(provider, req, ctx)
                .await?
                .map(BeforeRequestAction::Respond));
        }
        Ok(None)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        if matches!(req.path(), "/sign-in/social" | "/link-social")
            && req.server_context(REDIRECT_BASE_CONTEXT)?.is_some()
        {
            return self.wrap_authorization(response, ctx).await;
        }
        if !req
            .path()
            .strip_prefix("/callback/")
            .is_some_and(|provider| !provider.is_empty() && !provider.contains('/'))
        {
            return Ok(());
        }
        let Some(location) = response.headers.get("location").filter(|location| {
            location.contains("/oauth-proxy?callbackURL")
                || location.contains("/oauth-proxy-callback?callbackURL")
        }) else {
            return Ok(());
        };
        let Ok(location) = Url::parse(location) else {
            return Ok(());
        };
        let production = parse_url(
            self.config
                .production_url
                .as_deref()
                .filter(|url| !url.is_empty())
                .unwrap_or(&ctx.config.base_url),
        )?;
        if location.origin() == production.origin()
            && let Some((_, target)) = location.query_pairs().find(|(key, _)| key == "callbackURL")
        {
            let _ = response.headers.insert("location", target.into_owned());
        }
        Ok(())
    }
}

impl OAuthProxyPlugin {
    fn encryption_key<'a, S: AuthSchema>(&'a self, ctx: &'a AuthContext<S>) -> &'a str {
        self.config.secret.as_deref().unwrap_or(&ctx.config.secret)
    }

    fn initiate<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if self.config.skip_proxy(req, ctx) {
            return Ok(None);
        }
        let mut body = match json_body::parse(req) {
            Ok(Some(Value::Object(body))) => body,
            _ => return Ok(None),
        };
        let Some(provider) = body
            .get("provider")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let current = self.config.resolve_current_url(req, ctx)?;
        let original = body
            .get("callbackURL")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| handlers::auth_base_url(ctx));
        handlers::validate_redirect_target(&original, ctx, "Invalid callbackURL")?;
        let mut callback = parse_url(&format!(
            "{}{}{}{}",
            current.origin().ascii_serialization(),
            ctx.config.base_path,
            "/callback/",
            provider
        ))?;
        callback.set_path(&format!("{}/oauth-proxy", callback.path()));
        let _ = callback
            .query_pairs_mut()
            .append_pair("callbackURL", &original);
        let _ = body.insert("callbackURL".into(), callback.to_string().into());
        req.set_server_context(CALLBACK_CONTEXT, callback.to_string().into())?;
        let redirect_base = self
            .config
            .production_url
            .as_deref()
            .filter(|url| !url.is_empty())
            .map(|url| format!("{}{}", url.trim_end_matches('/'), ctx.config.base_path))
            .unwrap_or_else(|| handlers::auth_base_url(ctx));
        req.set_server_context(REDIRECT_BASE_CONTEXT, redirect_base.into())?;
        Ok(Some(BeforeRequestAction::ReplaceBody(serde_json::to_vec(
            &body,
        )?)))
    }

    async fn wrap_authorization<S: AuthSchema>(
        &self,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        if response.status != 200 {
            return Ok(());
        }
        let mut body: serde_json::Map<String, Value> = serde_json::from_slice(&response.body)?;
        let Some(url) = body
            .get("url")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return Ok(());
        };
        let mut url = parse_url(url)?;
        let Some((_, original_state)) = url.query_pairs().find(|(key, _)| key == "state") else {
            return Ok(());
        };
        let original_state = original_state.into_owned();
        let payload = match ctx.config.account.store_state_strategy {
            OAuthStateStrategy::Database => {
                let verification = ctx
                    .database
                    .get_verification_by_identifier(&format!("oauth:{original_state}"))
                    .await?
                    .ok_or_else(|| AuthError::internal("OAuth proxy state was not persisted"))?;
                verification.value().to_owned()
            }
            OAuthStateStrategy::Cookie => {
                let name = state::state_cookie_name(&ctx.config);
                let value = response
                    .headers
                    .get_all("set-cookie")
                    .find_map(|header| header.split(';').next()?.strip_prefix(&format!("{name}=")))
                    .ok_or_else(|| {
                        AuthError::internal("OAuth proxy state cookie was not issued")
                    })?;
                serde_json::to_string(&state::decode_cookie_state_value(
                    &ctx.config.secret,
                    value,
                )?)?
            }
        };
        let package = StatePackage {
            state: original_state,
            state_cookie: symmetric::encrypt(self.encryption_key(ctx), &payload)?,
            is_o_auth_proxy: true,
        };
        let mut encrypted = Some(symmetric::encrypt(
            self.encryption_key(ctx),
            &serde_json::to_string(&package)?,
        )?);
        let pairs: Vec<_> = url
            .query_pairs()
            .filter_map(|(key, value)| {
                let value = if key == "state" {
                    encrypted.take()?
                } else {
                    value.into_owned()
                };
                Some((key.into_owned(), value))
            })
            .collect();
        let _ = url.query_pairs_mut().clear().extend_pairs(pairs);
        let _ = body.insert("url".into(), url.to_string().into());
        response.body = serde_json::to_vec(&body)?;
        Ok(())
    }

    async fn production_callback<S: AuthSchema>(
        &self,
        provider_id: &str,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let mut params = req.query.clone();
        if req.method() == &HttpMethod::Post
            && let Some(bytes) = &req.body
        {
            let body = serde_json::from_slice::<std::collections::HashMap<String, String>>(bytes)
                .unwrap_or_else(|_| url::form_urlencoded::parse(bytes).into_owned().collect());
            for (key, value) in body {
                let _ = params.entry(key).or_insert(value);
            }
        }
        let Some(state) = params.get("state") else {
            return Ok(None);
        };
        let Ok(package) = symmetric::decrypt(self.encryption_key(ctx), state)
            .and_then(|plain| serde_json::from_str::<StatePackage>(&plain).map_err(Into::into))
        else {
            return Ok(None);
        };
        if !package.is_o_auth_proxy || package.state.is_empty() || package.state_cookie.is_empty() {
            return Ok(None);
        }
        let Ok(state) = symmetric::decrypt(self.encryption_key(ctx), &package.state_cookie)
            .and_then(|plain| {
                serde_json::from_str::<OAuthStatePayload>(&plain).map_err(Into::into)
            })
        else {
            return Ok(None);
        };
        let default_error = format!("{}/error", handlers::auth_base_url(ctx));
        let error_url = state
            .error_url
            .as_deref()
            .filter(|url| !url.is_empty())
            .unwrap_or(&default_error);
        if state
            .additional_data
            .get("oauthState")
            .is_some_and(|value| value != &Value::String(package.state.clone()))
        {
            return Ok(Some(redirect_error(error_url, "state_mismatch", None)?));
        }
        if let Some(error) = params.get("error").filter(|value| !value.is_empty()) {
            return Ok(Some(redirect_error(error_url, error, None)?));
        }
        let Some(code) = params.get("code").filter(|value| !value.is_empty()) else {
            return Ok(Some(redirect_error(error_url, "no_code", None)?));
        };
        let Some(provider) = ctx
            .extensions
            .get::<std::sync::Arc<super::resolved::ResolvedOAuthConfig>>()
            .and_then(|config| config.providers.get(provider_id))
        else {
            return Ok(Some(redirect_error(
                error_url,
                "oauth_provider_not_found",
                None,
            )?));
        };
        let tokens = match super::provider_tokens::validate_authorization_code_via_provider(
            provider,
            code,
            &format!("{}/callback/{provider_id}", handlers::auth_base_url(ctx)),
            Some(&state.code_verifier),
            None,
        )
        .await
        {
            Ok(tokens) => tokens,
            Err(_) => return Ok(Some(redirect_error(error_url, "invalid_code", None)?)),
        };
        let info = match handlers::fetch_user_info_from_provider(
            provider,
            OAuthUserInfoRequest {
                access_token: tokens.access_token.clone(),
                refresh_token: tokens.refresh_token.clone(),
                id_token: tokens.id_token.clone(),
                access_token_expires_at: tokens.access_token_expires_at,
                refresh_token_expires_at: tokens.refresh_token_expires_at,
                token_type: tokens.token_type.clone(),
                scopes: tokens.scopes.clone(),
                raw: tokens.raw.clone(),
                user: handlers::parse_callback_user_payload(params.get("user").map(String::as_str)),
            },
            state.id_token_nonce.as_deref(),
        )
        .await
        {
            Ok(info) => info,
            Err(_) => {
                return Ok(Some(redirect_error(
                    error_url,
                    "unable_to_get_user_info",
                    None,
                )?));
            }
        };
        if info.user.email.is_empty() {
            return Ok(Some(redirect_error(error_url, "email_not_found", None)?));
        }
        let mut callback = parse_url(&state.callback_url)?;
        let final_url = callback
            .query_pairs()
            .find(|(key, _)| key == "callbackURL")
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| state.callback_url.clone());
        let payload = Profile {
            user_info: ProfileUser {
                additional_fields: info.user.additional_fields,
                id: info.user.id.clone(),
                email: info.user.email,
                name: info.user.name.unwrap_or_default(),
                image: info.user.image,
                email_verified: info.user.email_verified,
            },
            account: ProfileAccount {
                account_id: info.user.id,
                provider_id: provider_id.to_owned(),
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                id_token: tokens.id_token,
                access_token_expires_at: tokens.access_token_expires_at,
                refresh_token_expires_at: tokens.refresh_token_expires_at,
                scope: Some(tokens.scopes.join(",")),
            },
            profile: info.data.as_object().cloned(),
            scopes: Some(tokens.scopes),
            state: package.state,
            callback_url: final_url,
            new_user_url: state.new_user_url,
            error_url: state.error_url,
            disable_sign_up: Some(
                provider.config.disable_sign_up
                    || provider.config.disable_implicit_sign_up
                        && !state.request_sign_up.unwrap_or(false),
            ),
            timestamp: Utc::now().timestamp_millis() as f64,
        };
        let encrypted =
            symmetric::encrypt(self.encryption_key(ctx), &serde_json::to_string(&payload)?)?;
        let _ = callback
            .query_pairs_mut()
            .append_pair("profile", &encrypted);
        Ok(Some(handlers::redirect_response(callback.as_str())))
    }

    async fn complete<S: AuthSchema>(
        &self,
        provider: Option<&str>,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let Some(callback) = req.query.get("callbackURL") else {
            return Ok(json_body::validation_error(
                "[query.callbackURL] Invalid input: expected string, received undefined",
            ));
        };
        handlers::validate_redirect_target(callback, ctx, "Invalid callbackURL")?;
        let default_error = format!(
            "{}/api/auth/error",
            ctx.config.base_url.trim_end_matches('/')
        );
        let Some(encrypted) = req.query.get("profile").filter(|value| !value.is_empty()) else {
            return redirect_error(&default_error, "missing_profile", None);
        };
        let plain = match symmetric::decrypt(self.encryption_key(ctx), encrypted) {
            Ok(plain) => plain,
            Err(_) => return redirect_error(&default_error, "invalid_profile", None),
        };
        let profile = match serde_json::from_str::<Profile>(&plain) {
            Ok(profile) if !profile.state.is_empty() && !profile.callback_url.is_empty() => profile,
            _ => return redirect_error(&default_error, "invalid_payload", None),
        };
        let error_url = profile
            .error_url
            .as_deref()
            .filter(|url| !url.is_empty())
            .unwrap_or(&default_error);
        if provider.is_some_and(|provider| provider != profile.account.provider_id) {
            return redirect_error(error_url, "provider_mismatch", None);
        }
        let age = (Utc::now().timestamp_millis() as f64 - profile.timestamp) / 1000.0;
        if age > self.config.max_age as f64 || age < -10.0 {
            return redirect_error(error_url, "payload_expired", None);
        }
        let state = match ctx.config.account.store_state_strategy {
            OAuthStateStrategy::Database => ctx
                .database
                .consume_verification_by_identifier(&format!("oauth:{}", profile.state))
                .await?
                .and_then(|verification| {
                    serde_json::from_str::<OAuthStatePayload>(verification.value()).ok()
                }),
            OAuthStateStrategy::Cookie => {
                state::get_cookie(req, &state::state_cookie_name(&ctx.config))
                    .and_then(|value| {
                        state::decode_cookie_state_value(&ctx.config.secret, &value).ok()
                    })
                    .filter(|state| {
                        !state.is_expired()
                            && state
                                .additional_data
                                .get("oauthState")
                                .is_some_and(|value| value.as_str() == Some(profile.state.as_str()))
                    })
            }
        };
        let Some(state) = state else {
            return redirect_error(error_url, "state_mismatch", None);
        };
        if state.is_expired()
            || state
                .additional_data
                .get("oauthState")
                .is_some_and(|value| value != &Value::String(profile.state.clone()))
        {
            return redirect_error(error_url, "state_mismatch", None);
        }
        if let Some(anonymous_user) = state.server_context.get("anonymousUserId") {
            req.set_server_context("anonymousUserId", anonymous_user.clone())?;
        }
        let clear = better_auth_core::utils::cookie_utils::create_clear_cookie(
            &state::state_cookie_name(&ctx.config),
            &ctx.config,
        );
        let user = OAuthUserInfo {
            additional_fields: profile.user_info.additional_fields,
            id: profile.account.account_id,
            email: profile.user_info.email.to_lowercase(),
            name: Some(profile.user_info.name),
            image: profile.user_info.image,
            email_verified: profile.user_info.email_verified,
        };
        let tokens = OAuthTokenSet {
            access_token: profile.account.access_token,
            refresh_token: profile.account.refresh_token,
            id_token: profile.account.id_token,
            access_token_expires_at: profile.account.access_token_expires_at,
            refresh_token_expires_at: profile.account.refresh_token_expires_at,
            scopes: profile.scopes.unwrap_or_else(|| {
                profile
                    .account
                    .scope
                    .as_deref()
                    .unwrap_or_default()
                    .split(',')
                    .map(str::to_owned)
                    .collect()
            }),
            ..Default::default()
        };
        if let Some(link) = state.link {
            if let Err(error) = handlers::complete_link_social(
                &profile.account.provider_id,
                &user,
                &tokens,
                &link,
                ctx,
            )
            .await
            {
                return Ok(redirect_error(error_url, &error, None)?
                    .with_appended_header("Set-Cookie", clear));
            }
            return Ok(handlers::redirect_response(&profile.callback_url)
                .with_appended_header("Set-Cookie", clear));
        }
        let fallback = super::resolved::ResolvedProvider {
            config: OAuthProvider::google("", ""),
            generic: None,
        };
        let provider = ctx
            .extensions
            .get::<std::sync::Arc<super::resolved::ResolvedOAuthConfig>>()
            .and_then(|config| config.providers.get(&profile.account.provider_id))
            .unwrap_or(&fallback);
        let outcome = match super::signin::process_oauth_sign_in(
            &profile.account.provider_id,
            provider,
            &user,
            &tokens,
            super::signin::OAuthSignInOptions {
                disable_sign_up: profile.disable_sign_up.unwrap_or(false),
                callback_url: &profile.callback_url,
                email_verification: ctx
                    .extensions
                    .get::<std::sync::Arc<super::resolved::ResolvedOAuthConfig>>()
                    .and_then(|config| config.email_verification.as_deref()),
            },
            &better_auth_core::RequestMeta::from_request(req),
            ctx,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                let (code, description) = error.redirect_parts();
                return Ok(redirect_error(error_url, &code, description)?
                    .with_appended_header("Set-Cookie", clear));
            }
        };
        let target = if outcome.is_register {
            profile
                .new_user_url
                .as_deref()
                .filter(|url| !url.is_empty())
                .unwrap_or(&profile.callback_url)
        } else {
            &profile.callback_url
        };
        Ok(handlers::redirect_response(target)
            .with_appended_header("Set-Cookie", clear)
            .with_appended_header(
                "Set-Cookie",
                better_auth_core::utils::cookie_utils::create_session_cookie(
                    outcome.session.token(),
                    &ctx.config,
                ),
            ))
    }
}

fn parse_url(value: &str) -> AuthResult<Url> {
    Url::parse(value)
        .map_err(|error| AuthError::bad_request(format!("Invalid OAuth proxy URL: {error}")))
}

fn redirect_error(
    target: &str,
    error: &str,
    description: Option<&str>,
) -> AuthResult<AuthResponse> {
    let separator = if target.contains('?') { '&' } else { '?' };
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    let _ = params.append_pair("error", error);
    if let Some(description) = description {
        let _ = params.append_pair("error_description", description);
    }
    Ok(handlers::redirect_response(&format!(
        "{target}{separator}{}",
        params.finish()
    )))
}
