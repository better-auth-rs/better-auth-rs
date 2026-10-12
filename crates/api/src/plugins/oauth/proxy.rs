//! Transfer verified OAuth profiles from a production callback to a preview.

use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, BeforeRequestAction, FieldMap, FieldValue, HttpMethod, OAuthStateStrategy,
    ResponseBody,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::{
    OAuthProvider, handlers,
    state::{self, OAuthStatePayload},
};
use crate::plugins::{json_body, symmetric};

mod environment;
mod production;

#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod linking_tests;
#[cfg(test)]
mod native_input_tests;
#[cfg(test)]
mod native_result_tests;
#[cfg(test)]
mod production_tests;
#[cfg(test)]
mod runtime_url_tests;

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
    /// Maximum profile age in seconds, including fractions and non-finite values.
    #[config(default = 60.0)]
    pub max_age: f64,
}

/// Complete preview authentication without creating a production session.
pub struct OAuthProxyPlugin {
    config: OAuthProxyConfig,
}

const CALLBACK_CONTEXT: &str = "oauthProxyCallback";

pub(super) fn validate_callback_url<S: AuthSchema>(
    req: &AuthRequest,
    callback: &str,
    ctx: &AuthContext<S>,
) -> AuthResult<()> {
    // HTTP origin middleware validates the original target before endpoint hooks run.
    // Exact equality keeps later hooks from substituting an untrusted target.
    if req
        .server_context(CALLBACK_CONTEXT)?
        .as_ref()
        .and_then(better_auth_core::FieldValue::as_str)
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
struct Profile {
    #[serde(with = "better_auth_core::field_value::serde::value")]
    user_info: FieldValue,
    #[serde(with = "better_auth_core::field_value::serde::map")]
    account: better_auth_core::FieldMap,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::field_value::serde::optional_value::is_absent_or_json_omitted",
        with = "better_auth_core::field_value::serde::optional_value"
    )]
    profile: Option<FieldValue>,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted"
    )]
    scopes: better_auth_core::SchemaValue<Vec<String>>,
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

impl Profile {
    fn parse(plain: &str) -> AuthResult<Self> {
        let native = better_auth_core::utils::json::parse_client_json(plain.into())?;
        let account = native.model_property("account")?;
        if !matches!(account, FieldValue::Object(_)) {
            return Err(AuthError::bad_request("Invalid OAuth proxy account"));
        }
        let mut fields = account.enumerable_fields()?;
        for name in ["providerId", "accountId"] {
            if !fields.get(name).is_some_and(FieldValue::is_string) {
                return Err(AuthError::bad_request("Invalid OAuth proxy account"));
            }
        }
        for name in [
            "accessToken",
            "refreshToken",
            "idToken",
            "scope",
            "password",
        ] {
            if fields.get(name).is_some_and(|value| {
                !matches!(
                    value,
                    FieldValue::Null
                        | FieldValue::Undefined
                        | FieldValue::String(_)
                        | FieldValue::Utf16String(_)
                )
            }) {
                return Err(AuthError::bad_request("Invalid OAuth proxy token"));
            }
        }
        for name in ["accessTokenExpiresAt", "refreshTokenExpiresAt"] {
            if fields.get(name).is_some_and(|value| match value {
                FieldValue::Null | FieldValue::Undefined => false,
                FieldValue::Date(date) => !date.milliseconds().is_finite(),
                _ => true,
            }) {
                return Err(AuthError::bad_request("Invalid OAuth proxy expiry"));
            }
        }
        let scopes = native.model_property("scopes")?;
        match &scopes {
            FieldValue::Undefined => {}
            FieldValue::Array(values) if values.every(|value| Ok(value.is_string()))? => {}
            _ => return Err(AuthError::bad_request("Invalid OAuth proxy scopes")),
        }
        let user = native.model_property("userInfo")?;
        if !matches!(user, FieldValue::Object(_)) {
            return Err(AuthError::bad_request("Invalid OAuth proxy user"));
        }
        let mut user_fields = FieldMap::new();
        for name in ["id", "email", "emailVerified", "name", "image"] {
            let value = user.model_property(name)?;
            let value = match name {
                "emailVerified" if value.is_undefined() => false.into(),
                "emailVerified" if matches!(value, FieldValue::Bool(_)) => value,
                "image" if value.is_string() || value.is_null() || value.is_undefined() => value,
                "id" | "email" | "name" if value.is_string() => {
                    if name == "email" {
                        super::native_user::lowercase(&value, "email")?
                    } else {
                        value
                    }
                }
                _ => return Err(AuthError::bad_request("Invalid OAuth proxy user")),
            };
            if !value.is_undefined() {
                let _ = user_fields.insert(name.into(), value);
            }
        }
        user_fields.extend(user.enumerable_fields_except(&[
            "id",
            "email",
            "emailVerified",
            "name",
            "image",
        ])?);
        let raw_profile = native.model_property("profile")?;
        if !raw_profile.is_undefined() && !matches!(raw_profile, FieldValue::Object(_)) {
            return Err(AuthError::bad_request(
                "Invalid OAuth proxy provider profile",
            ));
        }
        let mut profile: Self = serde_json::from_str(plain)?;
        profile.user_info = user_fields.into();
        profile.profile = (!raw_profile.is_undefined()).then_some(raw_profile);
        fields = fields.in_field_order(
            &[
                "providerId",
                "accountId",
                "accessToken",
                "refreshToken",
                "idToken",
                "accessTokenExpiresAt",
                "refreshTokenExpiresAt",
                "scope",
                "password",
            ]
            .map(str::to_owned),
        );
        profile.account = fields;
        profile.scopes = if scopes.is_undefined() {
            better_auth_core::SchemaValue::Undefined
        } else {
            better_auth_core::SchemaValue::from_field(scopes)
        };
        Ok(profile)
    }
}

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for OAuthProxyPlugin {
    fn name(&self) -> &'static str {
        "oauth-proxy"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/callback/{id}/oauth-proxy", "oAuthProxyCompletion")
                .query_validator(crate::plugins::query_input::proxy),
            AuthRoute::get("/oauth-proxy-callback", "oauthProxyCallback")
                .query_validator(crate::plugins::query_input::proxy),
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
        if req.path().starts_with("/sign-in/social") || req.path() == "/link-social" {
            return better_auth_core::observability::instrumentation::with_endpoint_hook(
                &ctx.config,
                req,
                "before",
                "plugin:oauth-proxy",
                async { self.initiate(req, ctx) },
            )
            .await;
        }
        if let Some(provider) = req
            .path()
            .strip_prefix("/callback/")
            .filter(|provider| !provider.is_empty() && !provider.contains('/'))
        {
            return better_auth_core::observability::instrumentation::with_endpoint_hook(
                &ctx.config,
                req,
                "before",
                "plugin:oauth-proxy",
                async {
                    Ok(self
                        .production_callback(provider, req, ctx)
                        .await?
                        .map(BeforeRequestAction::Respond))
                },
            )
            .await;
        }
        Ok(None)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        if req.path().starts_with("/sign-in/social") || req.path() == "/link-social" {
            return better_auth_core::observability::instrumentation::with_endpoint_hook(
                &ctx.config,
                req,
                "after",
                "plugin:oauth-proxy",
                async {
                    if !self.config.skip_proxy(req, ctx) {
                        self.wrap_authorization(response, ctx).await?;
                    }
                    Ok(())
                },
            )
            .await;
        }
        if !req
            .path()
            .strip_prefix("/callback/")
            .is_some_and(|provider| !provider.is_empty() && !provider.contains('/'))
        {
            return Ok(());
        }
        better_auth_core::observability::instrumentation::with_endpoint_hook(
            &ctx.config,
            req,
            "after",
            "plugin:oauth-proxy",
            async {
                let Some(location) = response.headers.get("location").filter(|location| {
                    (location.contains("/oauth-proxy?callbackURL")
                        || location.contains("/oauth-proxy-callback?callbackURL"))
                        && location.starts_with("http")
                }) else {
                    return Ok(());
                };
                let production = self
                    .config
                    .production_url
                    .as_deref()
                    .filter(|url| !url.is_empty())
                    .or_else(|| {
                        ctx.config
                            .base_url
                            .as_static()
                            .filter(|url| !url.is_empty())
                    })
                    .map(str::to_owned)
                    .unwrap_or_else(|| ctx.base_url());
                let production = environment::origin(&production);
                let location =
                    Url::parse(location).map_err(|_| AuthError::type_error("Invalid URL"))?;
                if production.as_ref() == Some(&location.origin()) {
                    if let Some((_, target)) = location
                        .query_pairs()
                        .find(|(key, _)| key == "callbackURL")
                        .filter(|(_, target)| !target.is_empty())
                    {
                        let _ = response.headers.insert("location", target.into_owned());
                    }
                    return Ok(());
                }
                ctx.logger().warn(
                    "OAuth proxy: cross-origin callback reached after hook unexpectedly",
                    &[],
                )?;
                Ok(())
            },
        )
        .await
    }
}

impl OAuthProxyPlugin {
    fn profile_expired(&self, timestamp: f64, now: i64) -> bool {
        let age = (now as f64 - timestamp) / 1000.0;
        age > self.config.max_age || age < -10.0
    }

    fn encryption_key<'a, S: AuthSchema>(
        &'a self,
        ctx: &'a AuthContext<S>,
    ) -> better_auth_core::SecretKey<'a> {
        self.config
            .secret
            .as_deref()
            .map_or_else(|| ctx.config.encryption_secret(), Into::into)
    }

    fn initiate<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if self.config.skip_proxy(req, ctx) {
            return Ok(None);
        }
        let body = req.input_field_value()?;
        if body.is_null() || body.is_undefined() {
            return Ok(None);
        }
        let provider = body.model_property("provider")?;
        if !provider.is_truthy() {
            return Ok(None);
        }
        let current = self.config.resolve_current_url(req, ctx)?;
        let original = body.model_property("callbackURL")?;
        let original = if original.is_truthy() {
            original
        } else {
            ctx.base_url().into()
        };
        let base_path = if ctx.config.base_path.is_empty() {
            "/api/auth"
        } else {
            &ctx.config.base_path
        };
        if let Some(production) = self
            .config
            .production_url
            .as_deref()
            .filter(|url| !url.is_empty())
        {
            ctx.set_base_url(format!("{}{base_path}", production.trim_end_matches('/')));
        }
        let mut callback: Vec<u16> = format!(
            "{}{base_path}/callback/",
            current.origin().ascii_serialization(),
        )
        .encode_utf16()
        .collect();
        callback.extend_from_slice(provider.display_utf16()?.as_utf16());
        callback.extend("/oauth-proxy?callbackURL=".encode_utf16());
        let original = original
            .display_utf16()?
            .to_utf8()
            .map_err(|_| AuthError::internal("URI malformed"))?;
        callback.extend(
            better_auth_core::utils::cookie_utils::encode_cookie_value(&original).encode_utf16(),
        );
        let callback: FieldValue = better_auth_core::Utf16String::from_units(callback).into();
        let object = body
            .as_object()
            .ok_or_else(|| AuthError::type_error("Cannot assign callbackURL to this body"))?;
        object.set("callbackURL", callback.clone())?;
        req.set_server_context(CALLBACK_CONTEXT, callback)?;
        Ok(None)
    }

    async fn wrap_authorization<S: AuthSchema>(
        &self,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        if !response.is_native() || response.is_api_error()? {
            return Ok(());
        }
        let ResponseBody::Native(FieldValue::Object(body)) = &response.body else {
            return Ok(());
        };
        let provider_url = body.get("url")?.unwrap_or_default();
        if !provider_url.is_string() || !provider_url.is_truthy() {
            return Ok(());
        }
        // URL construction consumes a USVString before the upstream state-processing try block.
        let provider_url = String::from_utf16_lossy(provider_url.display_utf16()?.as_utf16());
        let url = Url::parse(&provider_url).map_err(|_| AuthError::type_error("Invalid URL"))?;
        let Some(original_state) = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.is_empty())
        else {
            return Ok(());
        };
        match self
            .wrapped_authorization(response, url, original_state, ctx)
            .await
        {
            Ok(Some(body)) => response.body = ResponseBody::Native(body),
            Ok(None) => {}
            Err(error) => ctx.logger().error(
                "Failed to prepare OAuth proxy state:",
                &[better_auth_core::observability::logger::LogArgument::Error(
                    &error,
                )],
            )?,
        }
        Ok(())
    }

    async fn wrapped_authorization<S: AuthSchema>(
        &self,
        response: &AuthResponse,
        mut url: Url,
        original_state: String,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<FieldValue>> {
        let payload = match ctx.config.account.store_state_strategy() {
            OAuthStateStrategy::Database => ctx
                .database
                .find_verification_value(&original_state)
                .await?
                .map(|verification| verification.model_property("value"))
                .transpose()?
                .unwrap_or_default(),
            OAuthStateStrategy::Cookie => {
                let name = state::state_cookie_name(&ctx.config);
                let value = response
                    .headers
                    .get_all("set-cookie")
                    .filter_map(|header| {
                        header
                            .split(';')
                            .next()?
                            .trim()
                            .strip_prefix(&format!("{name}="))
                    })
                    .last()
                    .filter(|value| !value.is_empty());
                match value {
                    Some(value) => {
                        let value =
                            better_auth_core::utils::cookie_utils::decode_cookie_value(value);
                        symmetric::decrypt(ctx.config.encryption_secret(), &value)?.into()
                    }
                    None => FieldValue::Undefined,
                }
            }
        };
        if !payload.is_truthy() {
            ctx.logger().warn("No OAuth state found for proxy", &[])?;
            return Ok(None);
        }
        if !payload.is_string() {
            return Err(AuthError::type_error("string expected"));
        }
        let payload = String::from_utf16_lossy(payload.display_utf16()?.as_utf16());
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
        let mut body = response.body.field_value()?.enumerable_fields()?;
        let _ = body.insert("url".into(), url.to_string().into());
        Ok(Some(body.into()))
    }

    async fn complete<S: AuthSchema>(
        &self,
        provider: Option<&str>,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let Some(callback) = req.query_string("callbackURL")? else {
            return Err(json_body::validation_error(
                "[query.callbackURL] Invalid input: expected string, received undefined",
            ));
        };
        handlers::validate_redirect_target(&callback, ctx, "Invalid callbackURL")?;
        let base_url = ctx
            .config
            .base_url
            .as_static()
            .map(str::to_owned)
            .unwrap_or_else(|| {
                environment::origin(&ctx.base_url())
                    .map(|origin| origin.ascii_serialization())
                    .unwrap_or_default()
            });
        let default_error = ctx
            .config
            .api_error
            .error_url
            .clone()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("{}/api/auth/error", base_url.trim_end_matches('/')));
        let Some(encrypted) = req
            .query_string("profile")?
            .filter(|value| !value.is_empty())
        else {
            ctx.logger()
                .error("OAuth proxy callback missing profile data", &[])?;
            return redirect_error(&default_error, "missing_profile", None);
        };
        let plain = match symmetric::decrypt(self.encryption_key(ctx), &encrypted) {
            Ok(plain) => plain,
            Err(_) => return redirect_error(&default_error, "invalid_profile", None),
        };
        let profile = match Profile::parse(&plain) {
            Ok(profile) if !profile.state.is_empty() && !profile.callback_url.is_empty() => profile,
            _ => return redirect_error(&default_error, "invalid_payload", None),
        };
        let error_url = profile
            .error_url
            .as_deref()
            .filter(|url| !url.is_empty())
            .unwrap_or(&default_error);
        let provider_id = profile
            .account
            .get("providerId")
            .and_then(FieldValue::as_str)
            .ok_or_else(|| AuthError::internal("OAuth proxy providerId is not a UTF-8 string"))?;
        if provider.is_some_and(|provider| provider != provider_id) {
            return redirect_error(error_url, "provider_mismatch", None);
        }
        if self.profile_expired(profile.timestamp, Utc::now().timestamp_millis()) {
            return redirect_error(error_url, "payload_expired", None);
        }
        let state = match ctx.config.account.store_state_strategy() {
            OAuthStateStrategy::Database => ctx
                .database
                .consume_verification_by_identifier(&profile.state)
                .await?
                .map(|verification| {
                    verification
                        .value
                        .display_string()
                        .map(|value| OAuthStatePayload::parse(&value).ok())
                })
                .transpose()?
                .flatten(),
            OAuthStateStrategy::Cookie => {
                state::get_cookie(req, &state::state_cookie_name(&ctx.config))
                    .and_then(|value| {
                        state::decode_cookie_state_value(ctx.config.encryption_secret(), &value)
                            .ok()
                    })
                    .filter(|state| {
                        !state.is_expired()
                            && state.oauth_state.as_deref() == Some(profile.state.as_str())
                    })
            }
        };
        let Some(state) = state else {
            return redirect_error(error_url, "state_mismatch", None);
        };
        if state.is_expired()
            || state
                .oauth_state
                .as_deref()
                .is_some_and(|value| value != profile.state)
        {
            return redirect_error(error_url, "state_mismatch", None);
        }
        super::state_context::publish_parsed(req, &state, None)?;
        if let Some(anonymous_user) = state.server_context.get("anonymousUserId") {
            req.set_server_context(
                "anonymousUserId",
                better_auth_core::FieldValue::from_json(anonymous_user.clone())?,
            )?;
        }
        let clear = better_auth_core::utils::cookie_utils::create_clear_cookie(
            &state::state_cookie_name(&ctx.config),
            &ctx.config,
        )?;
        req.append_response_header("Set-Cookie", clear)?;
        let user = profile.user_info.clone();
        let scopes = if !profile.scopes.is_undefined() {
            profile.scopes.clone()
        } else {
            match profile.account.get("scope") {
                None | Some(FieldValue::Null | FieldValue::Undefined) => {
                    better_auth_core::SchemaValue::Undefined
                }
                Some(scope) => {
                    let units = scope.display_utf16()?;
                    let scopes: Vec<FieldValue> = units
                        .as_utf16()
                        .split(|unit| *unit == u16::from(b','))
                        .map(|units| {
                            better_auth_core::Utf16String::from_units(units.to_vec()).into()
                        })
                        .collect();
                    better_auth_core::SchemaValue::Dynamic(scopes.into())
                }
            }
        };
        let provider_profile = profile.profile.clone();
        if let Some(link) = state.link {
            if let handlers::OAuthLinkOutcome::Failed { code, description } =
                handlers::complete_link_social(
                    &user,
                    &profile.account,
                    &scopes,
                    &link,
                    Some(provider_profile.as_ref().unwrap_or(&FieldMap::new().into())),
                    &crate::plugins::endpoint_context::EndpointContext::new(
                        Some(req),
                        better_auth_core::FieldValue::Null,
                        ctx,
                    ),
                )
                .await?
            {
                return Err(req.redirect(error_location(
                    error_url,
                    &code,
                    description.as_deref(),
                )?)?);
            }
            return Err(req.redirect(&profile.callback_url)?);
        }
        let fallback = super::resolved::ResolvedProvider {
            config: OAuthProvider::google("", ""),
            generic: None,
        };
        let provider = ctx
            .extensions
            .get::<std::sync::Arc<super::resolved::ResolvedOAuthConfig>>()
            .and_then(|config| config.providers.get(provider_id))
            .unwrap_or(&fallback);
        let outcome = match super::signin::process_oauth_sign_in(
            provider_id,
            provider,
            &user,
            &profile.account,
            super::signin::OAuthSignInOptions {
                request: req,
                profile: provider_profile.as_ref(),
                body: Value::Null,
                disable_sign_up: profile.disable_sign_up.unwrap_or(false),
                override_user_info: false,
                callback_url: &profile.callback_url,
                email_verification: ctx
                    .extensions
                    .get::<std::sync::Arc<super::resolved::ResolvedOAuthConfig>>()
                    .and_then(|config| config.email_verification.as_deref()),
            },
            &better_auth_core::RequestMeta::from_request_with_config(
                req,
                &ctx.config.advanced.ip_address,
            ),
            ctx,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                let (code, description) = error.redirect_parts()?;
                return redirect_error(error_url, &code, description.as_deref());
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
        ctx.session_manager()
            .set_native_session_cookie(req, outcome.issued, None)
            .await?;
        Ok(handlers::redirect_response(target))
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
    Ok(handlers::redirect_response(&error_location(
        target,
        error,
        description,
    )?))
}

fn error_location(target: &str, error: &str, description: Option<&str>) -> AuthResult<String> {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    let _ = params.append_pair("error", error);
    if let Some(description) = description {
        let _ = params.append_pair("error_description", description);
    }
    better_auth_core::utils::url::append_query_params(target, &params.finish())
}

#[cfg(test)]
mod verification_presence_tests {
    #![expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "Serialization fixtures fail immediately on an invalid ordinary field shape."
    )]

    use super::Profile;
    use serde_json::{Value, json};

    #[test]
    fn proxy_profile_preserves_verification_presence() {
        for value in [
            None,
            Some(Value::Null),
            Some(json!(false)),
            Some(json!(true)),
        ] {
            let mut profile =
                json!({"id":"ordinary-account","email":"owner@example.test","name":"Owner"});
            if let Some(value) = value {
                profile["emailVerified"] = value;
            }
            let payload = json!({
                "userInfo": profile, "account": {"providerId":"google", "accountId":"ordinary-account"},
                "state":"state", "callbackURL":"http://localhost/callback", "timestamp": 1000,
            });
            let decoded = Profile::parse(&payload.to_string());
            if profile.get("emailVerified") == Some(&Value::Null) {
                assert!(decoded.is_err());
            } else {
                if profile.get("emailVerified").is_none() {
                    profile["emailVerified"] = json!(false);
                }
                assert_eq!(decoded.unwrap().user_info.json().unwrap(), Some(profile));
            }
        }
    }
}
