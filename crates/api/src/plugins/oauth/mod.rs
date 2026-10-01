use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};

use super::email_verification::EmailVerificationPlugin;
use tokio::sync::OnceCell;

use better_auth_core::AuthResult;
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};

mod account;
mod authorization;
mod callback;
pub mod encryption;
mod generic;
mod generic_profile;
mod handlers;
pub(crate) use handlers::validate_redirect_target;
pub(crate) use signin::sign_in_verified_profile;
mod logout;
pub(super) use logout::handle_sign_out;
mod oidc;
mod popup;
mod provider_tokens;
mod providers;
pub use popup::{OAUTH_POPUP_COMPLETE_SCRIPT, OAUTH_POPUP_SCRIPT_CSP_HASH, OAuthPopupPlugin};
mod proxy;
pub use proxy::{OAuthProxyConfig, OAuthProxyPlugin};
mod request;
mod resolved;
mod signin;
mod state;
mod state_json;
mod token;
mod types;

pub use generic::{
    GenericOAuthConfig, GenericOAuthUserInfoHandler, OAuthAccountSubject, OAuthCodeExchange,
    OAuthProfile, OAuthProfileMapper, OAuthRefreshParameters, OAuthTokenHandler,
    RefreshTokenParameters,
};
pub use token::{
    ClientAssertion, ClientAssertionContext, TokenEndpointAuth, TokenEndpointRequestContext,
    TokenEndpointSecretAuthentication, TokenGrantType, TokenRequestHook,
};

pub use providers::{
    OAuthCallbackUserName, OAuthCallbackUserPayload, OAuthConfig, OAuthIdTokenVerifier,
    OAuthProvider, OAuthRefreshTokenHandler, OAuthTokenSet, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};

pub struct OAuthPlugin {
    config: OAuthConfig,
    generic: HashMap<String, GenericOAuthConfig>,
    email_verification: Option<Arc<EmailVerificationPlugin>>,
    resolved: OnceCell<Arc<resolved::ResolvedOAuthConfig>>,
}

impl OAuthPlugin {
    pub fn new() -> Self {
        Self {
            config: OAuthConfig::default(),
            generic: HashMap::new(),
            email_verification: None,
            resolved: OnceCell::new(),
        }
    }

    pub fn with_config(config: OAuthConfig) -> Self {
        Self {
            config,
            ..Self::new()
        }
    }

    pub fn add_provider(mut self, name: &str, provider: OAuthProvider) -> Self {
        let _ = self.config.providers.insert(name.to_string(), provider);
        self.resolved = OnceCell::new();
        self
    }

    /// Register a generic OAuth/OIDC provider, resolving discovery during initialization.
    pub fn add_generic_provider(mut self, name: &str, config: GenericOAuthConfig) -> Self {
        let _ = self.generic.insert(name.to_owned(), config);
        self.resolved = OnceCell::new();
        self
    }

    /// Attach the email verification sender and OAuth sign-up/sign-in policy.
    pub fn with_email_verification(mut self, plugin: Arc<EmailVerificationPlugin>) -> Self {
        self.email_verification = Some(plugin);
        self.resolved = OnceCell::new();
        self
    }

    /// Resolve discovery and report whether a provider is available for authentication.
    ///
    /// Discovery results are cached and reused during auth initialization. Providers
    /// skipped after discovery failure return `false`; invalid static configuration
    /// returns an error. This does not contact token, userinfo, or JWKS endpoints.
    /// Configuring the plugin after this call invalidates the cached resolution.
    pub async fn has_provider(&self, name: &str) -> AuthResult<bool> {
        Ok(self.resolved_config().await?.providers.contains_key(name))
    }

    async fn resolved_config(&self) -> AuthResult<&Arc<resolved::ResolvedOAuthConfig>> {
        self.resolved
            .get_or_try_init(|| async {
                resolved::ResolvedOAuthConfig::new(
                    &self.config,
                    &self.generic,
                    self.email_verification.clone(),
                )
                .await
                .map(Arc::new)
            })
            .await
    }
}

impl Default for OAuthPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for OAuthPlugin {
    fn name(&self) -> &'static str {
        "oauth"
    }

    async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
        ctx.extensions.insert(self.config.clone());
        ctx.extensions.insert(self.resolved_config().await?.clone());
        Ok(())
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/sign-in/social", "socialSignIn").body_validator(request::validate),
            AuthRoute::get("/callback/{id}", "callbackOAuth")
                .body_validator(callback::body)
                .query_validator(crate::plugins::query_input::callback)
                .allowed_media_types(&["application/x-www-form-urlencoded", "application/json"]),
            AuthRoute::post("/callback/{id}", "callbackOAuth")
                .body_validator(callback::body)
                .query_validator(crate::plugins::query_input::callback)
                .allowed_media_types(&["application/x-www-form-urlencoded", "application/json"]),
            AuthRoute::post("/link-social", "linkSocialAccount")
                .require_headers(true)
                .body_validator(request::validate),
            AuthRoute::post("/get-access-token", "getAccessToken")
                .body_validator(account::account_body),
            AuthRoute::post("/refresh-token", "refreshToken").body_validator(account::account_body),
            AuthRoute::get("/account-info", "accountInfo")
                .query_validator(crate::plugins::query_input::account_selection),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let config = self.resolved_config().await?;
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-in/social") => Ok(Some(
                handlers::handle_social_sign_in(config, req, ctx).await?,
            )),
            (HttpMethod::Get | HttpMethod::Post, path) if path_matches_callback(path) => {
                let provider = extract_provider_from_callback(path);
                Ok(Some(
                    callback::handle_callback(config, &provider, req, ctx).await?,
                ))
            }
            (HttpMethod::Post, "/link-social") => {
                Ok(Some(handlers::handle_link_social(config, req, ctx).await?))
            }
            (HttpMethod::Post, "/get-access-token") => Ok(Some(
                account::handle_get_access_token(config, req, ctx).await?,
            )),
            (HttpMethod::Post, "/refresh-token") => {
                Ok(Some(account::handle_refresh_token(config, req, ctx).await?))
            }
            (HttpMethod::Get, "/account-info") => {
                Ok(Some(account::handle_account_info(config, req, ctx).await?))
            }
            _ => Ok(None),
        }
    }
}

/// Check if the path matches `/callback/{id}` (with optional query string).
fn path_matches_callback(path: &str) -> bool {
    let path_without_query = path.split('?').next().unwrap_or(path);
    path_without_query
        .strip_prefix("/callback/")
        .is_some_and(|provider| !provider.is_empty() && !provider.contains('/'))
}

/// Extract the provider name from `/callback/{id}?...`.
fn extract_provider_from_callback(path: &str) -> String {
    let path_without_query = path.split('?').next().unwrap_or(path);
    path_without_query["/callback/".len()..].to_string()
}

#[cfg(test)]
mod generic_signin_tests;

#[cfg(test)]
mod readiness_tests;
