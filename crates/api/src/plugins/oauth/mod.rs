use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};

use super::email_verification::EmailVerificationPlugin;
use tokio::sync::OnceCell;

use better_auth_core::AuthResult;
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};

mod account;
#[cfg(test)]
mod apple_flow_tests;
#[cfg(test)]
mod apple_tests;
pub use providers::apple::AppleOptions;
mod authorization;
mod callback;
mod callbacks;
pub use callbacks::{OAuthCallbacks, OAuthVerifierFuture};
mod cognito;
#[cfg(test)]
mod cognito_contract_tests;
#[cfg(test)]
mod cognito_signed_tests;
pub use cognito::CognitoOptions;
pub mod encryption;
#[cfg(test)]
mod facebook_contract_tests;
#[cfg(test)]
mod facebook_signed_tests;
mod generic;
mod generic_presets;
mod generic_profile;
#[cfg(all(test, feature = "axum"))]
mod gitlab_issuer_tests;
pub(super) mod google;
pub use google::GoogleOptions;
#[cfg(all(test, feature = "axum"))]
mod google_client_ids_tests;
mod handlers;
mod id_token;
pub use providers::facebook::FacebookOptions;
pub use providers::microsoft::{MicrosoftOptions, MicrosoftProfilePhotoSize};
#[cfg(all(test, feature = "axum"))]
mod microsoft_tests;
pub use providers::twitch::TwitchOptions;
mod line;
mod microsoft_entra;
pub(crate) use handlers::validate_redirect_target;
pub(crate) use signin::sign_in_verified_profile;
mod logout;
pub(super) use logout::handle_sign_out;
mod oidc;
#[cfg(all(test, feature = "axum"))]
mod paybin_tests;
#[cfg(test)]
mod paypal_tests;
mod popup;
mod provider_tokens;
mod providers;
pub use popup::{OAUTH_POPUP_COMPLETE_SCRIPT, OAUTH_POPUP_SCRIPT_CSP_HASH, OAuthPopupPlugin};
mod proxy;
pub use proxy::{OAuthProxyConfig, OAuthProxyPlugin};
mod request;
mod resolved;
#[cfg(test)]
mod salesforce_tests;
mod signin;
#[cfg(test)]
mod social_nonce_tests;
mod social_profile;
#[cfg(all(test, feature = "axum"))]
mod social_token_wire_tests;
mod state;
mod state_json;
#[cfg(all(test, feature = "axum"))]
mod tiktok_tests;
mod token;
#[cfg(test)]
mod twitter_tests;
mod types;
#[cfg(test)]
mod vk_tests;
#[cfg(test)]
mod wechat_tests;

#[cfg(test)]
mod google_test_support;
#[cfg(test)]
mod google_tests;
#[cfg(test)]
mod verifier_context_tests;

pub use better_auth_core::NativeRequest;
pub use generic::{
    GenericOAuthConfig, GenericOAuthProfileContext, GenericOAuthUserInfoHandler,
    OAuthAccountSubject, OAuthCodeExchange, OAuthProfile, OAuthProfileMapper,
    OAuthRefreshParameters, OAuthTokenHandler, RefreshTokenParameters, VerifiedOAuthClaims,
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

    fn telemetry_plugin_id(&self) -> Option<&'static str> {
        (!self.generic.is_empty()).then_some("generic-oauth")
    }

    fn telemetry(&self, options: &mut better_auth_core::observability::telemetry::PluginTelemetry) {
        use better_auth_core::observability::telemetry::SocialProviderTelemetry;
        if let Some(verification) = &self.email_verification {
            <EmailVerificationPlugin as AuthPlugin<S>>::telemetry(verification, options);
        }
        options
            .social_providers
            .extend(
                self.config
                    .providers
                    .iter()
                    .map(|(id, provider)| SocialProviderTelemetry {
                        id: id.clone(),
                        map_profile_to_user: provider.map_profile_to_user.is_some(),
                        disable_default_scope: provider.disable_default_scope,
                        disable_id_token_sign_in: provider.disable_id_token_sign_in,
                        disable_implicit_sign_up: provider.disable_implicit_sign_up,
                        disable_sign_up: provider.disable_sign_up,
                        get_user_info: provider.get_user_info.is_some(),
                        override_user_info_on_sign_in: provider.override_user_info_on_sign_in,
                        prompt: provider.prompt.clone(),
                        verify_id_token: provider.verify_id_token.is_some(),
                        scope: provider.scopes.clone(),
                        refresh_access_token: provider.refresh_access_token.is_some(),
                    }),
            );
    }

    async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
        let resolved = self.resolved_config().await?;
        if let Some(callbacks) = ctx.extensions.get::<Arc<OAuthCallbacks<S>>>() {
            for name in callbacks.verifiers.keys() {
                if !resolved.providers.contains_key(name) {
                    return Err(better_auth_core::AuthError::config(format!(
                        "OAuth verifier provider {name} is not registered"
                    )));
                }
            }
        }
        ctx.extensions.insert(self.config.clone());
        ctx.extensions.insert(resolved.clone());
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

#[cfg(test)]
mod social_options_tests;

#[cfg(test)]
mod email_verified_tests;

#[cfg(test)]
mod http_provider_tests;
