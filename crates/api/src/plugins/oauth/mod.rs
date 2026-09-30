use async_trait::async_trait;

use better_auth_core::AuthResult;
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};

mod account;
pub mod encryption;
mod handlers;
pub(crate) use handlers::{sign_in_verified_profile, validate_redirect_target};
mod logout;
mod providers;
mod proxy;
pub use proxy::{OAuthProxyConfig, OAuthProxyPlugin};
mod state;
mod types;

pub use providers::{
    OAuthCallbackUserName, OAuthCallbackUserPayload, OAuthConfig, OAuthIdTokenVerifier,
    OAuthProvider, OAuthRefreshTokenHandler, OAuthTokenSet, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};

pub struct OAuthPlugin {
    config: OAuthConfig,
}

impl OAuthPlugin {
    pub fn new() -> Self {
        Self {
            config: OAuthConfig::default(),
        }
    }

    pub fn with_config(config: OAuthConfig) -> Self {
        Self { config }
    }

    pub fn add_provider(mut self, name: &str, provider: OAuthProvider) -> Self {
        let _ = self.config.providers.insert(name.to_string(), provider);
        self
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
        Ok(())
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/sign-in/social", "social_sign_in"),
            AuthRoute::get("/callback/{provider}", "oauth_callback"),
            AuthRoute::post("/callback/{provider}", "oauth_callback_post"),
            AuthRoute::post("/link-social", "link_social"),
            AuthRoute::post("/get-access-token", "get_access_token"),
            AuthRoute::post("/refresh-token", "refresh_token"),
            AuthRoute::get("/account-info", "account_info"),
        ]
    }

    async fn before_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<better_auth_core::BeforeRequestAction>> {
        if req.method() == &HttpMethod::Post && req.path() == "/sign-out" {
            return Ok(Some(better_auth_core::BeforeRequestAction::Respond(
                logout::handle_sign_out(&self.config, req, ctx).await?,
            )));
        }
        Ok(None)
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-in/social") => Ok(Some(
                handlers::handle_social_sign_in(&self.config, req, ctx).await?,
            )),
            (HttpMethod::Get | HttpMethod::Post, path) if path_matches_callback(path) => {
                let provider = extract_provider_from_callback(path);
                Ok(Some(
                    handlers::handle_callback(&self.config, &provider, req, ctx).await?,
                ))
            }
            (HttpMethod::Post, "/link-social") => Ok(Some(
                handlers::handle_link_social(&self.config, req, ctx).await?,
            )),
            (HttpMethod::Post, "/get-access-token") => Ok(Some(
                account::handle_get_access_token(&self.config, req, ctx).await?,
            )),
            (HttpMethod::Post, "/refresh-token") => Ok(Some(
                account::handle_refresh_token(&self.config, req, ctx).await?,
            )),
            (HttpMethod::Get, "/account-info") => Ok(Some(
                account::handle_account_info(&self.config, req, ctx).await?,
            )),
            _ => Ok(None),
        }
    }
}

/// Check if the path matches `/callback/{provider}` (with optional query string).
fn path_matches_callback(path: &str) -> bool {
    let path_without_query = path.split('?').next().unwrap_or(path);
    path_without_query
        .strip_prefix("/callback/")
        .is_some_and(|provider| !provider.is_empty() && !provider.contains('/'))
}

/// Extract the provider name from `/callback/{provider}?...`.
fn extract_provider_from_callback(path: &str) -> String {
    let path_without_query = path.split('?').next().unwrap_or(path);
    path_without_query["/callback/".len()..].to_string()
}
