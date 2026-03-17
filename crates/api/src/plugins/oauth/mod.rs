use async_trait::async_trait;

use better_auth_core::AuthResult;
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};

#[cfg(feature = "axum")]
use better_auth_core::plugin::{AuthState, AxumPlugin};

pub mod encryption;
mod handlers;
mod providers;
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
impl AuthPlugin for OAuthPlugin {
    fn name(&self) -> &'static str {
        "oauth"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/sign-in/social", "social_sign_in"),
            AuthRoute::get("/callback/{provider}", "oauth_callback"),
            AuthRoute::post("/callback/{provider}", "oauth_callback_post"),
            AuthRoute::post("/link-social", "link_social"),
            AuthRoute::post("/get-access-token", "get_access_token"),
            AuthRoute::post("/refresh-token", "refresh_token"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
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
                handlers::handle_get_access_token(&self.config, req, ctx).await?,
            )),
            (HttpMethod::Post, "/refresh-token") => Ok(Some(
                handlers::handle_refresh_token(&self.config, req, ctx).await?,
            )),
            _ => Ok(None),
        }
    }
}

/// Check if the path matches `/callback/{provider}` (with optional query string).
fn path_matches_callback(path: &str) -> bool {
    let path_without_query = path.split('?').next().unwrap_or(path);
    path_without_query.starts_with("/callback/") && path_without_query.len() > "/callback/".len()
}

/// Extract the provider name from `/callback/{provider}?...`.
fn extract_provider_from_callback(path: &str) -> String {
    let path_without_query = path.split('?').next().unwrap_or(path);
    path_without_query["/callback/".len()..].to_string()
}

// ---------------------------------------------------------------------------
// Axum-native routing (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "axum")]
mod axum_impl {
    use super::*;
    use std::sync::Arc;

    use axum::extract::{Extension, Path, State};
    use better_auth_core::error::AuthError;
    use better_auth_core::extractors::{AuthRequestExt, AxumAuthResponse};

    #[derive(Clone)]
    struct PluginState {
        config: OAuthConfig,
    }

    async fn handle_social_sign_in(
        State(state): State<AuthState>,
        Extension(ps): Extension<Arc<PluginState>>,
        AuthRequestExt(req): AuthRequestExt,
    ) -> Result<AxumAuthResponse, AuthError> {
        let ctx = state.to_context();
        let response = handlers::handle_social_sign_in(&ps.config, &req, &ctx).await?;
        Ok(AxumAuthResponse(response))
    }

    async fn handle_callback(
        State(state): State<AuthState>,
        Extension(ps): Extension<Arc<PluginState>>,
        Path(provider): Path<String>,
        AuthRequestExt(req): AuthRequestExt,
    ) -> Result<AxumAuthResponse, AuthError> {
        let ctx = state.to_context();
        let response = handlers::handle_callback(&ps.config, &provider, &req, &ctx).await?;
        Ok(AxumAuthResponse(response))
    }

    async fn handle_link_social(
        State(state): State<AuthState>,
        Extension(ps): Extension<Arc<PluginState>>,
        AuthRequestExt(req): AuthRequestExt,
    ) -> Result<AxumAuthResponse, AuthError> {
        let ctx = state.to_context();
        let response = handlers::handle_link_social(&ps.config, &req, &ctx).await?;
        Ok(AxumAuthResponse(response))
    }

    async fn handle_get_access_token(
        State(state): State<AuthState>,
        Extension(ps): Extension<Arc<PluginState>>,
        AuthRequestExt(req): AuthRequestExt,
    ) -> Result<AxumAuthResponse, AuthError> {
        let ctx = state.to_context();
        let response = handlers::handle_get_access_token(&ps.config, &req, &ctx).await?;
        Ok(AxumAuthResponse(response))
    }

    async fn handle_refresh_token(
        State(state): State<AuthState>,
        Extension(ps): Extension<Arc<PluginState>>,
        AuthRequestExt(req): AuthRequestExt,
    ) -> Result<AxumAuthResponse, AuthError> {
        let ctx = state.to_context();
        let response = handlers::handle_refresh_token(&ps.config, &req, &ctx).await?;
        Ok(AxumAuthResponse(response))
    }

    #[async_trait]
    impl AxumPlugin for OAuthPlugin {
        fn name(&self) -> &'static str {
            "oauth"
        }

        fn router(&self) -> axum::Router<AuthState> {
            use axum::routing::{get, post};

            let plugin_state = Arc::new(PluginState {
                config: self.config.clone(),
            });

            axum::Router::new()
                .route("/sign-in/social", post(handle_social_sign_in))
                .route(
                    "/callback/:provider",
                    get(handle_callback).post(handle_callback),
                )
                .route("/link-social", post(handle_link_social))
                .route("/get-access-token", post(handle_get_access_token))
                .route("/refresh-token", post(handle_refresh_token))
                .layer(Extension(plugin_state))
        }
    }
}
