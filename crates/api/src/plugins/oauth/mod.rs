use async_trait::async_trait;

use better_auth_core::AuthResult;
use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};

#[cfg(feature = "axum")]
use better_auth_core::plugin::{AuthState, AxumPlugin};

pub mod encryption;
mod handlers;
mod providers;
mod types;

pub use providers::{OAuthConfig, OAuthProvider, OAuthStateStrategy, OAuthUserInfo};

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
        self.config.providers.insert(name.to_string(), provider);
        self
    }
}

impl Default for OAuthPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for OAuthPlugin {
    fn name(&self) -> &'static str {
        "oauth"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/sign-in/social", "social_sign_in"),
            AuthRoute::get("/callback/{provider}", "oauth_callback"),
            AuthRoute::post("/link-social", "link_social"),
            AuthRoute::post("/get-access-token", "get_access_token"),
            AuthRoute::post("/refresh-token", "refresh_token"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-in/social") => Ok(Some(
                handlers::handle_social_sign_in(&self.config, req, ctx).await?,
            )),
            (HttpMethod::Get, path) if path_matches_callback(path) => {
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

    use axum::Json;
    use axum::extract::{Extension, Path, State};
    use better_auth_core::error::AuthError;
    use better_auth_core::extractors::{
        AuthRequestExt, AxumAuthResponse, CurrentSession, ValidatedJson,
    };

    use super::handlers::{
        get_access_token_core, link_social_core, refresh_token_core, social_sign_in_core,
    };
    use super::types::{
        AccessTokenResponse, GetAccessTokenRequest, LinkSocialRequest, RefreshTokenRequest,
        RefreshTokenResponse, SocialSignInRequest, SocialSignInResponse,
    };

    #[derive(Clone)]
    struct PluginState {
        config: OAuthConfig,
    }

    async fn handle_social_sign_in<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        ValidatedJson(body): ValidatedJson<SocialSignInRequest>,
    ) -> Result<Json<SocialSignInResponse>, AuthError> {
        let ctx = state.to_context();
        let result = social_sign_in_core(&body, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    /// Callback handler uses AuthRequestExt bridge because it sets cookies
    /// and returns a complex response with headers.
    async fn handle_callback<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        Path(provider): Path<String>,
        AuthRequestExt(req): AuthRequestExt,
    ) -> Result<AxumAuthResponse, AuthError> {
        let ctx = state.to_context();
        Ok(AxumAuthResponse(
            handlers::handle_callback(&ps.config, &provider, &req, &ctx).await?,
        ))
    }

    async fn handle_link_social<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { session, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<LinkSocialRequest>,
    ) -> Result<Json<SocialSignInResponse>, AuthError> {
        let ctx = state.to_context();
        let result = link_social_core(&body, &session, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_get_access_token<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { session, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<GetAccessTokenRequest>,
    ) -> Result<Json<AccessTokenResponse>, AuthError> {
        let ctx = state.to_context();
        let result = get_access_token_core(&body, &session, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_refresh_token<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { session, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<RefreshTokenRequest>,
    ) -> Result<Json<RefreshTokenResponse>, AuthError> {
        let ctx = state.to_context();
        let result = refresh_token_core(&body, &session, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    #[async_trait]
    impl<DB: DatabaseAdapter> AxumPlugin<DB> for OAuthPlugin {
        fn name(&self) -> &'static str {
            "oauth"
        }

        fn router(&self) -> axum::Router<AuthState<DB>> {
            use axum::routing::{get, post};

            let plugin_state = Arc::new(PluginState {
                config: self.config.clone(),
            });

            axum::Router::new()
                .route("/sign-in/social", post(handle_social_sign_in::<DB>))
                .route("/callback/:provider", get(handle_callback::<DB>))
                .route("/link-social", post(handle_link_social::<DB>))
                .route("/get-access-token", post(handle_get_access_token::<DB>))
                .route("/refresh-token", post(handle_refresh_token::<DB>))
                .layer(Extension(plugin_state))
        }
    }
}
