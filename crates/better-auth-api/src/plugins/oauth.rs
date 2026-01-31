use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use validator::Validate;

use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, CreateAccount, CreateUser, HttpMethod, User};

/// OAuth authentication plugin for social sign-in
pub struct OAuthPlugin {
    config: OAuthConfig,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthConfig {
    pub providers: HashMap<String, OAuthProvider>,
}

#[derive(Debug, Clone)]
pub struct OAuthProvider {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub scopes: Vec<String>,
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

// Request/Response structures for social authentication
#[derive(Debug, Deserialize, Validate)]
#[allow(dead_code)]
struct SocialSignInRequest {
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL")]
    new_user_callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    error_callback_url: Option<String>,
    #[validate(length(min = 1, message = "Provider is required"))]
    provider: String,
    #[serde(rename = "disableRedirect")]
    disable_redirect: Option<String>,
    #[serde(rename = "idToken")]
    id_token: Option<String>,
    scopes: Option<String>,
    #[serde(rename = "requestSignUp")]
    request_sign_up: Option<String>,
    #[serde(rename = "loginHint")]
    login_hint: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
struct LinkSocialRequest {
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    #[validate(length(min = 1, message = "Provider is required"))]
    provider: String,
    scopes: Option<String>,
}

#[derive(Debug, Serialize)]
struct SocialSignInResponse {
    redirect: bool,
    token: String,
    url: Option<String>,
    user: User,
}

#[derive(Debug, Serialize)]
struct LinkSocialResponse {
    url: String,
    redirect: bool,
}

#[async_trait]
impl AuthPlugin for OAuthPlugin {
    fn name(&self) -> &'static str {
        "oauth"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/sign-in/social", "social_sign_in"),
            AuthRoute::post("/link-social", "link_social"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-in/social") => {
                Ok(Some(self.handle_social_sign_in(req, ctx).await?))
            }
            (HttpMethod::Post, "/link-social") => {
                Ok(Some(self.handle_link_social(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }
}

// Implementation methods outside the trait
impl OAuthPlugin {
    async fn handle_social_sign_in(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        let signin_req: SocialSignInRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Validate provider
        if !self.config.providers.contains_key(&signin_req.provider) {
            return Err(AuthError::bad_request(format!(
                "Provider '{}' is not configured",
                signin_req.provider
            )));
        }

        // If id_token is provided, verify and create session directly
        if let Some(id_token) = &signin_req.id_token {
            return self
                .handle_id_token_sign_in(id_token, &signin_req, ctx)
                .await;
        }

        // Otherwise, generate authorization URL for OAuth flow
        self.generate_auth_url(&signin_req, ctx).await
    }

    async fn handle_link_social(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        let link_req: LinkSocialRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Validate provider
        if !self.config.providers.contains_key(&link_req.provider) {
            return Err(AuthError::bad_request(format!(
                "Provider '{}' is not configured",
                link_req.provider
            )));
        }

        // Generate authorization URL for linking
        let provider = &self.config.providers[&link_req.provider];
        let callback_url = link_req.callback_url.unwrap_or_else(|| {
            format!(
                "{}/oauth/{}/callback",
                ctx.config.base_url, link_req.provider
            )
        });

        let scopes = if let Some(scopes) = &link_req.scopes {
            scopes.split(',').map(|s| s.trim().to_string()).collect()
        } else {
            provider.scopes.clone()
        };

        let auth_url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state=link_{}",
            provider.auth_url,
            provider.client_id,
            urlencoding::encode(&callback_url),
            urlencoding::encode(&scopes.join(" ")),
            uuid::Uuid::new_v4()
        );

        let response = LinkSocialResponse {
            url: auth_url,
            redirect: true,
        };

        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_id_token_sign_in(
        &self,
        id_token: &str,
        signin_req: &SocialSignInRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        // TODO: Implement proper JWT verification
        // For now, return a mock implementation that creates a user

        // Mock user creation from ID token
        let email = format!("user+{}@{}.com", uuid::Uuid::new_v4(), signin_req.provider);
        let name = format!("User from {}", signin_req.provider);

        // Check if user already exists
        let existing_user = ctx.database.get_user_by_email(&email).await?;
        let user = if let Some(user) = existing_user {
            user
        } else {
            // Create new user
            let create_user = CreateUser::new()
                .with_email(&email)
                .with_name(&name)
                .with_email_verified(true); // Social providers typically verify email

            ctx.database.create_user(create_user).await?
        };

        // Create account record for this social provider
        let create_account = CreateAccount {
            account_id: format!("{}_{}", signin_req.provider, uuid::Uuid::new_v4()),
            provider_id: signin_req.provider.clone(),
            user_id: user.id.clone(),
            access_token: Some("mock_access_token".to_string()),
            refresh_token: None,
            id_token: Some(id_token.to_string()),
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: None,
        };

        // Check if account already exists
        if ctx
            .database
            .get_account(&signin_req.provider, &create_account.account_id)
            .await?
            .is_none()
        {
            ctx.database.create_account(create_account).await?;
        }

        // Create session
        let session_manager =
            better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager.create_session(&user, None, None).await?;

        let response = SocialSignInResponse {
            redirect: false,
            token: session.token,
            url: None,
            user,
        };

        Ok(AuthResponse::json(200, &response)?)
    }

    async fn generate_auth_url(
        &self,
        signin_req: &SocialSignInRequest,
        ctx: &AuthContext,
    ) -> AuthResult<AuthResponse> {
        let provider = &self.config.providers[&signin_req.provider];
        let callback_url = signin_req.callback_url.clone().unwrap_or_else(|| {
            format!(
                "{}/oauth/{}/callback",
                ctx.config.base_url, signin_req.provider
            )
        });

        let scopes = if let Some(scopes) = &signin_req.scopes {
            scopes.split(',').map(|s| s.trim().to_string()).collect()
        } else {
            provider.scopes.clone()
        };

        let mut auth_url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
            provider.auth_url,
            provider.client_id,
            urlencoding::encode(&callback_url),
            urlencoding::encode(&scopes.join(" ")),
            uuid::Uuid::new_v4()
        );

        if let Some(login_hint) = &signin_req.login_hint {
            auth_url.push_str(&format!("&login_hint={}", urlencoding::encode(login_hint)));
        }

        // Return redirect response
        Ok(AuthResponse::json(
            200,
            &serde_json::json!({
                "url": auth_url,
                "redirect": true
            }),
        )?)
    }
}
