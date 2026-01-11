use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::core::{AuthPlugin, AuthRoute, AuthContext, PluginCapabilities};
use crate::types::{AuthRequest, AuthResponse, HttpMethod, User, CreateUser, CreateAccount};
use crate::error::{AuthError, AuthResult};

/// OAuth authentication plugin for social sign-in
pub struct OAuthPlugin {
    config: OAuthConfig,
}

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub providers: HashMap<String, OAuthProviderConfig>,
    pub jwt: HashMap<String, OAuthJwtConfig>,
}

#[derive(Debug, Clone)]
pub struct OAuthProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OAuthJwtConfig {
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub algorithm: Option<String>,
    pub public_keys: Option<Vec<String>>,
    pub shared_secret: Option<String>,
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
    
    pub fn add_provider(mut self, name: &str, provider: OAuthProviderConfig) -> Self {
        self.config.providers.insert(name.to_string(), provider);
        self
    }

    pub fn add_jwt_config(mut self, name: &str, config: OAuthJwtConfig) -> Self {
        self.config.jwt.insert(name.to_string(), config);
        self
    }
}

impl Default for OAuthPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            providers: HashMap::new(),
            jwt: HashMap::new(),
        }
    }
}

// Request/Response structures for social authentication
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SocialSignInRequest {
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL")]
    new_user_callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    error_callback_url: Option<String>,
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

#[derive(Debug, Deserialize)]
struct LinkSocialRequest {
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
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

    fn capabilities(&self) -> PluginCapabilities {
        PluginCapabilities {
            needs_database: true,
            ..PluginCapabilities::default()
        }
    }
    
    async fn on_request(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-in/social") => {
                Ok(Some(self.handle_social_sign_in(req, ctx).await?))
            },
            (HttpMethod::Post, "/link-social") => {
                Ok(Some(self.handle_link_social(req, ctx).await?))
            },
            _ => Ok(None),
        }
    }
}

// Implementation methods outside the trait
impl OAuthPlugin {
    async fn handle_social_sign_in(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let signin_req: SocialSignInRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Validate provider
        if !self.config.providers.contains_key(&signin_req.provider) {
            return Ok(AuthResponse::json(400, &serde_json::json!({
                "error": "Invalid provider",
                "message": format!("Provider '{}' is not configured", signin_req.provider)
            }))?);
        }
        
        // If id_token is provided, verify and create session directly
        if let Some(id_token) = &signin_req.id_token {
            return self.handle_id_token_sign_in(id_token, &signin_req, ctx).await;
        }
        
        // Otherwise, generate authorization URL for OAuth flow
        self.generate_auth_url(&signin_req, ctx).await
    }
    
    async fn handle_link_social(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let link_req: LinkSocialRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Validate provider
        if !self.config.providers.contains_key(&link_req.provider) {
            return Ok(AuthResponse::json(400, &serde_json::json!({
                "error": "Invalid provider",
                "message": format!("Provider '{}' is not configured", link_req.provider)
            }))?);
        }
        
        // Generate authorization URL for linking
        let provider = &self.config.providers[&link_req.provider];
        let callback_url = link_req.callback_url.unwrap_or_else(|| {
            format!("{}/oauth/{}/callback", ctx.config.base_url, link_req.provider)
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
        let _provider = match self.config.providers.get(&signin_req.provider) {
            Some(provider) => provider,
            None => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid provider",
                    "message": "Provider is not configured"
                }))?);
            }
        };

        let jwt_config = match self.config.jwt.get(&signin_req.provider) {
            Some(config) => config,
            None => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid provider",
                    "message": "JWT configuration is not configured"
                }))?);
            }
        };

        let claims = match self.verify_id_token(id_token, jwt_config) {
            Ok(claims) => claims,
            Err(err) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid token",
                    "message": err.to_string()
                }))?);
            }
        };

        let email = match claims.email.clone() {
            Some(email) => email,
            None => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid token",
                    "message": "ID token is missing email claim"
                }))?);
            }
        };
        let name = claims.name.clone().unwrap_or_else(|| format!("User from {}", signin_req.provider));
        
        // Check if user already exists
        let existing_user = ctx.database.get_user_by_email(&email).await?;
        let user = if let Some(user) = existing_user {
            user
        } else {
            // Create new user
            let create_user = CreateUser::new()
                .with_email(&email)
                .with_name(&name)
                .with_email_verified(claims.email_verified.unwrap_or(false));

            let user = ctx.database.create_user(create_user).await?;
            let _ = ctx.emit_user_created(&user).await;
            user
        };
        
        // Create account record for this social provider
        let create_account = CreateAccount {
            account_id: claims.sub.clone(),
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
        if ctx.database.get_account(&signin_req.provider, &create_account.account_id).await?.is_none() {
            ctx.database.create_account(create_account).await?;
        }
        
        // Create session
        let session_manager = crate::core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager.create_session(&user, None, None).await?;
        let _ = ctx.emit_session_created(&session).await;
        
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
            format!("{}/oauth/{}/callback", ctx.config.base_url, signin_req.provider)
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
        Ok(AuthResponse::json(200, &serde_json::json!({
            "url": auth_url,
            "redirect": true
        }))?)
    }

    fn verify_id_token(&self, id_token: &str, config: &OAuthJwtConfig) -> AuthResult<IdTokenClaims> {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};

        let alg = config.algorithm.as_deref().unwrap_or("RS256");
        let algorithm = match alg {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            "RS256" => Algorithm::RS256,
            "RS384" => Algorithm::RS384,
            "RS512" => Algorithm::RS512,
            _ => {
                return Err(AuthError::InvalidRequest("Unsupported JWT algorithm".to_string()));
            }
        };

        let mut validation = Validation::new(algorithm);
        if let Some(issuer) = config.issuer.as_deref() {
            validation.set_issuer(&[issuer]);
        }
        if let Some(audience) = config.audience.as_deref() {
            validation.set_audience(&[audience]);
        }

        if matches!(algorithm, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
            let secret = config.shared_secret.as_deref()
                .ok_or_else(|| AuthError::InvalidRequest("Missing JWT shared secret".to_string()))?;
            let key = DecodingKey::from_secret(secret.as_bytes());
            let token = decode::<IdTokenClaims>(id_token, &key, &validation)
                .map_err(|_| AuthError::InvalidRequest("Invalid ID token".to_string()))?;
            return Ok(token.claims);
        }

        let keys = config.public_keys.as_ref()
            .ok_or_else(|| AuthError::InvalidRequest("Missing JWT public keys".to_string()))?;

        for key_pem in keys {
            if let Ok(key) = DecodingKey::from_rsa_pem(key_pem.as_bytes()) {
                if let Ok(token) = decode::<IdTokenClaims>(id_token, &key, &validation) {
                    return Ok(token.claims);
                }
            }
        }

        Err(AuthError::InvalidRequest("Invalid ID token".to_string()))
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct IdTokenClaims {
    sub: String,
    email: Option<String>,
    #[serde(rename = "email_verified")]
    email_verified: Option<bool>,
    name: Option<String>,
}
