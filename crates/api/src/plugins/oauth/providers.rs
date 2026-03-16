use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Configuration for the OAuth plugin, containing all registered providers.
#[derive(Clone, Default)]
pub struct OAuthConfig {
    pub providers: HashMap<String, OAuthProvider>,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthTokenSet {
    pub token_type: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub id_token: Option<String>,
    pub raw: Option<Value>,
}

/// User information extracted from an OAuth provider's user info endpoint.
#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: bool,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthCallbackUserPayload {
    pub name: Option<OAuthCallbackUserName>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthCallbackUserName {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthUserInfoRequest {
    pub token_type: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub id_token: Option<String>,
    pub raw: Option<Value>,
    pub user: Option<OAuthCallbackUserPayload>,
}

#[derive(Debug, Clone)]
pub struct OAuthUserInfoResponse {
    pub user: OAuthUserInfo,
    pub data: Value,
}

#[async_trait]
pub trait OAuthUserInfoHandler: Send + Sync {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String>;
}

#[async_trait]
pub trait OAuthRefreshTokenHandler: Send + Sync {
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokenSet, String>;
}

#[async_trait]
pub trait OAuthIdTokenVerifier: Send + Sync {
    async fn verify_id_token(&self, token: &str, nonce: Option<&str>) -> Result<bool, String>;
}

/// Configuration for a single OAuth provider.
#[derive(Clone)]
pub struct OAuthProvider {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: Option<String>,
    pub scopes: Vec<String>,
    pub authorization_params: Vec<(String, String)>,
    pub map_user_info: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
    pub get_user_info: Option<Arc<dyn OAuthUserInfoHandler>>,
    pub refresh_access_token: Option<Arc<dyn OAuthRefreshTokenHandler>>,
    pub verify_id_token: Option<Arc<dyn OAuthIdTokenVerifier>>,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub override_user_info_on_sign_in: bool,
}

impl OAuthProvider {
    pub fn google(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            user_info_url: Some("https://www.googleapis.com/oauth2/v3/userinfo".to_string()),
            scopes: vec![
                "email".to_string(),
                "profile".to_string(),
                "openid".to_string(),
            ],
            authorization_params: vec![("include_granted_scopes".to_string(), "true".to_string())],
            map_user_info: Some(|v| {
                Ok(OAuthUserInfo {
                    id: v
                        .get("sub")
                        .and_then(|v| v.as_str())
                        .ok_or("missing sub")?
                        .to_string(),
                    email: v
                        .get("email")
                        .and_then(|v| v.as_str())
                        .ok_or("missing email")?
                        .to_string(),
                    name: v.get("name").and_then(|v| v.as_str()).map(String::from),
                    image: v.get("picture").and_then(|v| v.as_str()).map(String::from),
                    email_verified: v
                        .get("email_verified")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                })
            }),
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }

    pub fn github(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_info_url: Some("https://api.github.com/user".to_string()),
            scopes: vec!["user:email".to_string()],
            authorization_params: Vec::new(),
            map_user_info: Some(|v| {
                Ok(OAuthUserInfo {
                    id: v
                        .get("id")
                        .and_then(|v| v.as_i64())
                        .map(|i| i.to_string())
                        .or_else(|| v.get("id").and_then(|v| v.as_str()).map(String::from))
                        .ok_or("missing id")?,
                    email: v
                        .get("email")
                        .and_then(|v| v.as_str())
                        .ok_or("missing email")?
                        .to_string(),
                    name: v.get("name").and_then(|v| v.as_str()).map(String::from),
                    image: v
                        .get("avatar_url")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    email_verified: true,
                })
            }),
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }

    pub fn discord(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://discord.com/api/oauth2/authorize".to_string(),
            token_url: "https://discord.com/api/oauth2/token".to_string(),
            user_info_url: Some("https://discord.com/api/users/@me".to_string()),
            scopes: vec!["identify".to_string(), "email".to_string()],
            authorization_params: Vec::new(),
            map_user_info: Some(|v| {
                Ok(OAuthUserInfo {
                    id: v
                        .get("id")
                        .and_then(|v| v.as_str())
                        .ok_or("missing id")?
                        .to_string(),
                    email: v
                        .get("email")
                        .and_then(|v| v.as_str())
                        .ok_or("missing email")?
                        .to_string(),
                    name: v.get("username").and_then(|v| v.as_str()).map(String::from),
                    image: v.get("avatar").and_then(|v| v.as_str()).map(|a| {
                        format!(
                            "https://cdn.discordapp.com/avatars/{}/{}.png",
                            v.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                            a
                        )
                    }),
                    email_verified: v.get("verified").and_then(|v| v.as_bool()).unwrap_or(false),
                })
            }),
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }
}
