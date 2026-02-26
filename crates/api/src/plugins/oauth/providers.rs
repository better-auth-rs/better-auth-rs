use serde_json::Value;
use std::collections::HashMap;

/// Strategy for storing OAuth state during the authorization flow.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum OAuthStateStrategy {
    /// Stateless: store state in an encrypted cookie (default).
    #[default]
    Cookie,
    /// Stateful: store state in the verification table.
    Database,
}

/// Configuration for the OAuth plugin, containing all registered providers.
#[derive(Debug, Clone, Default)]
pub struct OAuthConfig {
    pub providers: HashMap<String, OAuthProvider>,
    /// Skip state cookie verification (default: false) - SECURITY WARNING
    pub skip_state_cookie_check: bool,
    /// Where to store OAuth state: Cookie (stateless) or Database (default: Cookie)
    pub store_state_strategy: OAuthStateStrategy,
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

/// Configuration for a single OAuth provider.
#[derive(Debug, Clone)]
pub struct OAuthProvider {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub scopes: Vec<String>,
    pub map_user_info: fn(Value) -> Result<OAuthUserInfo, String>,
}

impl OAuthProvider {
    pub fn google(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            user_info_url: "https://www.googleapis.com/oauth2/v3/userinfo".to_string(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            map_user_info: |v| {
                Ok(OAuthUserInfo {
                    id: v["sub"].as_str().ok_or("missing sub")?.to_string(),
                    email: v["email"].as_str().ok_or("missing email")?.to_string(),
                    name: v["name"].as_str().map(String::from),
                    image: v["picture"].as_str().map(String::from),
                    email_verified: v["email_verified"].as_bool().unwrap_or(false),
                })
            },
        }
    }

    pub fn github(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_info_url: "https://api.github.com/user".to_string(),
            scopes: vec!["user:email".to_string()],
            map_user_info: |v| {
                Ok(OAuthUserInfo {
                    id: v["id"]
                        .as_i64()
                        .map(|i| i.to_string())
                        .or_else(|| v["id"].as_str().map(String::from))
                        .ok_or("missing id")?,
                    email: v["email"].as_str().ok_or("missing email")?.to_string(),
                    name: v["name"].as_str().map(String::from),
                    image: v["avatar_url"].as_str().map(String::from),
                    email_verified: true,
                })
            },
        }
    }

    pub fn discord(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://discord.com/api/oauth2/authorize".to_string(),
            token_url: "https://discord.com/api/oauth2/token".to_string(),
            user_info_url: "https://discord.com/api/users/@me".to_string(),
            scopes: vec!["identify".to_string(), "email".to_string()],
            map_user_info: |v| {
                Ok(OAuthUserInfo {
                    id: v["id"].as_str().ok_or("missing id")?.to_string(),
                    email: v["email"].as_str().ok_or("missing email")?.to_string(),
                    name: v["username"].as_str().map(String::from),
                    image: v["avatar"].as_str().map(|a| {
                        format!(
                            "https://cdn.discordapp.com/avatars/{}/{}.png",
                            v["id"].as_str().unwrap_or(""),
                            a
                        )
                    }),
                    email_verified: v["verified"].as_bool().unwrap_or(false),
                })
            },
        }
    }
}
