use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct SocialSignInRequest {
    #[validate(length(min = 1, message = "Provider is required"))]
    pub provider: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LinkSocialRequest {
    #[validate(length(min = 1, message = "Provider is required"))]
    pub provider: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct GetAccessTokenRequest {
    #[validate(length(min = 1, message = "Provider ID is required"))]
    #[serde(rename = "providerId")]
    pub provider_id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RefreshTokenRequest {
    #[validate(length(min = 1, message = "Provider ID is required"))]
    #[serde(rename = "providerId")]
    pub provider_id: String,
}

#[derive(Debug, Serialize)]
pub struct SocialSignInResponse {
    pub url: String,
    pub redirect: bool,
}

#[derive(Debug, Serialize)]
pub struct OAuthCallbackResponse<U: Serialize> {
    pub token: String,
    pub user: U,
}

#[derive(Debug, Serialize)]
pub struct AccessTokenResponse {
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "accessTokenExpiresAt")]
    pub access_token_expires_at: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RefreshTokenResponse {
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "accessTokenExpiresAt")]
    pub access_token_expires_at: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}
