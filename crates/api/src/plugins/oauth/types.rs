use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct SocialSignInRequest {
    #[validate(length(min = 1, message = "Provider is required"))]
    pub provider: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct LinkSocialRequest {
    #[validate(length(min = 1, message = "Provider is required"))]
    pub provider: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct GetAccessTokenRequest {
    #[validate(length(min = 1, message = "Provider ID is required"))]
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "accountId")]
    pub account_id: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct RefreshTokenRequest {
    #[validate(length(min = 1, message = "Provider ID is required"))]
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "accountId")]
    pub account_id: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SocialSignInResponse {
    pub url: String,
    pub redirect: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct OAuthCallbackResponse<U: Serialize> {
    pub token: String,
    pub user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct AccessTokenResponse {
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "accessTokenExpiresAt")]
    pub access_token_expires_at: Option<String>,
    pub scopes: Vec<String>,
    #[serde(rename = "idToken")]
    pub id_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RefreshTokenResponse {
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "accessTokenExpiresAt")]
    pub access_token_expires_at: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "refreshTokenExpiresAt")]
    pub refresh_token_expires_at: Option<String>,
    pub scope: Option<String>,
    #[serde(rename = "idToken")]
    pub id_token: Option<String>,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "accountId")]
    pub account_id: String,
}
