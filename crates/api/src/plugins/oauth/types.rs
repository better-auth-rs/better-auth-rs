use better_auth_core::wire::UserView;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct SocialSignInRequest {
    #[validate(length(min = 1, message = "Provider is required"))]
    pub provider: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL")]
    pub new_user_callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    #[serde(rename = "disableRedirect")]
    pub disable_redirect: Option<bool>,
    #[serde(rename = "idToken")]
    pub id_token: Option<OAuthIdTokenRequest>,
    #[serde(rename = "requestSignUp")]
    pub request_sign_up: Option<bool>,
    #[serde(rename = "loginHint")]
    pub login_hint: Option<String>,
    #[serde(rename = "additionalData")]
    pub additional_data: Option<serde_json::Map<String, serde_json::Value>>,
    pub scopes: Option<Vec<String>>,
    #[serde(rename = "additionalParams")]
    pub additional_params: Option<IndexMap<String, String>>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct LinkSocialRequest {
    #[validate(length(min = 1, message = "Provider is required"))]
    pub provider: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    #[serde(rename = "disableRedirect")]
    pub disable_redirect: Option<bool>,
    #[serde(rename = "idToken")]
    pub id_token: Option<OAuthIdTokenRequest>,
    #[serde(rename = "requestSignUp")]
    pub request_sign_up: Option<bool>,
    #[serde(rename = "loginHint")]
    pub login_hint: Option<String>,
    #[serde(rename = "additionalData")]
    pub additional_data: Option<serde_json::Map<String, serde_json::Value>>,
    pub scopes: Option<Vec<String>>,
    #[serde(rename = "additionalParams")]
    pub additional_params: Option<IndexMap<String, String>>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct OAuthIdTokenRequest {
    #[validate(length(min = 1, message = "Token is required"))]
    pub token: String,
    pub nonce: Option<String>,
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<i64>,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SocialSignInResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub redirect: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AccessTokenResponse {
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(
        rename = "accessTokenExpiresAt",
        skip_serializing_if = "Option::is_none"
    )]
    pub access_token_expires_at: Option<String>,
    pub scopes: Vec<String>,
    #[serde(rename = "idToken", skip_serializing_if = "Option::is_none")]
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
    #[serde(
        rename = "refreshTokenExpiresAt",
        skip_serializing_if = "better_auth_core::SchemaValue::is_undefined"
    )]
    pub refresh_token_expires_at: better_auth_core::SchemaValue<Option<String>>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub scope: better_auth_core::SchemaValue<Option<String>>,
    #[serde(
        rename = "idToken",
        skip_serializing_if = "better_auth_core::SchemaValue::is_undefined"
    )]
    pub id_token: better_auth_core::SchemaValue<Option<String>>,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "accountId", skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AccountInfoUser {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<Option<String>>,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountInfoAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub provider_id: String,
    pub account_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct AccountInfoResponse {
    pub user: AccountInfoUser,
    pub data: serde_json::Value,
    pub account: AccountInfoAccount,
}
