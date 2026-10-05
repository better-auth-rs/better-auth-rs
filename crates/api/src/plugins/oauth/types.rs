use better_auth_core::wire::UserView;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SocialSignInRequest {
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

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LinkSocialRequest {
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

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OAuthIdTokenRequest {
    pub token: String,
    pub nonce: Option<String>,
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    pub user: Option<super::providers::OAuthCallbackUserPayload>,
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
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessTokenResponse {
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub access_token: better_auth_core::SchemaValue<Option<String>>,
    #[serde(
        skip_serializing_if = "better_auth_core::SchemaValue::is_undefined",
        serialize_with = "better_auth_core::schema_value::serialize_optional_date"
    )]
    pub access_token_expires_at:
        better_auth_core::SchemaValue<Option<chrono::DateTime<chrono::Utc>>>,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub id_token: better_auth_core::SchemaValue<Option<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshTokenResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "better_auth_core::utils::date::serialize_option"
    )]
    pub access_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub refresh_token: String,
    #[serde(
        skip_serializing_if = "better_auth_core::SchemaValue::is_undefined",
        serialize_with = "better_auth_core::schema_value::serialize_optional_date"
    )]
    pub refresh_token_expires_at:
        better_auth_core::SchemaValue<Option<chrono::DateTime<chrono::Utc>>>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub scope: better_auth_core::SchemaValue<Option<String>>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub id_token: better_auth_core::SchemaValue<Option<String>>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub provider_id: better_auth_core::SchemaValue<String>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub account_id: better_auth_core::SchemaValue<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AccountInfoUser {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub name: better_auth_core::SchemaValue<Option<String>>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub email: better_auth_core::SchemaValue<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<Option<String>>,
    #[serde(
        rename = "emailVerified",
        skip_serializing_if = "better_auth_core::SchemaValue::is_undefined"
    )]
    pub email_verified: better_auth_core::SchemaValue<Option<bool>>,
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountInfoAccount {
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub id: better_auth_core::SchemaValue<String>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub provider_id: better_auth_core::SchemaValue<String>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub account_id: better_auth_core::SchemaValue<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AccountInfoResponse {
    pub user: AccountInfoUser,
    pub data: serde_json::Value,
    pub account: AccountInfoAccount,
}
