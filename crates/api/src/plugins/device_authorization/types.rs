use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DeviceCodeRequest {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DeviceTokenRequest {
    pub grant_type: String,
    pub device_code: String,
    pub client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DeviceActionRequest {
    #[serde(rename = "userCode")]
    pub user_code: String,
}

#[derive(Debug, Serialize)]
pub(super) struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

#[derive(Debug, Serialize)]
pub(super) struct DeviceTokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub scope: String,
}

#[derive(Debug, Serialize)]
pub(super) struct DeviceVerifyResponse {
    pub user_code: String,
    pub status: String,
    #[serde(flatten)]
    pub review: Option<DeviceReviewContext>,
}

#[derive(Debug, Serialize)]
pub(super) struct DeviceReviewContext {
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub client_id: better_auth_core::SchemaValue<Option<String>>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_undefined")]
    pub scope: better_auth_core::SchemaValue<Option<String>>,
}

#[derive(Debug, Serialize)]
pub(super) struct DeviceActionResponse {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct DeviceErrorResponse {
    pub error: String,
    pub error_description: String,
}
