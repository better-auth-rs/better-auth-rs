use serde::{Deserialize, Serialize};

/// The validated and normalized request passed to a configured Device grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationRequest {
    /// Declared additional request fields after validation.
    #[serde(default, flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    /// Optional only when a grant supplies request authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// User to pre-bind through the existing native request field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Requested native scope after empty-value normalization.
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
    pub expires_in: better_auth_core::SchemaValue<f64>,
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
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
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
