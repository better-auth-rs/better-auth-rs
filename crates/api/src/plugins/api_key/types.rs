pub(crate) use better_auth_core::wire::ApiKeyView;
use serde::{Deserialize, Serialize};
use validator::Validate;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct CreateKeyRequest {
    pub name: Option<String>,
    pub prefix: Option<String>,
    #[serde(rename = "expiresIn")]
    pub expires_in: Option<i64>,
    pub remaining: Option<i64>,
    #[serde(rename = "rateLimitEnabled")]
    pub rate_limit_enabled: Option<bool>,
    #[serde(rename = "rateLimitTimeWindow")]
    pub rate_limit_time_window: Option<i64>,
    #[serde(rename = "rateLimitMax")]
    pub rate_limit_max: Option<i64>,
    #[serde(rename = "refillInterval")]
    pub refill_interval: Option<i64>,
    #[serde(rename = "refillAmount")]
    pub refill_amount: Option<i64>,
    pub permissions: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct UpdateKeyRequest {
    #[serde(rename = "keyId")]
    #[validate(length(min = 1, message = "Key ID is required"))]
    pub key_id: String,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub remaining: Option<i64>,
    #[serde(rename = "rateLimitEnabled")]
    pub rate_limit_enabled: Option<bool>,
    #[serde(rename = "rateLimitTimeWindow")]
    pub rate_limit_time_window: Option<i64>,
    #[serde(rename = "rateLimitMax")]
    pub rate_limit_max: Option<i64>,
    #[serde(rename = "refillInterval")]
    pub refill_interval: Option<i64>,
    #[serde(rename = "refillAmount")]
    pub refill_amount: Option<i64>,
    pub permissions: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    /// `None` = not sent, `Some(None)` = sent as null (clear expiration),
    /// `Some(Some(n))` = sent with a value in seconds.
    #[serde(
        default,
        rename = "expiresIn",
        with = "::serde_with::rust::double_option"
    )]
    pub expires_in: Option<Option<i64>>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct DeleteKeyRequest {
    #[serde(rename = "keyId")]
    #[validate(length(min = 1, message = "Key ID is required"))]
    pub key_id: String,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct CreateKeyResponse {
    pub key: String,
    #[serde(flatten)]
    pub api_key: ApiKeyView,
}
