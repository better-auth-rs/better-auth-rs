use serde::{Deserialize, Serialize};
use validator::Validate;

use better_auth_core::entity::AuthApiKey;

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
    #[validate(length(min = 1, message = "Key ID is required"))]
    pub id: String,
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
    #[serde(rename = "expiresIn")]
    pub expires_in: Option<i64>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct DeleteKeyRequest {
    #[validate(length(min = 1, message = "Key ID is required"))]
    pub id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct VerifyKeyRequest {
    pub key: String,
    pub permissions: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct ApiKeyView {
    pub id: String,
    pub name: Option<String>,
    pub start: Option<String>,
    pub prefix: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "refillInterval")]
    pub refill_interval: Option<i64>,
    #[serde(rename = "refillAmount")]
    pub refill_amount: Option<i64>,
    #[serde(rename = "lastRefillAt")]
    pub last_refill_at: Option<String>,
    pub enabled: bool,
    #[serde(rename = "rateLimitEnabled")]
    pub rate_limit_enabled: bool,
    #[serde(rename = "rateLimitTimeWindow")]
    pub rate_limit_time_window: Option<i64>,
    #[serde(rename = "rateLimitMax")]
    pub rate_limit_max: Option<i64>,
    #[serde(rename = "requestCount")]
    pub request_count: Option<i64>,
    pub remaining: Option<i64>,
    #[serde(rename = "lastRequest")]
    pub last_request: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    pub permissions: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateKeyResponse {
    pub key: String,
    #[serde(flatten)]
    pub api_key: ApiKeyView,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyKeyResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<VerifyErrorBody>,
    pub key: Option<ApiKeyView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyErrorBody {
    pub message: String,
    pub code: String,
}

impl ApiKeyView {
    pub fn from_entity(ak: &impl AuthApiKey) -> Self {
        Self {
            id: ak.id().to_string(),
            name: ak.name().map(|s| s.to_string()),
            start: ak.start().map(|s| s.to_string()),
            prefix: ak.prefix().map(|s| s.to_string()),
            user_id: ak.user_id().to_string(),
            refill_interval: ak.refill_interval(),
            refill_amount: ak.refill_amount(),
            last_refill_at: ak.last_refill_at().map(|s| s.to_string()),
            enabled: ak.enabled(),
            rate_limit_enabled: ak.rate_limit_enabled(),
            rate_limit_time_window: ak.rate_limit_time_window(),
            rate_limit_max: ak.rate_limit_max(),
            request_count: ak.request_count(),
            remaining: ak.remaining(),
            last_request: ak.last_request().map(|s| s.to_string()),
            expires_at: ak.expires_at().map(|s| s.to_string()),
            created_at: ak.created_at().to_string(),
            updated_at: ak.updated_at().to_string(),
            permissions: ak.permissions().and_then(|s| serde_json::from_str(s).ok()),
            metadata: ak.metadata().and_then(|s| serde_json::from_str(s).ok()),
        }
    }
}
