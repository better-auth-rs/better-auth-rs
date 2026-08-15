pub(crate) use better_auth_core::wire::ApiKeyView;
use serde::{Deserialize, Serialize};
use validator::Validate;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct CreateKeyRequest {
    /// Which api-key configuration to create under; the default when absent.
    #[serde(rename = "configId")]
    pub config_id: Option<String>,
    /// Owning organization, required when the configuration references
    /// organizations.
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
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
    /// Which api-key configuration the key belongs to.
    #[serde(rename = "configId")]
    pub config_id: Option<String>,
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
    /// Which api-key configuration the key belongs to.
    #[serde(rename = "configId")]
    pub config_id: Option<String>,
    #[serde(rename = "keyId")]
    #[validate(length(min = 1, message = "Key ID is required"))]
    pub key_id: String,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Query parameters accepted by `GET /api-key/list`.
#[derive(Debug, Default)]
pub(crate) struct ListKeysQuery {
    pub config_id: Option<String>,
    /// List organization-owned keys instead of the caller's own.
    pub organization_id: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
}

impl ListKeysQuery {
    pub(crate) fn from_request(req: &better_auth_core::AuthRequest) -> Self {
        let number = |key: &str| req.query.get(key).and_then(|value| value.parse().ok());
        Self {
            config_id: req.query.get("configId").cloned(),
            organization_id: req.query.get("organizationId").cloned(),
            limit: number("limit"),
            offset: number("offset"),
            sort_by: req.query.get("sortBy").cloned(),
            sort_direction: req.query.get("sortDirection").cloned(),
        }
    }
}

/// `GET /api-key/list` response. Upstream returns a paginated envelope rather
/// than a bare array, and omits `limit`/`offset` when the client did not send
/// them.
#[derive(Debug, Serialize)]
pub(crate) struct ListKeysResponse {
    #[serde(rename = "apiKeys")]
    pub api_keys: Vec<ApiKeyView>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateKeyResponse {
    pub key: String,
    #[serde(flatten)]
    pub api_key: ApiKeyView,
}
