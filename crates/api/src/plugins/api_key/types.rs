use better_auth_core::AuthRequest;
pub(crate) use better_auth_core::wire::ApiKeyView;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use validator::Validate;

/// API key creation parameters for HTTP and trusted server callers.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeyRequest {
    /// Configuration to use, or the default configuration when absent.
    #[serde(default, deserialize_with = "present")]
    pub config_id: Option<String>,
    /// User authorizing a server-side creation; HTTP clients must omit this field.
    #[serde(default, deserialize_with = "coerced_string")]
    pub user_id: Option<String>,
    /// Organization owning the key when the configuration references organizations.
    #[serde(default, deserialize_with = "coerced_string")]
    pub organization_id: Option<String>,
    /// Display name for the key.
    #[serde(default, deserialize_with = "present")]
    pub name: Option<String>,
    /// Prefix prepended to the generated key.
    #[serde(default, deserialize_with = "present")]
    pub prefix: Option<String>,
    /// Lifetime in seconds; null or absence uses the configured default.
    pub expires_in: Option<f64>,
    /// Remaining uses, available only to trusted server callers.
    pub remaining: Option<f64>,
    /// Enable rate limiting for this key, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub rate_limit_enabled: Option<bool>,
    /// Rate limit window in milliseconds, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub rate_limit_time_window: Option<f64>,
    /// Requests per window, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub rate_limit_max: Option<f64>,
    /// Refill interval in milliseconds, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub refill_interval: Option<f64>,
    /// Uses restored per refill, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub refill_amount: Option<f64>,
    /// Resource permissions, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub permissions: Option<HashMap<String, Vec<String>>>,
    /// Optional metadata; preservation of null matches the upstream wire contract.
    #[serde(default, deserialize_with = "present")]
    pub metadata: Option<serde_json::Value>,
}

/// API key updates for HTTP and trusted server callers.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateKeyRequest {
    /// Configuration used to locate the key.
    #[serde(default, deserialize_with = "present")]
    pub config_id: Option<String>,
    /// Identifier of the key to update.
    pub key_id: String,
    /// User authorizing a server-side update, or the current session user over HTTP.
    #[serde(default, deserialize_with = "coerced_string")]
    pub user_id: Option<String>,
    /// Replacement display name.
    #[serde(default, deserialize_with = "present")]
    pub name: Option<String>,
    /// Whether the key can authenticate requests.
    #[serde(default, deserialize_with = "present")]
    pub enabled: Option<bool>,
    /// Replacement remaining uses, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub remaining: Option<f64>,
    /// Enable rate limiting, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub rate_limit_enabled: Option<bool>,
    /// Replacement rate limit window in milliseconds, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub rate_limit_time_window: Option<f64>,
    /// Replacement requests per window, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub rate_limit_max: Option<f64>,
    /// Replacement refill interval in milliseconds, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub refill_interval: Option<f64>,
    /// Replacement uses per refill, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub refill_amount: Option<f64>,
    /// Replacement resource permissions; null clears permissions. Server callers only.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub permissions: Option<Option<HashMap<String, Vec<String>>>>,
    /// Replacement metadata; null clears metadata when metadata is enabled.
    #[serde(default, deserialize_with = "present")]
    pub metadata: Option<serde_json::Value>,
    /// Absent leaves expiration unchanged, null clears expiration, and a value sets seconds from now.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub expires_in: Option<Option<f64>>,
}

impl Validate for CreateKeyRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let mut errors = numeric_errors(&[
            ("expiresIn", self.expires_in, Some(1.0)),
            ("remaining", self.remaining, Some(0.0)),
            ("refillAmount", self.refill_amount, Some(1.0)),
            ("refillInterval", self.refill_interval, None),
            ("rateLimitTimeWindow", self.rate_limit_time_window, None),
            ("rateLimitMax", self.rate_limit_max, None),
        ]);
        if let Some(prefix) = self.prefix.as_deref()
            && let Err(error) = validate_prefix(prefix)
        {
            errors.add("prefix", error);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Validate for UpdateKeyRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let errors = numeric_errors(&[
            ("expiresIn", self.expires_in.flatten(), Some(1.0)),
            ("remaining", self.remaining, Some(1.0)),
            ("refillAmount", self.refill_amount, None),
            ("refillInterval", self.refill_interval, None),
            ("rateLimitTimeWindow", self.rate_limit_time_window, None),
            ("rateLimitMax", self.rate_limit_max, None),
        ]);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

pub(super) fn nonfinite_number_error(value: f64) -> String {
    let received = if value.is_nan() {
        "NaN"
    } else if value.is_sign_negative() {
        "-Infinity"
    } else {
        "Infinity"
    };
    format!("Invalid input: expected number, received {received}")
}

fn numeric_errors(
    fields: &[(&'static str, Option<f64>, Option<f64>)],
) -> validator::ValidationErrors {
    let mut errors = validator::ValidationErrors::new();
    for &(field, value, minimum) in fields {
        let Some(value) = value else {
            continue;
        };
        let message = if !value.is_finite() {
            Some(nonfinite_number_error(value))
        } else {
            minimum
                .filter(|minimum| value < *minimum)
                .map(|minimum| format!("Too small: expected number to be >={minimum}"))
        };
        if let Some(message) = message {
            let mut error = validator::ValidationError::new("range");
            error.message = Some(message.into());
            errors.add(field, error);
        }
    }
    errors
}

#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeleteKeyRequest {
    #[serde(default, deserialize_with = "present")]
    pub config_id: Option<String>,
    pub key_id: String,
}

/// Deserialize an explicitly supplied value without treating null as an absent field.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn coerced_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    better_auth_core::SchemaValue::<String>::from_json(Some(value))
        .and_then(|value| value.display_string())
        .map(Some)
        .map_err(serde::de::Error::custom)
}

fn validate_prefix(prefix: &str) -> Result<(), validator::ValidationError> {
    if !prefix.is_empty()
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Ok(())
    } else {
        let mut error = validator::ValidationError::new("regex");
        error.message = Some(
            "Invalid prefix format, must be alphanumeric and contain only underscores and hyphens."
                .into(),
        );
        Err(error)
    }
}

/// Query parameters accepted by `GET /api-key/list`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListKeysQuery {
    pub config_id: Option<String>,
    pub organization_id: Option<String>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
}

impl ListKeysQuery {
    pub(crate) fn from_request(req: &AuthRequest) -> better_auth_core::AuthResult<Self> {
        crate::plugins::query_input::parse(&req.query)
    }
}

/// Paginated API key response; absent pagination parameters are omitted.
#[derive(Debug, Serialize)]
pub(crate) struct ListKeysResponse {
    #[serde(rename = "apiKeys")]
    pub api_keys: Vec<ApiKeyView>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

/// Newly issued API key. The plaintext key is only returned during creation.
#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    /// Plaintext secret to deliver to the key holder.
    pub key: String,
    /// Stored public key attributes, without the secret hash.
    #[serde(flatten)]
    pub api_key: ApiKeyView,
}
