pub(crate) use better_auth_core::wire::ApiKeyView;
use better_auth_core::{AuthRequest, AuthResponse};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use validator::Validate;

/// API key creation parameters for HTTP and trusted server callers.
#[serde_with::skip_serializing_none]
#[derive(Debug, Default, Deserialize, Serialize)]
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
#[derive(Debug, Default, Deserialize, Serialize)]
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

/// Parse with the DTO schema and retain the field path in upstream validation errors.
pub(crate) fn parse_api_key_body<T>(request: &AuthRequest) -> Result<T, AuthResponse>
where
    T: serde::de::DeserializeOwned + Validate,
{
    let mut deserializer =
        serde_json::Deserializer::from_slice(request.body.as_deref().unwrap_or(b"null"));
    let body: T = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        let mut path = error.path().to_string().replace('[', ".").replace(']', "");
        if path == "." {
            path.clear();
        }
        let detail = error.inner().to_string();
        let message = if let Some(field) = detail
            .strip_prefix("missing field `")
            .and_then(|rest| rest.split('`').next())
        {
            path = field.to_string();
            "Invalid input: expected string, received undefined".to_string()
        } else if let Some((received, expected)) = detail
            .strip_prefix("invalid type: ")
            .and_then(|detail| detail.split_once(", expected "))
        {
            let expected = expected.split(" at line ").next().unwrap_or(expected);
            let expected = match expected {
                "a string" => "string",
                "a boolean" => "boolean",
                "f64" => "number",
                "a sequence" => "array",
                "a map" => "record",
                _ => "object",
            };
            let received = if received.starts_with("string") {
                "string"
            } else if received.starts_with("integer") || received.starts_with("floating point") {
                "number"
            } else if received.starts_with("boolean") {
                "boolean"
            } else {
                match received {
                    "sequence" => "array",
                    "map" => "object",
                    value => value,
                }
            };
            format!("Invalid input: expected {expected}, received {received}")
        } else {
            detail
        };
        let location = if path.is_empty() {
            "body".to_string()
        } else {
            format!("body.{path}")
        };
        validation_response(&location, &message)
    })?;
    deserializer
        .end()
        .map_err(|error| validation_response("body", &error.to_string()))?;
    body.validate()
        .map_err(|error| better_auth_core::validation_error_response(&error))?;
    Ok(body)
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

fn numeric_errors(
    fields: &[(&'static str, Option<f64>, Option<f64>)],
) -> validator::ValidationErrors {
    let mut errors = validator::ValidationErrors::new();
    for &(field, value, minimum) in fields {
        let Some(value) = value else {
            continue;
        };
        let message = if !value.is_finite() {
            Some("Invalid input: expected number, received number".to_string())
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

#[derive(Debug, Deserialize, Validate)]
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
    fn js_string(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::String(value) => value.clone(),
            serde_json::Value::Array(values) => values
                .iter()
                .map(|value| {
                    if value.is_null() {
                        String::new()
                    } else {
                        js_string(value)
                    }
                })
                .collect::<Vec<_>>()
                .join(","),
            serde_json::Value::Object(_) => "[object Object]".to_string(),
            value => value.to_string(),
        }
    }
    serde_json::Value::deserialize(deserializer).map(|value| Some(js_string(&value)))
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
#[derive(Debug, Default)]
pub(crate) struct ListKeysQuery {
    pub config_id: Option<String>,
    pub organization_id: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
}

impl ListKeysQuery {
    pub(crate) fn from_request(req: &AuthRequest) -> Result<Self, AuthResponse> {
        let number = |key: &str| -> Result<Option<usize>, AuthResponse> {
            let Some(value) = req.query.get(key) else {
                return Ok(None);
            };
            let parsed = if value.trim().is_empty() {
                0.0
            } else {
                value
                    .trim()
                    .parse::<f64>()
                    .map_err(|_| query_error(key, "Invalid input: expected number, received NaN"))?
            };
            if !parsed.is_finite() {
                return Err(query_error(
                    key,
                    if parsed.is_nan() {
                        "Invalid input: expected number, received NaN"
                    } else {
                        "Invalid input: expected number, received number"
                    },
                ));
            }
            if parsed.fract() != 0.0 {
                return Err(query_error(
                    key,
                    "Invalid input: expected int, received number",
                ));
            }
            if parsed < 0.0 {
                return Err(query_error(key, "Too small: expected number to be >=0"));
            }
            Ok(Some(parsed as usize))
        };
        if let Some(direction) = req.query.get("sortDirection")
            && !matches!(direction.as_str(), "asc" | "desc")
        {
            return Err(query_error(
                "sortDirection",
                "Invalid option: expected one of \"asc\"|\"desc\"",
            ));
        }
        Ok(Self {
            config_id: req.query.get("configId").cloned(),
            organization_id: req.query.get("organizationId").cloned(),
            limit: number("limit")?,
            offset: number("offset")?,
            sort_by: req.query.get("sortBy").cloned(),
            sort_direction: req.query.get("sortDirection").cloned(),
        })
    }
}

fn query_error(field: &str, message: &str) -> AuthResponse {
    validation_response(&format!("query.{field}"), message)
}

fn validation_response(location: &str, message: &str) -> AuthResponse {
    let body = better_auth_core::ErrorCodeMessageResponse {
        message: format!("[{location}] {message}"),
        code: Some("VALIDATION_ERROR".to_owned()),
    };
    AuthResponse::json(400, &body).unwrap_or_else(|_| AuthResponse::text(400, &body.message))
}

/// Paginated API key response; absent pagination parameters are omitted.
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

/// Newly issued API key. The plaintext key is only returned during creation.
#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    /// Plaintext secret to deliver to the key holder.
    pub key: String,
    /// Stored public key attributes, without the secret hash.
    #[serde(flatten)]
    pub api_key: ApiKeyView,
}
