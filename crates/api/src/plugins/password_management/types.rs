use serde::{Deserialize, Deserializer, Serialize};
use validator::Validate;

/// Request body for `POST /request-password-reset`.
#[derive(Debug, Deserialize, Validate)]
pub(crate) struct RequestPasswordResetRequest {
    #[validate(email(message = "Invalid email address"))]
    pub(crate) email: String,
    #[serde(rename = "redirectTo")]
    pub(crate) redirect_to: Option<String>,
}

/// Request body for `POST /reset-password`.
#[derive(Debug, Deserialize, Validate)]
pub(crate) struct ResetPasswordRequest {
    #[serde(rename = "newPassword")]
    #[validate(length(min = 1, message = "New password is required"))]
    pub(crate) new_password: String,
    pub(crate) token: Option<String>,
}

/// Query parameters for `POST /reset-password`.
#[cfg_attr(
    not(feature = "axum"),
    expect(dead_code, reason = "used by the axum handler query extractor")
)]
#[derive(Debug, Deserialize)]
pub(crate) struct ResetPasswordQuery {
    pub(crate) token: Option<String>,
}

/// Request body for `POST /change-password`.
#[derive(Debug, Deserialize, Validate)]
pub(crate) struct ChangePasswordRequest {
    #[serde(rename = "newPassword")]
    #[validate(length(min = 1, message = "New password is required"))]
    pub(crate) new_password: String,
    #[serde(rename = "currentPassword")]
    #[validate(length(min = 1, message = "Current password is required"))]
    pub(crate) current_password: String,
    #[serde(
        default,
        rename = "revokeOtherSessions",
        deserialize_with = "deserialize_bool_or_string"
    )]
    pub(crate) revoke_other_sessions: Option<bool>,
}

/// Query parameters for `GET /reset-password/{token}`.
#[derive(Debug, Deserialize)]
pub(crate) struct ResetPasswordTokenQuery {
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

/// Deserialize a value that can be either a boolean or a string ("true"/"false") into Option<bool>.
/// This is needed because the better-auth TypeScript SDK sends `revokeOtherSessions` as a boolean,
/// while some clients may send it as a string.
fn deserialize_bool_or_string<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    let value: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(serde_json::Value::Bool(b)) => Ok(Some(b)),
        Some(serde_json::Value::String(s)) => match s.to_lowercase().as_str() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            _ => Err(serde::de::Error::custom(format!(
                "invalid value for revokeOtherSessions: {}",
                s
            ))),
        },
        Some(other) => Err(serde::de::Error::custom(format!(
            "invalid type for revokeOtherSessions: {}",
            other
        ))),
    }
}

/// Response body for `POST /request-password-reset`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RequestPasswordResetResponse {
    pub(crate) status: bool,
    pub(crate) message: String,
}

/// Response body for `POST /change-password`.
#[derive(Debug, Serialize)]
pub(crate) struct ChangePasswordResponse<U: Serialize> {
    pub(crate) token: Option<String>,
    pub(crate) user: U,
}

/// Result of the reset-password-token core function.
pub(crate) enum ResetPasswordTokenResult {
    Redirect(String),
}
