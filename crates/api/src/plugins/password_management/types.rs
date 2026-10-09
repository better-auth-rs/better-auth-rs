use serde::{Deserialize, Serialize};
use validator::Validate;

/// Request body for `POST /request-password-reset`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub(crate) struct RequestPasswordResetRequest {
    #[validate(email(message = "Invalid email address"))]
    pub(crate) email: String,
    #[serde(rename = "redirectTo")]
    pub(crate) redirect_to: Option<String>,
}

/// Request body for `POST /reset-password`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub(crate) struct ResetPasswordRequest {
    #[serde(rename = "newPassword")]
    #[validate(length(min = 1, message = "New password is required"))]
    pub(crate) new_password: String,
    pub(crate) token: Option<String>,
}

/// Request body for `POST /change-password`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub(crate) struct ChangePasswordRequest {
    #[serde(rename = "newPassword")]
    #[validate(length(min = 1, message = "New password is required"))]
    pub(crate) new_password: String,
    #[serde(rename = "currentPassword")]
    #[validate(length(min = 1, message = "Current password is required"))]
    pub(crate) current_password: String,
    #[serde(rename = "revokeOtherSessions")]
    pub(crate) revoke_other_sessions: Option<bool>,
}

/// Request body for `POST /verify-password`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub(crate) struct VerifyPasswordRequest {
    pub(crate) password: String,
}

/// Query parameters for `GET /reset-password/{token}`.
#[derive(Debug, Deserialize)]
pub(crate) struct ResetPasswordTokenQuery {
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
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
    #[serde(
        with = "better_auth_core::field_value::serde::value",
        skip_serializing_if = "better_auth_core::FieldValue::is_json_omitted"
    )]
    pub(crate) token: better_auth_core::FieldValue,
    pub(crate) user: U,
}

/// Result of the reset-password-token core function.
pub(crate) enum ResetPasswordTokenResult {
    Redirect(String),
}
