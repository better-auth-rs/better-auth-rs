use serde::Serialize;

/// Read-only projection of configured plugin capabilities before initialization.
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginTelemetry {
    pub social_providers: Vec<SocialProviderTelemetry>,
    pub email_verification: EmailVerificationTelemetry,
    pub email_and_password: EmailPasswordTelemetry,
    #[serde(skip)]
    pub send_change_email_confirmation: bool,
    #[serde(skip)]
    pub change_email_enabled: Option<bool>,
}

/// Verification options whose callback and boolean presence is retained by the plugin.
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailVerificationTelemetry {
    pub send_verification_email: bool,
    pub send_on_sign_up: bool,
    pub send_on_sign_in: bool,
    pub auto_sign_in_after_verification: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    pub before_email_verification: bool,
    pub after_email_verification: bool,
}

/// Password options whose callback and boolean presence is retained by the plugin.
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailPasswordTelemetry {
    pub enabled: bool,
    pub disable_sign_up: bool,
    pub require_email_verification: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_password_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_password_length: Option<usize>,
    pub send_reset_password: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_password_token_expires_in: Option<i64>,
    pub on_password_reset: bool,
    pub password: PasswordTelemetry,
    pub auto_sign_in: bool,
    pub revoke_sessions_on_password_reset: bool,
}

/// A configured Rust password hasher implements both hash and verification callbacks.
#[derive(Default, Serialize)]
pub struct PasswordTelemetry {
    pub hash: bool,
    pub verify: bool,
}

/// Configured social-provider inputs; callback bodies and credentials are excluded.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SocialProviderTelemetry {
    pub id: String,
    pub map_profile_to_user: bool,
    pub disable_default_scope: bool,
    pub disable_id_token_sign_in: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_implicit_sign_up: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_sign_up: Option<bool>,
    pub get_user_info: bool,
    pub override_user_info_on_sign_in: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    pub verify_id_token: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Vec<String>>,
    pub refresh_access_token: bool,
}
