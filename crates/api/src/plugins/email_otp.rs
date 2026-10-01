//! Email OTP authentication compatible with Better Auth's `emailOTP` plugin.

use async_trait::async_trait;
use better_auth_core::{AuthContext, AuthRequest, AuthResponse, AuthResult};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(crate) mod callbacks;
pub use callbacks::{EmailOtpCallbackFuture, EmailOtpCallbacks};
mod handlers;
mod native;
mod otp;
pub use native::EmailOtpApi;
mod request;

/// Purpose of an email OTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EmailOtpType {
    /// Prove ownership of an email before signing in.
    SignIn,
    /// Mark an existing user's email as verified.
    EmailVerification,
    /// Reset the credential password.
    ForgetPassword,
    /// Verify the destination of an authenticated email change.
    ChangeEmail,
}

impl EmailOtpType {
    fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "sign-in",
            Self::EmailVerification => "email-verification",
            Self::ForgetPassword => "forget-password",
            Self::ChangeEmail => "change-email",
        }
    }
    fn identifier(self, email: &str) -> String {
        format!("{}-otp-{email}", self.as_str())
    }
}

/// Message delivered by the application's OTP sender.
#[derive(Debug, Clone, Serialize)]
pub struct EmailOtpMessage {
    /// Normalized recipient email.
    pub email: String,
    /// Plain OTP sent to the mailbox owner.
    pub otp: String,
    /// Verification purpose.
    #[serde(rename = "type")]
    pub kind: EmailOtpType,
}

/// Application-owned delivery of email OTPs.
#[async_trait]
pub trait SendEmailOtp: Send + Sync {
    /// Deliver an OTP; the plugin logs delivery errors like upstream background tasks.
    async fn send(&self, message: &EmailOtpMessage) -> AuthResult<()>;
}

/// OTP persistence protection.
#[derive(Clone, Default)]
pub enum EmailOtpStorage {
    /// Store the code unchanged, matching the upstream default.
    #[default]
    Plain,
    /// Store a SHA-256 digest. Resends cannot recover this code.
    Hashed,
    /// Encrypt with the auth secret before persistence.
    Encrypted,
    /// Application-owned irreversible hashing.
    CustomHash(super::one_time_token::TokenHasher),
    /// Application-owned reversible encryption.
    CustomEncryption(Arc<dyn EmailOtpCodec>),
}

/// Application encryption and decryption for stored OTPs.
#[async_trait]
pub trait EmailOtpCodec: Send + Sync {
    /// Encrypt an OTP for persistence.
    async fn encode(&self, otp: &str) -> AuthResult<String>;
    /// Decrypt a stored OTP. Propagate invalid ciphertext and application failures.
    async fn decode(&self, stored: &str) -> AuthResult<String>;
}

/// Application generator for deterministic or custom-format codes.
pub type EmailOtpGenerator = Arc<dyn Fn(&str, EmailOtpType) -> Option<String> + Send + Sync>;

/// Options for email OTP routes.
#[derive(Clone, better_auth_core::PluginConfig)]
#[plugin(name = "EmailOtpPlugin")]
pub struct EmailOtpConfig {
    /// OTP delivery callback; requests fail when no sender is configured.
    #[config(default = None)]
    pub sender: Option<Arc<dyn SendEmailOtp>>,
    /// Number of decimal digits in a generated OTP. Default: 6.
    #[config(default = 6)]
    pub otp_length: usize,
    /// OTP validity and resend extension. Default: 5 minutes.
    #[config(default = Duration::seconds(300))]
    pub expires_in: Duration,
    /// Failed code attempts before the next check locks the code. Zero means 3.
    #[config(default = 3)]
    pub allowed_attempts: u32,
    /// Prevent email OTP from creating a new user.
    #[config(default = false)]
    pub disable_sign_up: bool,
    /// Enable authenticated email changes.
    #[config(default = false)]
    pub change_email: bool,
    /// Require the current mailbox's verification OTP before email changes.
    #[config(default = false)]
    pub verify_current_email: bool,
    /// Reuse a valid recoverable code and extend its expiry on resend.
    #[config(default = false)]
    pub reuse_otp: bool,
    /// Stored code protection. Default: plain.
    #[config(default = EmailOtpStorage::Plain)]
    pub storage: EmailOtpStorage,
    /// Generate a custom OTP. Empty output uses the decimal generator.
    #[config(default = None)]
    pub generate_otp: Option<EmailOtpGenerator>,
    /// Send a verification OTP after successful sign-up.
    #[config(default = false)]
    pub send_verification_on_sign_up: bool,
    /// Replace default email verification messages with OTP delivery.
    #[config(default = false)]
    pub override_default_email_verification: bool,
    /// Endpoint rate limit window. Zero means 60 seconds.
    #[config(default = 60.0)]
    pub rate_limit_window: f64,
    /// Endpoint rate limit maximum. Zero means 3.
    #[config(default = 3.0)]
    pub rate_limit_max: f64,
}

/// Email OTP plugin with all nine public upstream routes.
pub struct EmailOtpPlugin {
    config: EmailOtpConfig,
}

better_auth_core::impl_auth_plugin! {
    EmailOtpPlugin, "email-otp";
    routes {
        post "/email-otp/send-verification-otp" => send, "sendEmailVerificationOTP";
        post "/email-otp/check-verification-otp" => check, "verifyEmailWithOTP";
        post "/email-otp/verify-email" => verify_email, "verifyEmailOTP";
        post "/sign-in/email-otp" => sign_in, "signInWithEmailOTP";
        post "/email-otp/request-password-reset" => request_password_reset, "requestPasswordResetWithEmailOTP";
        post "/forget-password/email-otp" => request_password_reset, "forgetPasswordWithEmailOTP";
        post "/email-otp/reset-password" => reset_password, "resetPasswordWithEmailOTP";
        post "/email-otp/request-email-change" => request_email_change, "requestEmailChangeWithEmailOTP";
        post "/email-otp/change-email" => handle_change_email, "changeEmailWithEmailOTP";
    }
    extra {
        async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
            ctx.extensions.insert(self.config.clone());
            Ok(())
        }
        fn rate_limits(&self) -> AuthResult<Vec<better_auth_core::middleware::PluginRateLimit>> {
            let window = self.config.rate_limit_window;
            let max = self.config.rate_limit_max;
            let rule = better_auth_core::middleware::EndpointRateLimit {
                window: if window == 0.0 || window.is_nan() { 60.0 } else { window },
                max_requests: if max == 0.0 || max.is_nan() { 3.0 } else { max },
            };
            Ok(<Self as better_auth_core::AuthPlugin<S>>::routes(self).into_iter()
                .map(|route| better_auth_core::middleware::PluginRateLimit::exact(route.path, rule)).collect())
        }

        async fn after_request(&self, req: &AuthRequest, response: &mut AuthResponse, ctx: &AuthContext<S>) -> AuthResult<()> {
            if self.config.send_verification_on_sign_up && !self.config.override_default_email_verification && req.path().starts_with("/sign-up") && response.status == 200 {
                let body: serde_json::Value = serde_json::from_slice(&response.body)?;
                if let Some(email) = body.get("user").and_then(|user| user.get("email")).and_then(serde_json::Value::as_str) {
                    let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(Some(req), req.body_as_json()?, ctx);
                    endpoint.response = Some(response);
                    let otp = self.create_otp(&endpoint, email, EmailOtpType::EmailVerification, &EmailOtpType::EmailVerification.identifier(email)).await?;
                    self.deliver(&endpoint, email, otp, EmailOtpType::EmailVerification).await?;
                }
            }
            Ok(())
        }
    }
}
