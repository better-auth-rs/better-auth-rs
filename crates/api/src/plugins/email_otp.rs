//! Email OTP authentication compatible with Better Auth's `emailOTP` plugin.

use async_trait::async_trait;
use better_auth_core::{AuthContext, AuthRequest, AuthResponse, AuthResult};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

mod handlers;
mod otp;
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
    /// Application-owned hashing or reversible encryption.
    Custom(Arc<dyn EmailOtpCodec>),
}

/// Custom OTP protection compatible with upstream hash or encrypt/decrypt callbacks.
#[async_trait]
pub trait EmailOtpCodec: Send + Sync {
    /// Hash or encrypt an OTP for persistence.
    async fn encode(&self, otp: &str) -> AuthResult<String>;
    /// Decrypt stored codes; return `None` for irreversible hashing.
    async fn decode(&self, stored: &str) -> AuthResult<Option<String>>;
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
    #[config(default = 60)]
    pub rate_limit_window: u64,
    /// Endpoint rate limit maximum. Zero means 3.
    #[config(default = 3)]
    pub rate_limit_max: u32,
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
            if self.config.override_default_email_verification {
                ctx.email_verification_policy.override_sender = Some(Arc::new(otp::VerificationSender {
                    config: self.config.clone(),
                    context: AuthContext::new(ctx.config.clone(), ctx.database.clone()),
                }));
            }
            Ok(())
        }
        fn rate_limits(&self) -> AuthResult<Vec<(String, better_auth_core::middleware::EndpointRateLimit)>> {
            let window = if self.config.rate_limit_window == 0 { 60 } else { self.config.rate_limit_window };
            let max = if self.config.rate_limit_max == 0 { 3 } else { self.config.rate_limit_max };
            Ok(<Self as better_auth_core::AuthPlugin<S>>::routes(self).into_iter().map(|route| (route.path, better_auth_core::middleware::EndpointRateLimit { window: std::time::Duration::from_secs(window), max_requests: max })).collect())
        }

        async fn after_request(&self, req: &AuthRequest, response: &mut AuthResponse, ctx: &AuthContext<S>) -> AuthResult<()> {
            if self.config.send_verification_on_sign_up && !self.config.override_default_email_verification && req.path().starts_with("/sign-up") && response.status == 200 {
                let body: serde_json::Value = serde_json::from_slice(&response.body)?;
                if let Some(email) = body.get("user").and_then(|user| user.get("email")).and_then(serde_json::Value::as_str) {
                    let otp = self.create_otp(ctx, email, EmailOtpType::EmailVerification, &EmailOtpType::EmailVerification.identifier(email)).await?;
                    self.deliver(email, otp, EmailOtpType::EmailVerification).await?;
                }
            }
            Ok(())
        }
    }
}
