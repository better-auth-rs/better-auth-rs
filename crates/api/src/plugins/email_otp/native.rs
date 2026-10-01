use super::{EmailOtpConfig, EmailOtpPlugin, EmailOtpType};
use crate::plugins::endpoint_context::EndpointContext;
use better_auth_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthVerification};

/// Trusted server operations using the registered Email OTP plugin configuration.
/// These methods have no HTTP routes and never send email.
pub struct EmailOtpApi<'a, S: AuthSchema> {
    plugin: EmailOtpPlugin,
    context: &'a AuthContext<S>,
    transaction: Option<&'a dyn better_auth_core::store::AuthTransaction<S>>,
}
impl<'a, S: AuthSchema> EmailOtpApi<'a, S> {
    /// Bind to an initialized context. Callback wrappers use the same registered configuration.
    pub fn from_context(context: &'a AuthContext<S>) -> AuthResult<Self> {
        let config = context
            .extensions
            .get::<EmailOtpConfig>()
            .ok_or_else(|| AuthError::config("EmailOtpPlugin is not registered"))?;
        Ok(Self {
            plugin: EmailOtpPlugin::with_config(config.clone()),
            context,
            transaction: None,
        })
    }

    /// Bind native OTP operations to the endpoint's active database transaction.
    pub fn from_endpoint(endpoint: &EndpointContext<'a, S>) -> AuthResult<Self> {
        let mut api = Self::from_context(endpoint.auth)?;
        api.transaction = endpoint.transaction;
        Ok(api)
    }

    /// Generate and store a new code even when resend reuse is enabled.
    /// The email is lowercased but is not required to have email syntax or an existing user.
    pub async fn create(&self, email: &str, kind: EmailOtpType) -> AuthResult<String> {
        let mut endpoint = EndpointContext::new(
            None,
            serde_json::json!({"email":email,"type":kind}),
            self.context,
        );
        endpoint.path = Some("virtual:");
        endpoint.transaction = self.transaction;
        let email = email.to_lowercase();
        self.plugin
            .create_otp(&endpoint, &email, kind, &kind.identifier(&email))
            .await
    }

    /// Read a live plaintext or decrypted code without consuming it or changing attempts.
    /// Live hashed codes return an error; missing or expired codes return `None` first.
    pub async fn get(&self, email: &str, kind: EmailOtpType) -> AuthResult<Option<String>> {
        let identifier = kind.identifier(&email.to_lowercase());
        let record = match self.transaction {
            Some(transaction) => {
                transaction
                    .get_verification_including_expired(&identifier)
                    .await?
            }
            None => {
                self.context
                    .database
                    .get_verification_including_expired(&identifier)
                    .await?
            }
        };
        let Some(record) = record else {
            return Ok(None);
        };
        if record.expires_at() < chrono::Utc::now() {
            return Ok(None);
        }
        let (stored, _) = super::otp::split(record.value());
        self.plugin
            .recover(stored, self.context.config.encryption_secret())
            .await?
            .map(Some)
            .ok_or_else(|| {
                AuthError::bad_request("OTP is hashed, cannot return the plain text OTP")
            })
    }
}
