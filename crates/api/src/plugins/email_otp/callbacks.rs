use super::{EmailOtpMessage, EmailOtpPlugin, EmailOtpType};
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{AuthPlugin, AuthResult, AuthSchema};
use std::{future::Future, pin::Pin, sync::Arc};

/// Borrowing callback future; callbacks can use the active typed store directly.
pub type EmailOtpCallbackFuture<'a> = Pin<Box<dyn Future<Output = AuthResult<()>> + Send + 'a>>;
type Sender<S> = dyn for<'a> Fn(&'a EmailOtpMessage, &'a EndpointContext<'_, S>) -> EmailOtpCallbackFuture<'a>
    + Send
    + Sync;
type Generator<S> =
    dyn Fn(&str, EmailOtpType, &EndpointContext<'_, S>) -> AuthResult<Option<String>> + Send + Sync;

/// Email OTP callbacks with the complete endpoint context.
pub struct EmailOtpCallbacks<S: AuthSchema> {
    pub(super) sender: Option<Arc<Sender<S>>>,
    pub(super) generator: Option<Arc<Generator<S>>>,
}
impl<S: AuthSchema> Default for EmailOtpCallbacks<S> {
    fn default() -> Self {
        Self {
            sender: None,
            generator: None,
        }
    }
}
impl<S: AuthSchema> EmailOtpCallbacks<S> {
    /// Deliver OTPs with parsed input and access to the active typed runtime.
    pub fn send<F>(mut self, callback: F) -> Self
    where
        F: for<'a> Fn(
                &'a EmailOtpMessage,
                &'a EndpointContext<'_, S>,
            ) -> EmailOtpCallbackFuture<'a>
            + Send
            + Sync
            + 'static,
    {
        self.sender = Some(Arc::new(callback));
        self
    }
    /// Generate OTPs synchronously; `None` or an empty code selects decimal generation.
    pub fn generate<F>(mut self, callback: F) -> Self
    where
        F: Fn(&str, EmailOtpType, &EndpointContext<'_, S>) -> AuthResult<Option<String>>
            + Send
            + Sync
            + 'static,
    {
        self.generator = Some(Arc::new(callback));
        self
    }
}
impl EmailOtpPlugin {
    /// Attach schema-aware callbacks after configuring the plugin options.
    pub fn callbacks<S: AuthSchema>(self, callbacks: EmailOtpCallbacks<S>) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
}

/// Whether the active OTP plugin replaces default email verification delivery.
pub(crate) fn overrides_verification(ctx: &better_auth_core::AuthContext<impl AuthSchema>) -> bool {
    ctx.extensions
        .get::<super::EmailOtpConfig>()
        .is_some_and(|config| config.override_default_email_verification)
}

pub(crate) async fn send_verification_override(
    email: &str,
    request: Option<&better_auth_core::AuthRequest>,
    ctx: &better_auth_core::AuthContext<impl AuthSchema>,
) -> AuthResult<()> {
    let config = ctx
        .extensions
        .get::<super::EmailOtpConfig>()
        .ok_or_else(|| {
            better_auth_core::AuthError::config("Email OTP override is not configured")
        })?;
    let plugin = EmailOtpPlugin::with_config(config.clone());
    let email = email.to_lowercase();
    let kind = EmailOtpType::EmailVerification;
    let mut endpoint = EndpointContext::new(
        request,
        serde_json::json!({"email":email,"type":"email-verification"}),
        ctx,
    );
    endpoint.path = Some("/email-otp/send-verification-otp");
    let result = async {
        let otp = plugin.resolve_otp(&endpoint, &email, kind).await?;
        if ctx.database.get_user_by_email(&email).await?.is_none() {
            ctx.database
                .delete_verification_by_identifier(&kind.identifier(&email))
                .await?;
            return Ok(());
        }
        plugin.deliver(&endpoint, &email, otp, kind).await
    }
    .await;
    // The upstream override invokes the complete OTP endpoint through runInBackgroundOrAwait.
    if let Err(error) = result {
        better_auth_core::observability::logger::current().error(
            "Failed to run background task",
            &[
                better_auth_core::observability::LogArgument::Value(&serde_json::json!(
                    "email-otp"
                )),
                better_auth_core::observability::LogArgument::Error(&error),
            ],
        );
    }
    Ok(())
}
