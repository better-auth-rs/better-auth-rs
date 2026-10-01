use super::{EmailOtpMessage, EmailOtpPlugin, EmailOtpType};
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::background::{BackgroundFuture, run_or_await};
use better_auth_core::{AuthPlugin, AuthResult, AuthSchema};
use std::sync::Arc;

type Sender<S> = dyn Fn(&EmailOtpMessage, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
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
    /// Construct delivery work after persisting the OTP. Factory errors propagate immediately.
    /// Retain the endpoint with `to_owned` when delivery uses its runtime or transaction.
    pub fn send<F>(mut self, callback: F) -> Self
    where
        F: Fn(&EmailOtpMessage, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
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
    endpoint: &EndpointContext<'_, impl AuthSchema>,
) -> AuthResult<()> {
    let ctx = endpoint.auth;
    let config = ctx
        .extensions
        .get::<super::EmailOtpConfig>()
        .ok_or_else(|| {
            better_auth_core::AuthError::config("Email OTP override is not configured")
        })?;
    let plugin = EmailOtpPlugin::with_config(config.clone());
    let email = email.to_lowercase();
    let kind = EmailOtpType::EmailVerification;
    let owned = endpoint.to_owned();
    let request_context =
        better_auth_core::hooks::current_request_hook_context().map(|mut context| {
            context.path = Some("/email-otp/send-verification-otp".into());
            context.body = Some(serde_json::json!({"email":email,"type":"email-verification"}));
            context.params.clear();
            context
        });
    let task = Box::pin(async move {
        let operation = async {
            let mut endpoint = owned.as_endpoint();
            endpoint.body = serde_json::json!({"email":email,"type":"email-verification"});
            endpoint.path = Some("/email-otp/send-verification-otp");
            // The upstream override starts from its captured init context, not the caller's resolved session or response.
            endpoint.session = None;
            endpoint.response = None;
            endpoint.params.clear();
            let otp = plugin.resolve_otp(&endpoint, &email, kind).await?;
            let user = match endpoint.transaction {
                Some(transaction) => transaction.get_user_by_email(&email).await?,
                None => endpoint.auth.database.get_user_by_email(&email).await?,
            };
            if user.is_none() {
                let identifier = kind.identifier(&email);
                match endpoint.transaction {
                    Some(transaction) => {
                        transaction
                            .delete_verification_by_identifier(&identifier)
                            .await?
                    }
                    None => {
                        endpoint
                            .auth
                            .database
                            .delete_verification_by_identifier(&identifier)
                            .await?
                    }
                }
                return Ok(());
            }
            plugin.deliver(&endpoint, &email, otp, kind).await
        };
        match request_context {
            Some(context) => {
                better_auth_core::hooks::with_request_hook_context_value(context, operation).await
            }
            None => operation.await,
        }
    });
    // The upstream override invokes the complete OTP endpoint through runInBackgroundOrAwait.
    run_or_await(
        Some(task),
        ctx.config.advanced.background_tasks.as_ref(),
        &ctx.config.logger,
    )
    .await;
    Ok(())
}
