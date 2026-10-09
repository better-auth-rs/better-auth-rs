use super::EmailVerificationPlugin;
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{
    AuthPlugin, AuthResult, AuthSchema, FieldValue, background::BackgroundFuture, wire::UserView,
};
use std::sync::Arc;

/// Email verification delivery data.
#[derive(Clone)]
pub struct VerificationEmail {
    /// User snapshot supplied by the verification lifecycle.
    pub user: FieldValue,
    /// Complete verification link, including the token.
    pub url: String,
    /// Verification token for application-specific delivery.
    pub token: String,
}
impl VerificationEmail {
    /// Read object fields through native Rust slots at an application boundary.
    pub fn user_view(&self) -> AuthResult<UserView> {
        let fields = self.user.as_object().ok_or_else(|| {
            better_auth_core::AuthError::internal("Verification User must be an object")
        })?;
        UserView::try_from(fields.clone())
    }
}
type Sender<S> = dyn Fn(&VerificationEmail, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
    + Send
    + Sync;

/// Verification delivery with the complete endpoint and active transaction.
pub struct EmailVerificationCallbacks<S: AuthSchema> {
    pub(super) sender: Arc<Sender<S>>,
}
impl<S: AuthSchema> EmailVerificationCallbacks<S> {
    /// Invoke delivery before background scheduling. Return `None` for synchronous completion.
    /// Use `EndpointContext::to_owned` when the returned future needs its transaction.
    pub fn send(
        callback: impl Fn(
            &VerificationEmail,
            &EndpointContext<'_, S>,
        ) -> AuthResult<Option<BackgroundFuture>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            sender: Arc::new(callback),
        }
    }
}
impl EmailVerificationPlugin {
    /// Attach typed delivery callbacks after configuring the verification options.
    pub fn callbacks<S: AuthSchema>(
        self,
        callbacks: EmailVerificationCallbacks<S>,
    ) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
}
