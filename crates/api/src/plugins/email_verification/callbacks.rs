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
        UserView::try_from(fields.snapshot_fields()?)
    }
}
type Sender<S> = dyn Fn(&VerificationEmail, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
    + Send
    + Sync;
pub(super) type Lifecycle<S> = dyn Fn(&FieldValue, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
    + Send
    + Sync;

/// Verification delivery with the complete endpoint and active transaction.
pub struct EmailVerificationCallbacks<S: AuthSchema> {
    pub(super) sender: Option<Arc<Sender<S>>>,
    pub(super) before: Option<Arc<Lifecycle<S>>>,
    pub(super) after: Option<Arc<Lifecycle<S>>>,
}
impl<S: AuthSchema> Default for EmailVerificationCallbacks<S> {
    fn default() -> Self {
        Self {
            sender: None,
            before: None,
            after: None,
        }
    }
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
            sender: Some(Arc::new(callback)),
            ..Self::default()
        }
    }

    /// Run before verification mutates the User. Returned work completes before the mutation.
    pub fn before(
        mut self,
        callback: impl Fn(&FieldValue, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.before = Some(Arc::new(callback));
        self
    }

    /// Run after verification mutates the User. Cancellation preserves the upstream null User.
    pub fn after(
        mut self,
        callback: impl Fn(&FieldValue, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.after = Some(Arc::new(callback));
        self
    }

    pub(crate) fn has_sender(&self) -> bool {
        self.sender.is_some()
    }
    pub(crate) fn has_before(&self) -> bool {
        self.before.is_some()
    }
    pub(crate) fn has_after(&self) -> bool {
        self.after.is_some()
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
