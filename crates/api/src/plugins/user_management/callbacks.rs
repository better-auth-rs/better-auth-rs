use super::UserManagementPlugin;
use crate::plugins::{
    email_verification::VerificationEmail,
    endpoint_context::{EndpointContext, WithCallbacks},
};
use better_auth_core::{AuthPlugin, AuthResult, AuthSchema, background::BackgroundFuture};
use std::sync::Arc;

/// Confirmation sent to the current address before a verified user changes email.
#[derive(Clone)]
pub struct ChangeEmailConfirmation {
    /// Current session user, before the email change.
    pub user: better_auth_core::wire::UserView,
    /// Requested new address.
    pub new_email: String,
    /// Confirmation URL.
    pub url: String,
    /// Signed confirmation token.
    pub token: String,
}
type Sender<S, M> =
    dyn Fn(&M, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>> + Send + Sync;

/// User notification factories with the complete endpoint and original Request.
/// Return `None` for synchronous completion or an owned future for background scheduling.
pub struct UserManagementCallbacks<S: AuthSchema> {
    pub(super) confirmation: Option<Arc<Sender<S, ChangeEmailConfirmation>>>,
    pub(super) deletion: Option<Arc<Sender<S, VerificationEmail>>>,
}
impl<S: AuthSchema> Default for UserManagementCallbacks<S> {
    fn default() -> Self {
        Self {
            confirmation: None,
            deletion: None,
        }
    }
}
impl<S: AuthSchema> UserManagementCallbacks<S> {
    pub(crate) fn has_confirmation_sender(&self) -> bool {
        self.confirmation.is_some()
    }

    /// Use the existing configured senders until a factory overrides each delivery path.
    pub fn new() -> Self {
        Self::default()
    }

    /// Send confirmation to the current address of a verified user.
    pub fn change_email_confirmation(
        mut self,
        callback: impl Fn(
            &ChangeEmailConfirmation,
            &EndpointContext<'_, S>,
        ) -> AuthResult<Option<BackgroundFuture>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.confirmation = Some(Arc::new(callback));
        self
    }

    /// Send account deletion confirmation after the verification record is stored.
    pub fn delete_account_verification(
        mut self,
        callback: impl Fn(
            &VerificationEmail,
            &EndpointContext<'_, S>,
        ) -> AuthResult<Option<BackgroundFuture>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.deletion = Some(Arc::new(callback));
        self
    }
}
impl UserManagementPlugin {
    /// Attach typed notification factories after configuring user management.
    pub fn callbacks<S: AuthSchema>(
        self,
        callbacks: UserManagementCallbacks<S>,
    ) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
}
