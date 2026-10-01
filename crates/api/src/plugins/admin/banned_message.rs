//! Banned-user messages resolved before session creation.

use better_auth_core::{AuthResult, wire::UserView};
use std::{fmt, future::Future, pin::Pin, sync::Arc};

/// A message callback may borrow the stored user while awaiting application work.
pub type BannedUserMessageFuture<'a> =
    Pin<Box<dyn Future<Output = AuthResult<String>> + Send + 'a>>;
type MessageCallback = dyn for<'a> Fn(&'a UserView) -> BannedUserMessageFuture<'a> + Send + Sync;

/// Fixed text or an asynchronous message generated from the stored user.
#[derive(Clone)]
pub enum BannedUserMessage {
    /// Reuse this message for every active ban.
    Text(String),
    /// Resolve the message before rejecting session creation.
    Callback(Arc<MessageCallback>),
}

impl BannedUserMessage {
    /// Build a callback that can inspect private application user fields.
    pub fn callback<F>(callback: F) -> Self
    where
        F: for<'a> Fn(&'a UserView) -> BannedUserMessageFuture<'a> + Send + Sync + 'static,
    {
        Self::Callback(Arc::new(callback))
    }

    pub(crate) async fn resolve(&self, user: &UserView) -> AuthResult<String> {
        match self {
            Self::Text(message) => Ok(message.clone()),
            Self::Callback(callback) => callback(user).await.map_err(|error| {
                if better_auth_core::hooks::current_request_hook_context()
                    .is_some_and(|ctx| ctx.is_http)
                    && error.status_code() == 500
                    && !matches!(
                        error,
                        better_auth_core::AuthError::Response(_)
                            | better_auth_core::AuthError::Upstream { .. }
                    )
                {
                    tracing::error!(%error, "Admin banned-user message callback failed");
                    better_auth_core::AuthResponse::new(500).into()
                } else {
                    error
                }
            }),
        }
    }
}

impl Default for BannedUserMessage {
    fn default() -> Self {
        Self::Text("You have been banned from this application. Please contact support if you believe this is an error.".into())
    }
}

impl From<String> for BannedUserMessage {
    fn from(message: String) -> Self {
        Self::Text(message)
    }
}
impl From<&str> for BannedUserMessage {
    fn from(message: &str) -> Self {
        Self::Text(message.into())
    }
}
impl fmt::Debug for BannedUserMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(message) => formatter.debug_tuple("Text").field(message).finish(),
            Self::Callback(_) => formatter.write_str("Callback(..)"),
        }
    }
}
