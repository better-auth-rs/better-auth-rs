use super::{PhoneNumberPlugin, PhoneOtp, PhoneVerification};
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{AuthPlugin, AuthResult, AuthSchema, background::BackgroundFuture};
use std::{future::Future, pin::Pin, sync::Arc};

/// Borrowing future for phone callbacks with access to the active typed store.
pub type PhoneCallbackFuture<'a, T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send + 'a>>;
type OtpCallback<S, T> = dyn for<'a> Fn(&'a PhoneOtp, &'a EndpointContext<'_, S>) -> PhoneCallbackFuture<'a, T>
    + Send
    + Sync;
type Sender<S> = dyn Fn(&PhoneOtp, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
    + Send
    + Sync;
type VerifiedCallback<S> = dyn for<'a> Fn(&'a PhoneVerification, &'a EndpointContext<'_, S>) -> PhoneCallbackFuture<'a, ()>
    + Send
    + Sync;

/// Phone callbacks with parsed endpoint input and the complete authentication runtime.
pub struct PhoneNumberCallbacks<S: AuthSchema> {
    pub(super) send: Option<Arc<Sender<S>>>,
    pub(super) reset: Option<Arc<Sender<S>>>,
    pub(super) verify: Option<Arc<OtpCallback<S, bool>>>,
    pub(super) verified: Option<Arc<VerifiedCallback<S>>>,
}
impl<S: AuthSchema> Default for PhoneNumberCallbacks<S> {
    fn default() -> Self {
        Self {
            send: None,
            reset: None,
            verify: None,
            verified: None,
        }
    }
}
impl<S: AuthSchema> PhoneNumberCallbacks<S> {
    /// Start verification delivery. Return `None` for synchronous completion.
    /// Retain the endpoint with `to_owned` when asynchronous delivery needs its context.
    pub fn send_otp<F>(mut self, callback: F) -> Self
    where
        F: Fn(&PhoneOtp, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
            + Send
            + Sync
            + 'static,
    {
        self.send = Some(Arc::new(callback));
        self
    }
    /// Start password reset delivery. Return `None` for synchronous completion.
    pub fn send_password_reset_otp<F>(mut self, callback: F) -> Self
    where
        F: Fn(&PhoneOtp, &EndpointContext<'_, S>) -> AuthResult<Option<BackgroundFuture>>
            + Send
            + Sync
            + 'static,
    {
        self.reset = Some(Arc::new(callback));
        self
    }
    /// Verify a code using an external provider.
    pub fn verify_otp<F>(mut self, callback: F) -> Self
    where
        F: for<'a> Fn(&'a PhoneOtp, &'a EndpointContext<'_, S>) -> PhoneCallbackFuture<'a, bool>
            + Send
            + Sync
            + 'static,
    {
        self.verify = Some(Arc::new(callback));
        self
    }
    /// Observe the persisted user before a session is created.
    pub fn on_verification<F>(mut self, callback: F) -> Self
    where
        F: for<'a> Fn(
                &'a PhoneVerification,
                &'a EndpointContext<'_, S>,
            ) -> PhoneCallbackFuture<'a, ()>
            + Send
            + Sync
            + 'static,
    {
        self.verified = Some(Arc::new(callback));
        self
    }
}
#[derive(Clone, Copy)]
pub(super) enum Delivery {
    Verification,
    PasswordReset,
}
impl PhoneNumberPlugin {
    /// Attach schema-aware callbacks after configuring the plugin options.
    pub fn callbacks<S: AuthSchema>(
        self,
        callbacks: PhoneNumberCallbacks<S>,
    ) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
    pub(super) fn has_sender<S: AuthSchema>(
        &self,
        ctx: &better_auth_core::AuthContext<S>,
        kind: Delivery,
    ) -> bool {
        let callbacks = ctx.extensions.get::<Arc<PhoneNumberCallbacks<S>>>();
        match kind {
            Delivery::Verification => {
                self.send_otp.is_some()
                    || callbacks.is_some_and(|callbacks| callbacks.send.is_some())
            }
            Delivery::PasswordReset => {
                self.send_password_reset_otp.is_some()
                    || callbacks.is_some_and(|callbacks| callbacks.reset.is_some())
            }
        }
    }
    pub(super) fn delivery<S: AuthSchema>(
        &self,
        otp: PhoneOtp,
        endpoint: &EndpointContext<'_, S>,
        kind: Delivery,
    ) -> AuthResult<Option<BackgroundFuture>> {
        let callbacks = endpoint
            .auth
            .extensions
            .get::<Arc<PhoneNumberCallbacks<S>>>();
        let (typed, legacy) = match kind {
            Delivery::Verification => (
                callbacks.and_then(|callbacks| callbacks.send.as_ref()),
                self.send_otp.as_ref(),
            ),
            Delivery::PasswordReset => (
                callbacks.and_then(|callbacks| callbacks.reset.as_ref()),
                self.send_password_reset_otp.as_ref(),
            ),
        };
        if let Some(callback) = typed {
            callback(&otp, endpoint)
        } else if let Some(callback) = legacy {
            let request = endpoint.request.ok_or_else(|| {
                better_auth_core::AuthError::config("Legacy phone callbacks require a request")
            })?;
            Ok(Some(callback(otp, request.clone())))
        } else {
            Err(super::error(
                501,
                "SEND_OTP_NOT_IMPLEMENTED",
                "sendOTP not implemented",
            ))
        }
    }
    pub(super) async fn notify_verified<S: AuthSchema>(
        &self,
        data: PhoneVerification,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<()> {
        if let Some(callback) = endpoint
            .auth
            .extensions
            .get::<Arc<PhoneNumberCallbacks<S>>>()
            .and_then(|callbacks| callbacks.verified.as_ref())
        {
            callback(&data, endpoint).await?;
        } else if let Some(callback) = &self.callback_on_verification {
            let request = endpoint.request.ok_or_else(|| {
                better_auth_core::AuthError::config("Legacy phone callbacks require a request")
            })?;
            callback(data, request.clone()).await?;
        }
        Ok(())
    }
}
