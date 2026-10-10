//! # Better Auth API
//!
//! Plugin implementations for the Better Auth authentication framework.

#![cfg_attr(
    test,
    allow(
        unused_results,
        unreachable_pub,
        reason = "test code intentionally discards setup return values and exposes helpers broadly"
    )
)]

#[cfg(all(
    feature = "native-tls",
    any(feature = "rustls", feature = "rustls-no-provider")
))]
compile_error!(
    "features `native-tls` and `rustls` are mutually exclusive. \
     Enable exactly one of them: \
     for `native-tls` (default), remove the `rustls` feature; \
     for `rustls`, set `default-features = false, features = [\"rustls\"]`."
);

#[cfg(not(any(
    feature = "native-tls",
    feature = "rustls",
    feature = "rustls-no-provider"
)))]
compile_error!(
    "one of the TLS backends must be enabled: \
     enable `native-tls` (default), `rustls`, or `rustls-no-provider`."
);

pub mod plugins;

pub use plugins::account_management::AccountManagementPlugin;
pub use plugins::api_key::{ApiKeyConfig, ApiKeyPlugin};
pub use plugins::device_authorization::DeviceAuthorizationPlugin;
pub use plugins::email_password::EmailPasswordPlugin;
pub use plugins::email_verification::EmailVerificationPlugin;
pub use plugins::oauth::OAuthPlugin;
pub use plugins::passkey::{PasskeyConfig, PasskeyPlugin};
pub use plugins::password_management::PasswordManagementPlugin;
pub use plugins::session_management::SessionManagementPlugin;
pub use plugins::two_factor::TwoFactorPlugin;
