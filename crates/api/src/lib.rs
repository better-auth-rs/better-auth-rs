//! # Better Auth API
//!
//! Plugin implementations for the Better Auth authentication framework.

#[cfg(all(feature = "native-tls", feature = "rustls"))]
compile_error!(
    "features `native-tls` and `rustls` are mutually exclusive. \
     Enable exactly one of them: \
     for `native-tls` (default), remove the `rustls` feature; \
     for `rustls`, set `default-features = false, features = [\"rustls\"]`."
);

#[cfg(not(any(feature = "native-tls", feature = "rustls")))]
compile_error!(
    "one of the TLS backends must be enabled: \
     enable either the `native-tls` (default) or `rustls` feature."
);

pub mod plugins;

pub use plugins::account_management::AccountManagementPlugin;
pub use plugins::api_key::{ApiKeyConfig, ApiKeyPlugin};
pub use plugins::device_authorization::{DeviceAuthorizationConfig, DeviceAuthorizationPlugin};
pub use plugins::email_password::EmailPasswordPlugin;
pub use plugins::email_verification::EmailVerificationPlugin;
pub use plugins::oauth::OAuthPlugin;
pub use plugins::passkey::{PasskeyConfig, PasskeyPlugin};
pub use plugins::password_management::PasswordManagementPlugin;
pub use plugins::session_management::SessionManagementPlugin;
pub use plugins::two_factor::TwoFactorPlugin;
