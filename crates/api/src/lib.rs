//! # Better Auth API
//!
//! Plugin implementations for the Better Auth authentication framework.

pub mod plugins;

pub use plugins::account_management::AccountManagementPlugin;
pub use plugins::api_key::{ApiKeyConfig, ApiKeyPlugin};
pub use plugins::email_password::EmailPasswordPlugin;
pub use plugins::email_verification::EmailVerificationPlugin;
pub use plugins::oauth::OAuthPlugin;
pub use plugins::password_management::PasswordManagementPlugin;
pub use plugins::session_management::SessionManagementPlugin;
pub use plugins::two_factor::TwoFactorPlugin;
