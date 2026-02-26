pub mod account_management;
pub mod admin;
pub mod api_key;
pub mod email_password;
pub mod email_verification;
pub mod oauth;
pub mod organization;
pub mod passkey;
pub mod password_management;
pub mod session_management;
pub mod two_factor;
pub mod user_management;

pub use account_management::AccountManagementPlugin;
pub use admin::{AdminConfig, AdminPlugin};
pub use api_key::{ApiKeyConfig, ApiKeyPlugin};
pub use better_auth_core::PasswordHasher;
pub use email_password::{EmailPasswordConfig, EmailPasswordPlugin};
pub use email_verification::{
    EmailVerificationConfig, EmailVerificationHook, EmailVerificationPlugin, SendVerificationEmail,
};
pub use organization::{OrganizationConfig, OrganizationPlugin};
pub use passkey::{PasskeyConfig, PasskeyPlugin};
pub use password_management::{
    PasswordManagementConfig, PasswordManagementPlugin, SendResetPassword,
};
pub use session_management::SessionManagementPlugin;
pub use two_factor::{TwoFactorConfig, TwoFactorPlugin};
pub use user_management::{
    ChangeEmailConfig, DeleteUserConfig, UserManagementConfig, UserManagementPlugin,
};
