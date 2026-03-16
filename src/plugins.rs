//! Built-in plugins and plugin-specific configuration modules.

pub use better_auth_api::OAuthPlugin;
pub use better_auth_api::plugins::email_verification::SendVerificationEmail;
pub use better_auth_api::plugins::password_management::SendResetPassword;
pub use better_auth_api::plugins::user_management::SendChangeEmailConfirmation;
pub use better_auth_api::plugins::{
    AccountManagementPlugin, AdminConfig, AdminPlugin, ApiKeyConfig, ApiKeyPlugin,
    ChangeEmailConfig, DeleteUserConfig, EmailPasswordConfig, EmailPasswordPlugin,
    EmailVerificationConfig, EmailVerificationHook, EmailVerificationPlugin, OrganizationConfig,
    OrganizationPlugin, PasskeyConfig, PasskeyPlugin, PasswordManagementConfig,
    PasswordManagementPlugin, SessionManagementPlugin, TwoFactorConfig, TwoFactorPlugin,
    UserManagementConfig, UserManagementPlugin, account_management, admin, api_key, email_password,
    email_verification, oauth, organization, passkey, password_management, session_management,
    two_factor, user_management,
};
