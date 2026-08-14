//! Built-in plugins and plugin-specific configuration modules.

pub use better_auth_api::OAuthPlugin;
pub use better_auth_api::plugins::email_verification::SendVerificationEmail;
pub use better_auth_api::plugins::password_management::SendResetPassword;
pub use better_auth_api::plugins::two_factor::SendTwoFactorOtp;
pub use better_auth_api::plugins::user_management::SendChangeEmailConfirmation;
pub use better_auth_api::plugins::{
    AccountManagementPlugin, AdminConfig, AdminPlugin, ApiKeyConfig, ApiKeyPlugin,
    ChangeEmailConfig, DeleteUserConfig, DeviceAuthorizationPlugin, EmailPasswordConfig,
    EmailPasswordPlugin, EmailVerificationConfig, EmailVerificationHook, EmailVerificationPlugin,
    OrganizationConfig, OrganizationPlugin, PasskeyConfig, PasskeyPlugin, PasswordManagementConfig,
    PasswordManagementPlugin, RolePermissions, SessionManagementPlugin, TwoFactorConfig,
    TwoFactorPlugin, UserManagementConfig, UserManagementPlugin, account_management, admin,
    api_key, device_authorization, email_password, email_verification, oauth, organization,
    passkey, password_management, session_management, two_factor, user_management,
};
