//! Built-in plugins and plugin-specific configuration modules.

pub use better_auth_api::plugins::captcha;
pub use better_auth_api::plugins::captcha::{CaptchaPlugin, CaptchaProvider};
pub use better_auth_api::plugins::endpoint_context;
pub use better_auth_api::plugins::have_i_been_pwned;
pub use better_auth_api::plugins::have_i_been_pwned::{
    HaveIBeenPwnedConfig, HaveIBeenPwnedPlugin, PasswordCompromiseClient, is_password_compromised,
};
pub use better_auth_api::plugins::user_admission;
pub use better_auth_api::plugins::{OpenApiConfig, OpenApiPlugin, open_api};

pub use better_auth_api::plugins::{
    CustomSessionCallback, CustomSessionInput, CustomSessionPlugin, custom_session,
};

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
pub use better_auth_api::plugins::{
    EmailOtpApi, EmailOtpCodec, EmailOtpConfig, EmailOtpGenerator, EmailOtpMessage, EmailOtpPlugin,
    EmailOtpStorage, EmailOtpType, MagicLinkConfig, MagicLinkMessage, MagicLinkPlugin,
    MultiSessionConfig, MultiSessionPlugin, OneTimeTokenConfig, OneTimeTokenPlugin, SendEmailOtp,
    SendMagicLink, TokenStorage, email_otp, magic_link, multi_session, one_time_token,
};
pub use better_auth_api::plugins::{
    JwtAdapterFuture, JwtAlgorithm, JwtApi, JwtAudience, JwtCallOverrides, JwtCallbackFuture,
    JwtCallbacks, JwtCustomSign, JwtDefinePayload, JwtExpiration, JwtGetSubject, JwtKeyOptions,
    JwtKeyPairConfig, JwtPlugin, JwtPluginConfig, JwtSigningOptions, JwtTokenOptions, jwt,
};
pub use better_auth_api::plugins::{OAuthPopupPlugin, OAuthProxyConfig, OAuthProxyPlugin};
pub use better_auth_api::plugins::{OneTapConfig, OneTapPlugin, one_tap};

pub use anonymous::AnonymousPlugin;
pub use better_auth_api::plugins::{anonymous, phone_number, siwe};
pub use phone_number::PhoneNumberPlugin;
pub use siwe::SiwePlugin;

pub use better_auth_api::plugins::last_login_method::{
    self, BeforeStoreLastLoginCookie, LastLoginMethodConfig, LastLoginMethodPlugin,
    LastLoginMethodResolver,
};

pub use better_auth_api::plugins::username::{
    self, UsernameConfig, UsernameNormalization, UsernameNormalizer, UsernamePlugin,
    UsernameValidationOrder, UsernameValidator,
};

pub use better_auth_api::plugins::test_utils::{self, TestUtilsApi, TestUtilsPlugin};
