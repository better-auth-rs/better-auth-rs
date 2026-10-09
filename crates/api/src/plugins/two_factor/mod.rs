use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use rand::Rng;
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use totp_rs::{Algorithm, TOTP};

use better_auth_core::entity::{AuthRecordFields, AuthSession, AuthUser};
use better_auth_core::session::NativeSessionData;
use better_auth_core::utils::cookie_utils::{
    create_clear_cookie, create_session_like_cookie, related_cookie_name,
};
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateVerification, FieldMap,
    FieldValue, RequestMeta, SchemaValue, TwoFactor, UpdateUser,
};

use crate::plugins::helpers::{
    SessionIssueError, admit_session_for_id, delete_session_cookies, get_cookie,
    get_credential_account,
};

use super::StatusResponse;
mod actions;
mod callbacks;
mod challenge;
pub use callbacks::TwoFactorCallbacks;
mod helpers;
mod native;
mod options;
mod request;
pub use native::TwoFactorApi;
pub use options::{
    BackupCodeOptions, BackupCodeStorage, TwoFactorCipher, TwoFactorHasher, TwoFactorOtpStorage,
};
mod security;
mod totp;
use actions::*;
use helpers::*;
use security::*;

#[cfg(test)]
mod enrollment_tests;
#[cfg(test)]
mod native_tests;
#[cfg(test)]
mod security_tests;
#[cfg(test)]
mod tests;

const TWO_FACTOR_COOKIE_SUFFIX: &str = "two_factor";
const TRUST_DEVICE_COOKIE_SUFFIX: &str = "trust_device";
const DONT_REMEMBER_COOKIE_SUFFIX: &str = "dont_remember";

const METADATA_ENABLED: &str = "two_factor.enabled";
const METADATA_TOTP_DISABLED: &str = "two_factor.totp_disabled";
const METADATA_OTP_ENABLED: &str = "two_factor.otp_enabled";
const DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS: f64 = 600.0;
const DEFAULT_TRUST_DEVICE_MAX_AGE_SECS: f64 = 2_592_000.0;
const DEFAULT_TOTP_PERIOD_SECS: f64 = 30.0;
const DEFAULT_TOTP_DIGITS: usize = 6;
const CHALLENGE_ATTEMPT_LIMIT: usize = 5;

type HmacSha256 = Hmac<Sha256>;

/// Callback used by the two-factor plugin to deliver a one-time password.
#[async_trait]
pub trait SendTwoFactorOtp: Send + Sync {
    /// Send a one-time password to the given user.
    async fn send(&self, user: &FieldValue, otp: &str) -> AuthResult<()>;
}

/// Two-factor authentication plugin providing TOTP, OTP, and backup code flows.
#[derive(Clone)]
pub struct TwoFactorPlugin {
    config: TwoFactorConfig,
}

/// Public configuration for the two-factor plugin.
#[derive(Clone, better_auth_core::PluginConfig)]
#[plugin(name = "TwoFactorPlugin")]
pub struct TwoFactorConfig {
    /// Permit passwordless management only when the user has no credential password.
    #[config(default = false)]
    pub allow_passwordless: bool,
    /// Disable TOTP enrollment, verification and generation.
    #[config(default = false)]
    pub totp_disabled: bool,
    /// Override passwordless policy for reading the TOTP URI.
    #[config(default = None)]
    pub totp_allow_passwordless: Option<bool>,
    /// Number of decimal digits in delivered OTPs.
    #[config(default = 6)]
    pub otp_digits: usize,
    /// Delivered OTP lifetime. Zero uses the upstream three-minute default.
    #[config(default = Duration::minutes(3))]
    pub otp_period: Duration,
    /// Failed OTP attempts before the next request consumes the exhausted code. Zero means five.
    #[config(default = 5)]
    pub otp_allowed_attempts: usize,
    /// Stored OTP representation.
    #[config(default = TwoFactorOtpStorage::Plain)]
    pub otp_storage: TwoFactorOtpStorage,
    /// Backup-code generation, storage and passwordless policy.
    #[config(default = BackupCodeOptions::default())]
    pub backup_code_options: BackupCodeOptions,
    /// Account-level protection shared by all sign-in factors and challenges.
    #[config(default = AccountLockout::default())]
    pub account_lockout: AccountLockout,
    /// Override the issuer embedded in generated TOTP URIs.
    #[config(default = None)]
    pub issuer: Option<String>,
    /// Skip the enrollment verification step and enable 2FA immediately.
    #[config(default = false)]
    pub skip_verification_on_enable: bool,
    /// Pending two-factor cookie lifetime in seconds, including fractions. Zero is preserved.
    #[config(default = DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS)]
    pub two_factor_cookie_max_age: f64,
    /// Trusted-device cookie lifetime in seconds, including fractions. Zero is preserved.
    #[config(default = DEFAULT_TRUST_DEVICE_MAX_AGE_SECS)]
    pub trust_device_max_age: f64,
    /// TOTP period in fractional seconds. Enrollment URIs preserve the configured value.
    /// Generation, verification, and URI retrieval use 30 seconds for zero or NaN.
    #[config(default = DEFAULT_TOTP_PERIOD_SECS)]
    pub totp_period: f64,
    /// TOTP digit count.
    #[config(default = DEFAULT_TOTP_DIGITS)]
    pub totp_digits: usize,
    /// Optional OTP sender callback. When absent, `/two-factor/send-otp` is disabled.
    #[config(default = None, skip)]
    pub send_otp: Option<Arc<dyn SendTwoFactorOtp>>,
}

impl std::fmt::Debug for TwoFactorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorConfig")
            .field("account_lockout", &self.account_lockout)
            .field("issuer", &self.issuer)
            .field(
                "skip_verification_on_enable",
                &self.skip_verification_on_enable,
            )
            .field("two_factor_cookie_max_age", &self.two_factor_cookie_max_age)
            .field("trust_device_max_age", &self.trust_device_max_age)
            .field("totp_period", &self.totp_period)
            .field("totp_digits", &self.totp_digits)
            .field("send_otp", &self.send_otp.as_ref().map(|_| "custom"))
            .finish()
    }
}

/// Consecutive verification failures allowed before the account is temporarily locked.
#[derive(Debug, Clone)]
pub struct AccountLockout {
    /// Enable account-level lockout.
    pub enabled: bool,
    /// Failures across factors and challenges before locking the account.
    pub max_failed_attempts: i64,
    /// Duration of the lock in seconds, including fractions. Zero is preserved.
    pub duration_seconds: f64,
}

impl Default for AccountLockout {
    fn default() -> Self {
        Self {
            enabled: true,
            max_failed_attempts: 10,
            duration_seconds: 900.0,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum EnrollmentMethod {
    Otp,
    #[default]
    Totp,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct EnableRequest {
    password: Option<String>,
    issuer: Option<String>,
    #[serde(default)]
    method: EnrollmentMethod,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DisableRequest {
    password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct GetTotpUriRequest {
    password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct VerifyTotpRequest {
    code: String,
    #[serde(rename = "trustDevice")]
    trust_device: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct VerifyOtpRequest {
    code: String,
    #[serde(rename = "trustDevice")]
    trust_device: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct GenerateBackupCodesRequest {
    password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct VerifyBackupCodeRequest {
    code: String,
    #[serde(rename = "disableSession")]
    disable_session: Option<bool>,
    #[serde(rename = "trustDevice")]
    trust_device: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct EnableResponse {
    method: &'static str,
    #[serde(rename = "totpURI", skip_serializing_if = "Option::is_none")]
    totp_uri: Option<String>,
    #[serde(rename = "backupCodes", skip_serializing_if = "Option::is_none")]
    backup_codes: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TotpUriResponse {
    #[serde(rename = "totpURI")]
    totp_uri: String,
}

#[derive(Debug)]
pub(crate) struct SessionTokenResponse {
    token: FieldValue,
    user: FieldValue,
}

impl SessionTokenResponse {
    fn into_field_value(self) -> FieldValue {
        FieldMap::from([("token".into(), self.token), ("user".into(), self.user)]).into()
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct BackupCodesResponse {
    status: bool,
    #[serde(rename = "backupCodes")]
    backup_codes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TwoFactorRedirectResponse {
    #[serde(rename = "twoFactorRedirect")]
    two_factor_redirect: bool,
    /// Second factors this user can actually complete, so the client knows
    /// which challenge to present.
    #[serde(rename = "twoFactorMethods")]
    two_factor_methods: Vec<&'static str>,
}

struct PendingTwoFactorState {
    user: UserView,
    key: String,
    dont_remember: bool,
    expires_at: SchemaValue<better_auth_core::FieldDate>,
}

enum ResolvedTwoFactorState {
    Session {
        data: Box<NativeSessionData>,
        key: String,
    },
    Pending(PendingTwoFactorState),
}

pub(crate) struct TrustedDeviceCheck {
    pub trusted: bool,
    pub set_cookie_headers: Vec<String>,
}

pub(crate) async fn inspect_trusted_device(
    req: &AuthRequest,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<TrustedDeviceCheck> {
    let cookie_name = related_cookie_name(&ctx.config, TRUST_DEVICE_COOKIE_SUFFIX);
    let Some(raw_cookie) = get_cookie(req, &cookie_name) else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: Vec::new(),
        });
    };

    let Some(signed_value) = verify_signed_cookie_value(ctx.config.signing_secret(), &raw_cookie)?
        .filter(|value| !value.is_empty())
    else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: Vec::new(),
        });
    };

    let Some((token, trust_identifier)) = signed_value.split_once('!') else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_cookie_header(
                req,
                &ctx.config,
                TRUST_DEVICE_COOKIE_SUFFIX,
            )?],
        });
    };

    let expected_token = sign_value(
        ctx.config.signing_secret(),
        &format!("{}!{}", user.id().display_string()?, trust_identifier),
    )?;
    if token != expected_token {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_cookie_header(
                req,
                &ctx.config,
                TRUST_DEVICE_COOKIE_SUFFIX,
            )?],
        });
    }

    let Some(verification) = ctx
        .database
        .get_verification_by_identifier(trust_identifier)
        .await?
    else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_cookie_header(
                req,
                &ctx.config,
                TRUST_DEVICE_COOKIE_SUFFIX,
            )?],
        });
    };

    if !verification
        .value
        .field_value()
        .strict_equals(&user.id().field_value())
        || verification.expires_at.is_before_or_equal(Utc::now())?
    {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_cookie_header(
                req,
                &ctx.config,
                TRUST_DEVICE_COOKIE_SUFFIX,
            )?],
        });
    }

    ctx.database
        .delete_verification_by_identifier(trust_identifier)
        .await?;

    let rotated_cookie = create_trust_device_cookie_header(user, ctx).await?;
    Ok(TrustedDeviceCheck {
        trusted: true,
        set_cookie_headers: vec![rotated_cookie],
    })
}

pub(crate) async fn begin_sign_in_challenge(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    headers: &mut better_auth_core::Headers,
) -> AuthResult<TwoFactorRedirectResponse> {
    let identifier = format!("2fa-{}", uuid::Uuid::new_v4());
    let max_age = two_factor_cookie_max_age(ctx);
    let expires_at = cookie_expires_at(max_age)?;
    _ = ctx
        .database
        .create_verification_optional(CreateVerification {
            identifier: (identifier.clone()).into(),
            value: user.id().into_owned(),
            expires_at: expires_at.into(),
            ..Default::default()
        })
        .await?;

    let _ = ctx
        .database
        .create_verification_optional(CreateVerification {
            identifier: (format!("2fa-attempts-{identifier}")).into(),
            value: ("0".to_owned()).into(),
            expires_at: expires_at.into(),
            ..Default::default()
        })
        .await?;

    headers.append(
        "Set-Cookie",
        create_signed_cookie_header(
            ctx.config.signing_secret(),
            &ctx.config,
            TWO_FACTOR_COOKIE_SUFFIX,
            &identifier,
            Some(max_age),
        )?,
    );

    // TOTP is per-user: only offered once the user has a stored secret. OTP is
    // server-level: offered whenever a sender is configured.
    let mut two_factor_methods = Vec::new();
    if !ctx
        .get_metadata(METADATA_TOTP_DISABLED)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        && ctx
            .database
            .get_two_factor_by_user_id_value(&user.id().into_owned())
            .await?
            .is_some_and(|factor| !factor.verified.field_value().strict_equals(&false.into()))
    {
        two_factor_methods.push("totp");
    }
    if ctx
        .get_metadata(METADATA_OTP_ENABLED)
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        two_factor_methods.push("otp");
    }

    Ok(TwoFactorRedirectResponse {
        two_factor_redirect: true,
        two_factor_methods,
    })
}

impl TwoFactorPlugin {
    /// Generate a TOTP from a supplied secret in trusted server code.
    pub fn generate_totp(&self, secret: &str) -> AuthResult<String> {
        require_totp(&self.config)?;
        totp_verifier(&self.config, secret)
            .with_default_period()
            .generate_current()
    }

    /// Install a custom OTP sender.
    pub fn custom_send_otp(mut self, sender: Arc<dyn SendTwoFactorOtp>) -> Self {
        self.config.send_otp = Some(sender);
        self
    }

    /// Read the currently stored backup codes for a user.
    ///
    /// This is the Rust server-side equivalent of the TypeScript
    /// `auth.api.viewBackupCodes` capability. It is intentionally not exposed
    /// as a public HTTP route.
    pub async fn view_backup_codes<S: better_auth_core::AuthSchema>(
        &self,
        user_id: &str,
        ctx: &AuthContext<S>,
    ) -> AuthResult<FieldValue> {
        view_backup_codes_core(user_id, &self.config.backup_code_options, ctx).await
    }
}

#[async_trait]
impl<S: better_auth_core::AuthSchema> better_auth_core::AuthPlugin<S> for TwoFactorPlugin {
    fn name(&self) -> &'static str {
        "two-factor"
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.after_sign_in(req, response, ctx).await
    }
    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        let passwordless = self.config.allow_passwordless;
        let totp_passwordless = self.config.totp_allow_passwordless.unwrap_or(passwordless);
        let backup_passwordless = self
            .config
            .backup_code_options
            .allow_passwordless
            .unwrap_or(passwordless);
        [
            ("/two-factor/enable", "enableTwoFactor", passwordless),
            ("/two-factor/disable", "disableTwoFactor", passwordless),
            ("/two-factor/get-totp-uri", "getTOTPURI", totp_passwordless),
            ("/two-factor/verify-totp", "verifyTOTP", passwordless),
            ("/two-factor/send-otp", "sendTwoFactorOTP", passwordless),
            ("/two-factor/verify-otp", "verifyTwoFactorOTP", passwordless),
            (
                "/two-factor/generate-backup-codes",
                "generateBackupCodes",
                backup_passwordless,
            ),
            (
                "/two-factor/verify-backup-code",
                "verifyBackupCode",
                passwordless,
            ),
        ]
        .into_iter()
        .map(|(path, operation, optional)| {
            better_auth_core::AuthRoute::post(path, operation)
                .body_validator(move |req| request::validate(req, optional))
        })
        .collect()
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if *req.method() != better_auth_core::HttpMethod::Post {
            return Ok(None);
        }
        let response = match req.path() {
            "/two-factor/enable" => self.handle_enable(req, ctx).await?,
            "/two-factor/disable" => self.handle_disable(req, ctx).await?,
            "/two-factor/get-totp-uri" => self.handle_get_totp_uri(req, ctx).await?,
            "/two-factor/verify-totp" => self.handle_verify_totp(req, ctx).await?,
            "/two-factor/send-otp" => self.handle_send_otp(req, ctx).await?,
            "/two-factor/verify-otp" => self.handle_verify_otp(req, ctx).await?,
            "/two-factor/generate-backup-codes" => {
                self.handle_generate_backup_codes(req, ctx).await?
            }
            "/two-factor/verify-backup-code" => self.handle_verify_backup_code(req, ctx).await?,
            _ => return Ok(None),
        };
        Ok(Some(response))
    }
    async fn on_init(
        &self,
        ctx: &mut better_auth_core::AuthInitContext<S>,
    ) -> better_auth_core::AuthResult<()> {
        let role = better_auth_core::store::schema::EntityRole::TwoFactor;
        ctx.register_model_fields(
            role,
            better_auth_core::plugin_runtime::ModelFields::plugin_native_fields(role),
        )?;
        ctx.extensions.insert(self.config.clone());
        S::User::require_plugin_fields("two-factor", &["two_factor_enabled"])?;
        ctx.register_native_user_fields(METADATA_ENABLED);
        ctx.set_metadata(METADATA_ENABLED, serde_json::Value::Bool(true));
        ctx.set_metadata(
            METADATA_TOTP_DISABLED,
            serde_json::Value::Bool(self.config.totp_disabled),
        );
        ctx.set_metadata(
            METADATA_OTP_ENABLED,
            serde_json::Value::Bool(
                self.config.send_otp.is_some()
                    || ctx
                        .extensions
                        .get::<Arc<TwoFactorCallbacks<S>>>()
                        .is_some_and(|callbacks| callbacks.sender.is_some()),
            ),
        );
        Ok(())
    }
}

impl TwoFactorPlugin {
    async fn handle_enable(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: EnableRequest = request::read(req, self.config.allow_passwordless)?;
        let data = ctx.require_native_session(req).await?;

        let (response, set_cookie_headers) =
            enable_core(req, &body, &data, &self.config, ctx).await?;
        let mut auth_response = AuthResponse::json(200, &response)?;
        for cookie in set_cookie_headers {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        Ok(auth_response)
    }

    async fn handle_disable(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: DisableRequest = request::read(req, self.config.allow_passwordless)?;
        let data = ctx.require_native_session(req).await?;

        let (response, set_cookie_headers) =
            disable_core(&body, &data, req, &self.config, ctx).await?;
        let mut auth_response = AuthResponse::json(200, &response)?;
        for cookie in set_cookie_headers {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        Ok(auth_response)
    }

    async fn handle_get_totp_uri(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: GetTotpUriRequest = request::read(
            req,
            self.config
                .totp_allow_passwordless
                .unwrap_or(self.config.allow_passwordless),
        )?;
        let data = ctx.require_native_session(req).await?;

        let response = get_totp_uri_core(&body, &data, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_verify_totp(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyTotpRequest = request::read(req, false)?;

        let (response, set_cookie_headers) =
            verify_totp_core(req, &body, &self.config, ctx).await?;
        let mut auth_response = AuthResponse::native(200, response.into_field_value());
        for cookie in set_cookie_headers {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        Ok(auth_response)
    }

    async fn handle_send_otp(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let response = send_otp_core(req, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_verify_otp(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyOtpRequest = request::read(req, false)?;

        let (response, set_cookie_headers) = verify_otp_core(req, &body, &self.config, ctx).await?;
        let mut auth_response = AuthResponse::native(200, response.into_field_value());
        for cookie in set_cookie_headers {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        Ok(auth_response)
    }

    async fn handle_generate_backup_codes(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: GenerateBackupCodesRequest = request::read(
            req,
            self.config
                .backup_code_options
                .allow_passwordless
                .unwrap_or(self.config.allow_passwordless),
        )?;
        let data = ctx.require_native_session(req).await?;

        let response = generate_backup_codes_core(&body, &data, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_verify_backup_code(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyBackupCodeRequest = request::read(req, false)?;

        let (response, set_cookie_headers) =
            verify_backup_code_core(req, &body, &self.config, ctx).await?;
        let mut auth_response = AuthResponse::native(200, response.into_field_value());
        for cookie in set_cookie_headers {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        Ok(auth_response)
    }
}

async fn resolve_two_factor_state<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<ResolvedTwoFactorState> {
    match ctx.require_native_session(req).await {
        Ok(data) => {
            let key = format!(
                "{}!{}",
                SchemaValue::<String>::from_field(data.user_property("id")?.clone())
                    .display_string()?,
                data.session.id().display_string()?
            );
            return Ok(ResolvedTwoFactorState::Session {
                data: Box::new(data),
                key,
            });
        }
        Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {}
        Err(error) => return Err(error),
    }

    let identifier = read_signed_cookie(req, TWO_FACTOR_COOKIE_SUFFIX, ctx)?
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    let verification = ctx
        .database
        .get_verification_by_identifier(&identifier)
        .await?
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    if verification.expires_at.is_before_or_equal(Utc::now())? {
        ctx.database
            .delete_verification_by_identifier(&identifier)
            .await?;
        return Err(AuthError::authentication_failed(
            "Invalid two factor cookie",
        ));
    }

    let user = ctx
        .database
        .get_user_by_id_value(&verification.value.field_value())
        .await?
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    let dont_remember = read_signed_cookie(req, DONT_REMEMBER_COOKIE_SUFFIX, ctx)?
        .is_some_and(|value| !value.is_empty());

    Ok(ResolvedTwoFactorState::Pending(PendingTwoFactorState {
        user: ctx.internal_user_view(&user).await?,
        key: identifier,
        dont_remember,
        expires_at: verification.expires_at,
    }))
}

async fn verify_existing_session_factor(
    req: &AuthRequest,
    data: NativeSessionData,
    enrollment: Option<EnrollmentMethod>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    complete_enrollment: impl std::future::Future<Output = AuthResult<()>>,
) -> AuthResult<(SessionTokenResponse, Vec<String>)> {
    if enrollment.is_some() && !data.user_property("twoFactorEnabled")?.is_truthy() {
        let updated_user = update_two_factor_user(data.user_property("id")?, true, ctx).await?;
        let issued = issue_factor_session(
            req,
            SchemaValue::from_field(data.user_property("id")?.clone()),
            updated_user
                .clone()
                .map_or(FieldValue::Null, |user| FieldMap::from(user).into()),
            data.session.field_values()?,
            ctx,
        )
        .await?;
        delete_factor_session(&data.session, ctx).await?;
        complete_enrollment.await?;
        return Ok((
            SessionTokenResponse {
                token: if enrollment == Some(EnrollmentMethod::Otp) {
                    issued
                        .field_values()?
                        .get("token")
                        .cloned()
                        .unwrap_or_default()
                } else {
                    data.session
                        .field_values()?
                        .get("token")
                        .cloned()
                        .unwrap_or_default()
                },
                // TS keeps the verify response on the pre-update snapshot even
                // though the re-issued session already observes 2FA as enabled.
                user: if enrollment == Some(EnrollmentMethod::Otp) {
                    FieldMap::from(
                        ctx.user_view(updated_user.as_ref().ok_or_else(|| {
                            AuthError::internal("Cannot convert undefined or null to object")
                        })?)
                        .await?,
                    )
                    .into()
                } else {
                    data.public_user(&ctx.config.user)?
                },
            },
            Vec::new(),
        ));
    }

    complete_enrollment.await?;
    Ok((
        SessionTokenResponse {
            token: data
                .session
                .field_values()?
                .get("token")
                .cloned()
                .unwrap_or_default(),
            user: data.public_user(&ctx.config.user)?,
        },
        Vec::new(),
    ))
}

async fn finalize_pending_two_factor<S: better_auth_core::AuthSchema>(
    pending: PendingTwoFactorState,
    req: &AuthRequest,
    trust_device: bool,
    ctx: &AuthContext<S>,
) -> AuthResult<(SessionTokenResponse, Vec<String>)> {
    let Some(consumed) = ctx
        .database
        .consume_verification_by_identifier(&pending.key)
        .await?
        .filter(|verification| {
            verification
                .value
                .field_value()
                .strict_equals(&pending.user.id.field_value())
        })
    else {
        req.append_response_header(
            "Set-Cookie",
            clear_cookie_header(req, &ctx.config, TWO_FACTOR_COOKIE_SUFFIX)?,
        )?;
        return Err(AuthError::authentication_failed(
            "Invalid two factor cookie",
        ));
    };
    let meta = RequestMeta::from_request_with_config(req, &ctx.config.advanced.ip_address);
    let expires_in = if pending.dont_remember {
        Duration::days(1)
    } else {
        ctx.config.session.expires_in()
    };
    let manager = ctx.session_manager();
    admit_session_for_id(ctx, &consumed.value, None)
        .await
        .map_err(SessionIssueError::into_auth_error)?;
    let Some(session) = manager
        .create_session_for_id_with_lifetime_optional(
            consumed.value,
            meta.ip_address,
            meta.user_agent,
            expires_in,
        )
        .await?
    else {
        return Err(AuthError::Upstream {
            status: 500,
            code: "FAILED_TO_CREATE_SESSION",
            message: "failed to create session",
        });
    };
    manager
        .set_native_session_cookie(
            req,
            better_auth_core::session::NativeSessionData {
                user: FieldMap::from(pending.user.clone()).into(),
                session: session.clone(),
            },
            None,
        )
        .await?;
    req.append_response_header(
        "Set-Cookie",
        clear_cookie_header(req, &ctx.config, TWO_FACTOR_COOKIE_SUFFIX)?,
    )?;
    if trust_device {
        req.append_response_header(
            "Set-Cookie",
            create_trust_device_cookie_header(&pending.user, ctx).await?,
        )?;
        req.append_response_header(
            "Set-Cookie",
            clear_cookie_header(req, &ctx.config, DONT_REMEMBER_COOKIE_SUFFIX)?,
        )?;
    }

    Ok((
        SessionTokenResponse {
            token: session
                .field_values()?
                .get("token")
                .cloned()
                .unwrap_or_default(),
            user: FieldMap::from(ctx.user_view(&pending.user).await?).into(),
        },
        Vec::new(),
    ))
}

async fn load_two_factor_record(
    user_id: &FieldValue,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<TwoFactor> {
    ctx.database
        .get_two_factor_by_user_id_value(&SchemaValue::from_field(user_id.clone()))
        .await?
        .ok_or_else(|| AuthError::bad_request("TOTP not enabled"))
}

impl ResolvedTwoFactorState {
    fn is_sign_in(&self) -> bool {
        matches!(self, Self::Pending(_))
    }

    fn user_id(&self) -> AuthResult<FieldValue> {
        match self {
            Self::Session { data, .. } => Ok(data.user_property("id")?.clone()),
            Self::Pending(pending) => Ok(pending.user.id.field_value()),
        }
    }

    fn user(&self) -> FieldValue {
        match self {
            Self::Session { data, .. } => data.user.clone(),
            Self::Pending(pending) => FieldMap::from(pending.user.clone()).into(),
        }
    }

    fn key(&self) -> &str {
        match self {
            Self::Session { key, .. } => key,
            Self::Pending(pending) => &pending.key,
        }
    }
}
