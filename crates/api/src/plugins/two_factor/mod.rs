use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::Rng;
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use totp_rs::{Algorithm, TOTP};
use validator::Validate;

use better_auth_core::entity::{AuthSession, AuthTwoFactor, AuthUser, AuthVerification};
use better_auth_core::utils::cookie_utils::{
    create_clear_cookie, create_session_cookie, create_session_cookie_with_max_age,
    create_session_like_cookie, related_cookie_name,
};
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateTwoFactor,
    CreateVerification, RequestMeta, TwoFactor, UpdateUser,
};

use crate::plugins::helpers::{
    SessionIssueError, delete_session_cookie_headers, get_cookie, get_credential_password_hash,
    issue_user_session, issue_user_session_with_lifetime,
};

use super::StatusResponse;
mod actions;
mod helpers;
mod security;
use actions::*;
use helpers::*;
use security::*;

#[cfg(test)]
mod security_tests;
#[cfg(test)]
mod tests;

const TWO_FACTOR_COOKIE_SUFFIX: &str = "two_factor";
const TRUST_DEVICE_COOKIE_SUFFIX: &str = "trust_device";
const DONT_REMEMBER_COOKIE_SUFFIX: &str = "dont_remember";

const METADATA_ENABLED: &str = "two_factor.enabled";
const METADATA_OTP_ENABLED: &str = "two_factor.otp_enabled";
const METADATA_TWO_FACTOR_COOKIE_MAX_AGE: &str = "two_factor.two_factor_cookie_max_age";
const METADATA_TRUST_DEVICE_MAX_AGE: &str = "two_factor.trust_device_max_age";

const DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS: i64 = 10 * 60;
const DEFAULT_TRUST_DEVICE_MAX_AGE_SECS: i64 = 30 * 24 * 60 * 60;
const DEFAULT_TOTP_PERIOD_SECS: u64 = 30;
const DEFAULT_TOTP_DIGITS: usize = 6;
const DEFAULT_OTP_DIGITS: usize = 6;
const DEFAULT_OTP_LIFETIME_SECS: i64 = 3 * 60;
const DEFAULT_OTP_ATTEMPT_LIMIT: usize = 5;
const DEFAULT_BACKUP_CODE_COUNT: usize = 10;
const DEFAULT_BACKUP_CODE_LENGTH: usize = 10;

const ENCRYPTION_INFO: &[u8] = b"better-auth-two-factor-encryption";

type HmacSha256 = Hmac<Sha256>;

/// Callback used by the two-factor plugin to deliver a one-time password.
#[async_trait]
pub trait SendTwoFactorOtp: Send + Sync {
    /// Send a one-time password to the given user.
    async fn send(&self, user: &UserView, otp: &str) -> AuthResult<()>;
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
    /// Account-level protection shared by all sign-in factors and challenges.
    #[config(default = AccountLockout::default())]
    pub account_lockout: AccountLockout,
    /// Override the issuer embedded in generated TOTP URIs.
    #[config(default = None)]
    pub issuer: Option<String>,
    /// Skip the enrollment verification step and enable 2FA immediately.
    #[config(default = false)]
    pub skip_verification_on_enable: bool,
    /// Maximum lifetime for the pending two-factor cookie used during sign-in.
    #[config(default = DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS)]
    pub two_factor_cookie_max_age: i64,
    /// Maximum lifetime for the trusted-device cookie.
    #[config(default = DEFAULT_TRUST_DEVICE_MAX_AGE_SECS)]
    pub trust_device_max_age: i64,
    /// TOTP period in seconds.
    #[config(default = DEFAULT_TOTP_PERIOD_SECS)]
    pub totp_period: u64,
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
    /// Duration of the lock in seconds.
    pub duration_seconds: i64,
}

impl Default for AccountLockout {
    fn default() -> Self {
        Self {
            enabled: true,
            max_failed_attempts: 10,
            duration_seconds: 900,
        }
    }
}

#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum EnrollmentMethod {
    Otp,
    #[default]
    Totp,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct EnableRequest {
    password: String,
    issuer: Option<String>,
    #[serde(default)]
    method: EnrollmentMethod,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct DisableRequest {
    password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct GetTotpUriRequest {
    password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct VerifyTotpRequest {
    code: String,
    #[serde(rename = "trustDevice")]
    trust_device: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct VerifyOtpRequest {
    code: String,
    #[serde(rename = "trustDevice")]
    trust_device: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct GenerateBackupCodesRequest {
    password: String,
}

#[derive(Debug, Deserialize, Validate)]
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

#[derive(Debug, Serialize)]
pub(crate) struct SessionTokenResponse<U: Serialize> {
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    user: U,
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
}

enum ResolvedTwoFactorState {
    Session {
        user: UserView,
        session: Box<better_auth_core::wire::SessionView>,
        key: String,
    },
    Pending(PendingTwoFactorState),
}

pub(crate) struct SignInTwoFactorRedirect {
    pub response: TwoFactorRedirectResponse,
    pub set_cookie_headers: Vec<String>,
}

pub(crate) struct TrustedDeviceCheck {
    pub trusted: bool,
    pub set_cookie_headers: Vec<String>,
}

/// Whether the TwoFactor plugin is installed, read from the flag it sets at
/// `on_init`. Public because `POST /update-user` gates `input: false` fields
/// on it (better-auth 1.6.29 parity).
pub fn is_enabled(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> bool {
    ctx.get_metadata(METADATA_ENABLED)
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
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

    let clear_header = create_clear_cookie(&cookie_name, &ctx.config);
    let Some(signed_value) = verify_signed_cookie_value(&ctx.config.secret, &raw_cookie)? else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    };

    let Some((token, trust_identifier)) = signed_value.split_once('!') else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    };

    let expected_token = sign_value(
        &ctx.config.secret,
        &format!("{}!{}", user.id(), trust_identifier),
    )?;
    if token != expected_token {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    }

    let Some(verification) = ctx
        .database
        .get_verification_by_identifier(trust_identifier)
        .await?
    else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    };

    if verification.value() != user.id().as_ref() || verification.expires_at() <= Utc::now() {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    }

    ctx.database
        .delete_verification(verification.id().as_ref())
        .await?;

    let rotated_cookie = create_trust_device_cookie_header(user, ctx).await?;
    Ok(TrustedDeviceCheck {
        trusted: true,
        set_cookie_headers: vec![rotated_cookie],
    })
}

pub(crate) async fn begin_sign_in_challenge(
    user: &impl AuthUser,
    remember_me: Option<bool>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SignInTwoFactorRedirect> {
    let identifier = format!("2fa-{}", uuid::Uuid::new_v4());
    _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: identifier.clone(),
            value: user.id().to_string(),
            expires_at: Utc::now() + Duration::seconds(two_factor_cookie_max_age(ctx)),
        })
        .await?;

    let _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: format!("2fa-attempts-{identifier}"),
            value: "0".to_owned(),
            expires_at: Utc::now() + Duration::seconds(two_factor_cookie_max_age(ctx)),
        })
        .await?;

    let mut headers = delete_session_cookie_headers(&ctx.config);
    headers.retain(|cookie| {
        !cookie.starts_with(&format!(
            "{}=",
            related_cookie_name(&ctx.config, DONT_REMEMBER_COOKIE_SUFFIX)
        ))
    });
    headers.push(create_signed_cookie_header(
        &ctx.config.secret,
        &ctx.config,
        TWO_FACTOR_COOKIE_SUFFIX,
        &identifier,
        Some(two_factor_cookie_max_age(ctx)),
    )?);

    if remember_me == Some(false) {
        headers.push(create_signed_cookie_header(
            &ctx.config.secret,
            &ctx.config,
            DONT_REMEMBER_COOKIE_SUFFIX,
            "true",
            None,
        )?);
    }

    // TOTP is per-user: only offered once the user has a stored secret. OTP is
    // server-level: offered whenever a sender is configured.
    let mut two_factor_methods = Vec::new();
    if ctx
        .database
        .get_two_factor_by_user_id(user.id().as_ref())
        .await?
        .is_some_and(|factor| factor.verified)
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

    Ok(SignInTwoFactorRedirect {
        response: TwoFactorRedirectResponse {
            two_factor_redirect: true,
            two_factor_methods,
        },
        set_cookie_headers: headers,
    })
}

impl TwoFactorPlugin {
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
    ) -> AuthResult<Vec<String>> {
        view_backup_codes_core(user_id, ctx).await
    }
}

better_auth_core::impl_auth_plugin! {
    TwoFactorPlugin, "two-factor";
    routes {
        post "/two-factor/enable" => handle_enable, "enable_two_factor";
        post "/two-factor/disable" => handle_disable, "disable_two_factor";
        post "/two-factor/get-totp-uri" => handle_get_totp_uri, "get_totp_uri";
        post "/two-factor/verify-totp" => handle_verify_totp, "verify_totp";
        post "/two-factor/send-otp" => handle_send_otp, "send_otp";
        post "/two-factor/verify-otp" => handle_verify_otp, "verify_otp";
        post "/two-factor/generate-backup-codes" => handle_generate_backup_codes, "generate_backup_codes";
        post "/two-factor/verify-backup-code" => handle_verify_backup_code, "verify_backup_code";
    }
    extra {
        async fn on_init(
            &self,
            ctx: &mut better_auth_core::AuthInitContext<S>,
        ) -> better_auth_core::AuthResult<()> {
            S::User::require_plugin_fields("two-factor", &["two_factor_enabled"])?;
            ctx.set_metadata(METADATA_ENABLED, serde_json::Value::Bool(true));
            ctx.set_metadata(
                METADATA_OTP_ENABLED,
                serde_json::Value::Bool(self.config.send_otp.is_some()),
            );
            ctx.set_metadata(
                METADATA_TWO_FACTOR_COOKIE_MAX_AGE,
                serde_json::Value::Number(self.config.two_factor_cookie_max_age.into()),
            );
            ctx.set_metadata(
                METADATA_TRUST_DEVICE_MAX_AGE,
                serde_json::Value::Number(self.config.trust_device_max_age.into()),
            );
            Ok(())
        }
    }
}

impl TwoFactorPlugin {
    async fn handle_enable(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, session) = ctx.require_session(req).await?;
        let body: EnableRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (response, set_cookie_headers) =
            enable_core(&body, &user, &session, &self.config, ctx).await?;
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
        let (user, session) = ctx.require_session(req).await?;
        let body: DisableRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (response, set_cookie_headers) = disable_core(&body, &user, &session, req, ctx).await?;
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
        let (user, _session) = ctx.require_session(req).await?;
        let body: GetTotpUriRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let response = get_totp_uri_core(&body, &user, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_verify_totp(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyTotpRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (response, set_cookie_headers) =
            verify_totp_core(req, &body, &self.config, ctx).await?;
        let mut auth_response = AuthResponse::json(200, &response)?;
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
        let body: VerifyOtpRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (response, set_cookie_headers) = verify_otp_core(req, &body, &self.config, ctx).await?;
        let mut auth_response = AuthResponse::json(200, &response)?;
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
        let (user, _session) = ctx.require_session(req).await?;
        let body: GenerateBackupCodesRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let response = generate_backup_codes_core(&body, &user, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_verify_backup_code(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyBackupCodeRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (response, set_cookie_headers) =
            verify_backup_code_core(req, &body, &self.config, ctx).await?;
        let mut auth_response = AuthResponse::json(200, &response)?;
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
    match ctx.require_session(req).await {
        Ok((user, session)) => {
            let key = format!("{}!{}", user.id(), session.id());
            return Ok(ResolvedTwoFactorState::Session {
                user,
                session: Box::new(session),
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
    if verification.expires_at() <= Utc::now() {
        ctx.database
            .delete_verification(verification.id().as_ref())
            .await?;
        return Err(AuthError::authentication_failed(
            "Invalid two factor cookie",
        ));
    }

    let user = ctx
        .database
        .get_user_by_id(verification.value())
        .await?
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    let dont_remember = read_signed_cookie(req, DONT_REMEMBER_COOKIE_SUFFIX, ctx)?.is_some();

    Ok(ResolvedTwoFactorState::Pending(PendingTwoFactorState {
        user: UserView::from(&user),
        key: identifier,
        dont_remember,
    }))
}

async fn verify_existing_session_factor(
    user: impl AuthUser,
    session: impl AuthSession,
    enrollment: Option<EnrollmentMethod>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    if enrollment.is_some() && !user.two_factor_enabled() {
        let updated_user = ctx
            .database
            .update_user(
                user.id().as_ref(),
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let issued = issue_user_session(
            ctx,
            updated_user.id().as_ref(),
            session.ip_address().map(str::to_owned),
            session.user_agent().map(str::to_owned),
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?;
        ctx.database.delete_session(session.token()).await?;
        return Ok((
            SessionTokenResponse {
                token: Some(if enrollment == Some(EnrollmentMethod::Otp) {
                    issued.session.token().to_string()
                } else {
                    session.token().to_string()
                }),
                // TS keeps the verify response on the pre-update snapshot even
                // though the re-issued session already observes 2FA as enabled.
                user: if enrollment == Some(EnrollmentMethod::Otp) {
                    UserView::from(&updated_user)
                } else {
                    UserView::from(&user)
                },
            },
            vec![create_session_cookie(issued.session.token(), &ctx.config)],
        ));
    }

    Ok((
        SessionTokenResponse {
            token: Some(session.token().to_string()),
            user: UserView::from(&user),
        },
        Vec::new(),
    ))
}

async fn finalize_pending_two_factor<S: better_auth_core::AuthSchema>(
    pending: PendingTwoFactorState,
    req: &AuthRequest,
    trust_device: bool,
    ctx: &AuthContext<S>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    let Some(consumed) = ctx
        .database
        .consume_verification_by_identifier(&pending.key)
        .await?
        .filter(|verification| verification.value() == pending.user.id)
    else {
        req.append_response_header(
            "Set-Cookie",
            clear_cookie_header(&ctx.config, TWO_FACTOR_COOKIE_SUFFIX),
        )?;
        return Err(AuthError::authentication_failed(
            "Invalid two factor cookie",
        ));
    };
    let meta = RequestMeta::from_request(req);
    let expires_in = if pending.dont_remember {
        Duration::days(1)
    } else {
        ctx.config.session.expires_in
    };
    let issued = issue_user_session_with_lifetime(
        ctx,
        consumed.value(),
        meta.ip_address,
        meta.user_agent,
        expires_in,
    )
    .await
    .map_err(SessionIssueError::into_auth_error)?;

    let mut set_cookie_headers = vec![clear_cookie_header(&ctx.config, TWO_FACTOR_COOKIE_SUFFIX)];
    {
        set_cookie_headers.push(create_session_cookie_for_dont_remember(
            issued.session.token(),
            pending.dont_remember,
            &ctx.config,
        ));
        if pending.dont_remember {
            set_cookie_headers.push(create_signed_cookie_header(
                &ctx.config.secret,
                &ctx.config,
                DONT_REMEMBER_COOKIE_SUFFIX,
                "true",
                None,
            )?);
        }
    }
    if trust_device {
        set_cookie_headers.push(create_trust_device_cookie_header(&issued.user, ctx).await?);
        set_cookie_headers.push(clear_cookie_header(
            &ctx.config,
            DONT_REMEMBER_COOKIE_SUFFIX,
        ));
    }

    Ok((
        SessionTokenResponse {
            token: Some(issued.session.token().to_string()),
            user: UserView::from(&issued.user),
        },
        set_cookie_headers,
    ))
}

async fn load_two_factor_record(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<TwoFactor> {
    ctx.database
        .get_two_factor_by_user_id(user.id().as_ref())
        .await?
        .ok_or_else(|| AuthError::bad_request("TOTP not enabled"))
}

impl ResolvedTwoFactorState {
    fn is_sign_in(&self) -> bool {
        matches!(self, Self::Pending(_))
    }

    fn user(&self) -> &UserView {
        match self {
            Self::Session { user, .. } => user,
            Self::Pending(pending) => &pending.user,
        }
    }

    fn key(&self) -> &str {
        match self {
            Self::Session { key, .. } => key,
            Self::Pending(pending) => &pending.key,
        }
    }
}
