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
    issue_user_session,
};

use super::StatusResponse;

#[cfg(test)]
mod tests;

const TWO_FACTOR_COOKIE_SUFFIX: &str = "two_factor";
const TRUST_DEVICE_COOKIE_SUFFIX: &str = "trust_device";
const DONT_REMEMBER_COOKIE_SUFFIX: &str = "dont_remember";

const METADATA_ENABLED: &str = "two_factor.enabled";
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

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct EnableRequest {
    password: String,
    issuer: Option<String>,
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
    #[serde(rename = "totpURI")]
    totp_uri: String,
    #[serde(rename = "backupCodes")]
    backup_codes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TotpUriResponse {
    #[serde(rename = "totpURI")]
    totp_uri: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct SessionTokenResponse<U: Serialize> {
    token: String,
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
}

struct PendingTwoFactorState<S: better_auth_core::AuthSchema> {
    user: S::User,
    verification: S::Verification,
    key: String,
    dont_remember: bool,
}

enum ResolvedTwoFactorState<S: better_auth_core::AuthSchema> {
    Session {
        user: S::User,
        session: S::Session,
        key: String,
    },
    Pending(PendingTwoFactorState<S>),
}

pub(crate) struct SignInTwoFactorRedirect {
    pub response: TwoFactorRedirectResponse,
    pub set_cookie_headers: Vec<String>,
}

pub(crate) struct TrustedDeviceCheck {
    pub trusted: bool,
    pub set_cookie_headers: Vec<String>,
}

pub(crate) fn is_enabled(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> bool {
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

    Ok(SignInTwoFactorRedirect {
        response: TwoFactorRedirectResponse {
            two_factor_redirect: true,
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
            ctx.set_metadata(METADATA_ENABLED, serde_json::Value::Bool(true));
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

        let (response, set_cookie_headers) = verify_otp_core(req, &body, ctx).await?;
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

        let (response, set_cookie_headers) = verify_backup_code_core(req, &body, ctx).await?;
        let mut auth_response = AuthResponse::json(200, &response)?;
        for cookie in set_cookie_headers {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        Ok(auth_response)
    }
}

async fn enable_core(
    body: &EnableRequest,
    user: &impl AuthUser,
    current_session: &impl AuthSession,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(EnableResponse, Vec<String>)> {
    verify_user_password(ctx, user, &body.password).await?;

    let _ = ctx.database.delete_two_factor(user.id().as_ref()).await;

    let secret = generate_secret();
    let encrypted_secret = encrypt_value(&ctx.config.secret, &secret)?;
    let backup_codes = generate_backup_codes();
    let encrypted_backup_codes =
        encrypt_value(&ctx.config.secret, &serde_json::to_string(&backup_codes)?)?;

    _ = ctx
        .database
        .create_two_factor(CreateTwoFactor {
            user_id: user.id().to_string(),
            secret: encrypted_secret,
            backup_codes: encrypted_backup_codes,
        })
        .await?;

    let mut set_cookie_headers = Vec::new();
    if config.skip_verification_on_enable {
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
            current_session.ip_address().map(str::to_owned),
            current_session.user_agent().map(str::to_owned),
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?;
        ctx.database.delete_session(current_session.token()).await?;
        set_cookie_headers.push(create_session_cookie(issued.session.token(), &ctx.config));
    }

    let totp_uri = build_totp(config, &secret, body.issuer.as_deref(), user, ctx)?.get_url();
    Ok((
        EnableResponse {
            totp_uri,
            backup_codes,
        },
        set_cookie_headers,
    ))
}

async fn disable_core(
    body: &DisableRequest,
    user: &impl AuthUser,
    current_session: &impl AuthSession,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(StatusResponse, Vec<String>)> {
    verify_user_password(ctx, user, &body.password).await?;

    ctx.database.delete_two_factor(user.id().as_ref()).await?;

    let updated_user = ctx
        .database
        .update_user(
            user.id().as_ref(),
            UpdateUser {
                two_factor_enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;

    let issued = issue_user_session(
        ctx,
        updated_user.id().as_ref(),
        current_session.ip_address().map(str::to_owned),
        current_session.user_agent().map(str::to_owned),
    )
    .await
    .map_err(SessionIssueError::into_auth_error)?;
    ctx.database.delete_session(current_session.token()).await?;

    let mut set_cookie_headers = vec![create_session_cookie(issued.session.token(), &ctx.config)];

    if let Some(trust_cookie) = read_signed_cookie(req, TRUST_DEVICE_COOKIE_SUFFIX, ctx)? {
        if let Some((_, trust_identifier)) = trust_cookie.split_once('!')
            && let Some(verification) = ctx
                .database
                .get_verification_by_identifier(trust_identifier)
                .await?
        {
            let _ = ctx
                .database
                .delete_verification(verification.id().as_ref())
                .await;
        }
        set_cookie_headers.push(clear_cookie_header(&ctx.config, TRUST_DEVICE_COOKIE_SUFFIX));
    }

    Ok((StatusResponse { status: true }, set_cookie_headers))
}

async fn get_totp_uri_core(
    body: &GetTotpUriRequest,
    user: &impl AuthUser,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<TotpUriResponse> {
    verify_user_password(ctx, user, &body.password).await?;
    let two_factor = load_two_factor_record(user, ctx).await?;
    let secret = decrypt_value(&ctx.config.secret, two_factor.secret())?;
    Ok(TotpUriResponse {
        totp_uri: build_totp(config, &secret, None, user, ctx)?.get_url(),
    })
}

async fn verify_totp_core(
    req: &AuthRequest,
    body: &VerifyTotpRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    let state = resolve_two_factor_state(req, ctx).await?;
    let two_factor = load_two_factor_record(state.user(), ctx).await?;
    let secret = decrypt_value(&ctx.config.secret, two_factor.secret())?;
    let totp = build_totp(config, &secret, None, state.user(), ctx)?;

    if !totp
        .check_current(&body.code)
        .map_err(|error| AuthError::internal(format!("Failed to verify TOTP: {}", error)))?
    {
        return Err(AuthError::authentication_failed("Invalid code"));
    }

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            verify_existing_session_factor(user, session, true, ctx).await
        }
        ResolvedTwoFactorState::Pending(pending) => {
            finalize_pending_two_factor(pending, req, body.trust_device.unwrap_or(false), true, ctx)
                .await
        }
    }
}

async fn send_otp_core(
    req: &AuthRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let sender = config
        .send_otp
        .as_ref()
        .ok_or_else(|| AuthError::bad_request("otp isn't configured"))?;
    let state = resolve_two_factor_state(req, ctx).await?;

    let otp = format!(
        "{:0width$}",
        rand::thread_rng().gen_range(0..10u32.pow(DEFAULT_OTP_DIGITS as u32)),
        width = DEFAULT_OTP_DIGITS
    );
    let hashed_otp = better_auth_core::hash_password(None, &otp).await?;
    let identifier = otp_verification_identifier(state.key());

    if let Some(existing) = ctx
        .database
        .get_verification_by_identifier(&identifier)
        .await?
    {
        ctx.database
            .delete_verification(existing.id().as_ref())
            .await?;
    }

    _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier,
            value: format!("{}:0", hashed_otp),
            expires_at: Utc::now() + Duration::seconds(DEFAULT_OTP_LIFETIME_SECS),
        })
        .await?;

    if let Err(error) = sender.send(&UserView::from(state.user()), &otp).await {
        tracing::warn!(error = %error, "Failed to send two-factor OTP");
    }

    Ok(StatusResponse { status: true })
}

async fn verify_otp_core(
    req: &AuthRequest,
    body: &VerifyOtpRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    let state = resolve_two_factor_state(req, ctx).await?;
    let identifier = otp_verification_identifier(state.key());
    let Some(verification) = ctx
        .database
        .get_verification_by_identifier(&identifier)
        .await?
    else {
        return Err(AuthError::bad_request("OTP has expired"));
    };

    if verification.expires_at() <= Utc::now() {
        ctx.database
            .delete_verification(verification.id().as_ref())
            .await?;
        return Err(AuthError::bad_request("OTP has expired"));
    }

    let Some((stored_hash, counter)) = verification.value().rsplit_once(':') else {
        return Err(AuthError::internal("Malformed OTP verification payload"));
    };

    let attempts = counter.parse::<usize>().map_err(|error| {
        AuthError::internal(format!("Malformed OTP attempt counter: {}", error))
    })?;
    if attempts >= DEFAULT_OTP_ATTEMPT_LIMIT {
        ctx.database
            .delete_verification(verification.id().as_ref())
            .await?;
        return Err(AuthError::bad_request(
            "Too many attempts. Please request a new code.",
        ));
    }

    let is_valid = match better_auth_core::verify_password(None, &body.code, stored_hash).await {
        Ok(()) => true,
        Err(AuthError::InvalidCredentials) => false,
        Err(error) => return Err(error),
    };

    if !is_valid {
        let next_value = format!("{}:{}", stored_hash, attempts + 1);
        let expires_at = verification.expires_at();
        let verification_identifier = verification.identifier().to_string();
        ctx.database
            .delete_verification(verification.id().as_ref())
            .await?;
        _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: verification_identifier,
                value: next_value,
                expires_at,
            })
            .await?;
        return Err(AuthError::authentication_failed("Invalid code"));
    }

    ctx.database
        .delete_verification(verification.id().as_ref())
        .await?;

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            verify_existing_session_factor(user, session, true, ctx).await
        }
        ResolvedTwoFactorState::Pending(pending) => {
            finalize_pending_two_factor(pending, req, body.trust_device.unwrap_or(false), true, ctx)
                .await
        }
    }
}

async fn generate_backup_codes_core(
    body: &GenerateBackupCodesRequest,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<BackupCodesResponse> {
    if !user.two_factor_enabled() {
        return Err(AuthError::bad_request("Two factor isn't enabled"));
    }

    verify_user_password(ctx, user, &body.password).await?;
    let _ = load_two_factor_record(user, ctx).await?;

    let backup_codes = generate_backup_codes();
    let encrypted = encrypt_value(&ctx.config.secret, &serde_json::to_string(&backup_codes)?)?;
    _ = ctx
        .database
        .update_two_factor_backup_codes(user.id().as_ref(), &encrypted)
        .await?;

    Ok(BackupCodesResponse {
        status: true,
        backup_codes,
    })
}

async fn verify_backup_code_core(
    req: &AuthRequest,
    body: &VerifyBackupCodeRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    let state = resolve_two_factor_state(req, ctx).await?;
    let two_factor = ctx
        .database
        .get_two_factor_by_user_id(state.user().id().as_ref())
        .await?
        .ok_or_else(|| AuthError::bad_request("Backup codes aren't enabled"))?;

    let Some(mut backup_codes) =
        decrypt_backup_codes(two_factor.backup_codes(), &ctx.config.secret)?
    else {
        return Err(AuthError::authentication_failed("Invalid backup code"));
    };
    let Some(index) = backup_codes
        .iter()
        .position(|candidate| candidate == &body.code)
    else {
        return Err(AuthError::authentication_failed("Invalid backup code"));
    };
    let _ = backup_codes.remove(index);

    let encrypted = encrypt_value(&ctx.config.secret, &serde_json::to_string(&backup_codes)?)?;
    _ = ctx
        .database
        .update_two_factor_backup_codes(state.user().id().as_ref(), &encrypted)
        .await?;

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            if body.disable_session.unwrap_or(false) {
                Ok((
                    SessionTokenResponse {
                        token: session.token().to_string(),
                        user: UserView::from(&user),
                    },
                    Vec::new(),
                ))
            } else {
                verify_existing_session_factor(user, session, false, ctx).await
            }
        }
        ResolvedTwoFactorState::Pending(pending) => {
            finalize_pending_two_factor(
                pending,
                req,
                body.trust_device.unwrap_or(false),
                !body.disable_session.unwrap_or(false),
                ctx,
            )
            .await
        }
    }
}

async fn view_backup_codes_core<S: better_auth_core::AuthSchema>(
    user_id: &str,
    ctx: &AuthContext<S>,
) -> AuthResult<Vec<String>> {
    let two_factor = ctx
        .database
        .get_two_factor_by_user_id(user_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Backup codes aren't enabled"))?;
    let Some(backup_codes) = decrypt_backup_codes(two_factor.backup_codes(), &ctx.config.secret)?
    else {
        return Err(AuthError::bad_request("Invalid backup code"));
    };
    Ok(backup_codes)
}

async fn resolve_two_factor_state<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<ResolvedTwoFactorState<S>> {
    if let Ok((user, session)) = ctx.require_session(req).await {
        let key = format!("{}!{}", user.id(), session.id());
        return Ok(ResolvedTwoFactorState::Session { user, session, key });
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
        user,
        verification,
        key: identifier,
        dont_remember,
    }))
}

async fn verify_existing_session_factor(
    user: impl AuthUser,
    session: impl AuthSession,
    enable_two_factor_if_needed: bool,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    if enable_two_factor_if_needed && !user.two_factor_enabled() {
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
                token: issued.session.token().to_string(),
                // TS keeps the verify response on the pre-update snapshot even
                // though the re-issued session already observes 2FA as enabled.
                user: UserView::from(&user),
            },
            vec![create_session_cookie(issued.session.token(), &ctx.config)],
        ));
    }

    Ok((
        SessionTokenResponse {
            token: session.token().to_string(),
            user: UserView::from(&user),
        },
        Vec::new(),
    ))
}

async fn finalize_pending_two_factor<S: better_auth_core::AuthSchema>(
    pending: PendingTwoFactorState<S>,
    req: &AuthRequest,
    trust_device: bool,
    set_session_cookie: bool,
    ctx: &AuthContext<S>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    let meta = RequestMeta::from_request(req);
    let issued = issue_user_session(
        ctx,
        pending.user.id().as_ref(),
        meta.ip_address,
        meta.user_agent,
    )
    .await
    .map_err(SessionIssueError::into_auth_error)?;
    ctx.database
        .delete_verification(pending.verification.id().as_ref())
        .await?;

    let mut set_cookie_headers = vec![clear_cookie_header(&ctx.config, TWO_FACTOR_COOKIE_SUFFIX)];
    if set_session_cookie {
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
            token: issued.session.token().to_string(),
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

fn build_totp(
    config: &TwoFactorConfig,
    secret: &str,
    request_issuer: Option<&str>,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<TOTP> {
    let issuer = request_issuer
        .map(str::to_owned)
        .or_else(|| config.issuer.clone())
        .unwrap_or_else(|| ctx.config.app_name.clone());
    let account_name = user.email().unwrap_or("user").to_string();
    TOTP::new(
        Algorithm::SHA1,
        config.totp_digits,
        1,
        config.totp_period,
        secret.as_bytes().to_vec(),
        Some(issuer),
        account_name,
    )
    .map_err(|error| AuthError::internal(format!("Failed to create TOTP: {}", error)))
}

async fn verify_user_password(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user: &impl AuthUser,
    password: &str,
) -> AuthResult<()> {
    let stored_hash = get_credential_password_hash(ctx, user)
        .await?
        .ok_or_else(|| AuthError::bad_request("Invalid password"))?;
    match better_auth_core::verify_password(None, password, &stored_hash).await {
        Ok(()) => Ok(()),
        Err(AuthError::InvalidCredentials) => Err(AuthError::bad_request("Invalid password")),
        Err(error) => Err(error),
    }
}

fn generate_secret() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn generate_backup_codes() -> Vec<String> {
    (0..DEFAULT_BACKUP_CODE_COUNT)
        .map(|_| {
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(DEFAULT_BACKUP_CODE_LENGTH)
                .map(char::from)
                .collect::<String>()
        })
        .map(|code| format!("{}-{}", &code[..5], &code[5..]))
        .collect()
}

fn decrypt_backup_codes(backup_codes: &str, secret: &str) -> AuthResult<Option<Vec<String>>> {
    let decrypted = decrypt_value(secret, backup_codes)?;
    serde_json::from_str(&decrypted)
        .ok()
        .map_or(Ok(None), |codes| Ok(Some(codes)))
}

fn otp_verification_identifier(key: &str) -> String {
    format!("2fa-otp-{}", key)
}

fn two_factor_cookie_max_age(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> i64 {
    ctx.get_metadata(METADATA_TWO_FACTOR_COOKIE_MAX_AGE)
        .and_then(|value| value.as_i64())
        .unwrap_or(DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS)
}

fn trust_device_max_age(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> i64 {
    ctx.get_metadata(METADATA_TRUST_DEVICE_MAX_AGE)
        .and_then(|value| value.as_i64())
        .unwrap_or(DEFAULT_TRUST_DEVICE_MAX_AGE_SECS)
}

fn create_session_cookie_for_dont_remember(
    token: &str,
    dont_remember: bool,
    config: &better_auth_core::AuthConfig,
) -> String {
    if dont_remember {
        create_session_cookie_with_max_age(Some(token), None, config)
    } else {
        create_session_cookie(token, config)
    }
}

fn clear_cookie_header(config: &better_auth_core::AuthConfig, suffix: &str) -> String {
    create_clear_cookie(&related_cookie_name(config, suffix), config)
}

async fn create_trust_device_cookie_header(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<String> {
    let identifier = format!("trust-device-{}", uuid::Uuid::new_v4());
    let token = sign_value(&ctx.config.secret, &format!("{}!{}", user.id(), identifier))?;
    let value = format!("{}!{}", token, identifier);
    let expires_at = Utc::now() + Duration::seconds(trust_device_max_age(ctx));
    _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: identifier.clone(),
            value: user.id().to_string(),
            expires_at,
        })
        .await?;
    create_signed_cookie_header(
        &ctx.config.secret,
        &ctx.config,
        TRUST_DEVICE_COOKIE_SUFFIX,
        &value,
        Some(trust_device_max_age(ctx)),
    )
}

fn create_signed_cookie_header(
    secret: &str,
    config: &better_auth_core::AuthConfig,
    suffix: &str,
    value: &str,
    max_age_seconds: Option<i64>,
) -> AuthResult<String> {
    let cookie_name = related_cookie_name(config, suffix);
    let signed_value = sign_cookie_value(secret, value)?;
    Ok(create_session_like_cookie(
        &cookie_name,
        &signed_value,
        max_age_seconds,
        config,
    ))
}

fn read_signed_cookie<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    suffix: &str,
    ctx: &AuthContext<S>,
) -> AuthResult<Option<String>> {
    let cookie_name = related_cookie_name(&ctx.config, suffix);
    let Some(raw_cookie) = get_cookie(req, &cookie_name) else {
        return Ok(None);
    };
    verify_signed_cookie_value(&ctx.config.secret, &raw_cookie)
}

fn sign_cookie_value(secret: &str, value: &str) -> AuthResult<String> {
    Ok(format!("{}.{}", value, sign_value(secret, value)?))
}

fn verify_signed_cookie_value(secret: &str, signed_value: &str) -> AuthResult<Option<String>> {
    let Some((value, signature)) = signed_value.rsplit_once('.') else {
        return Ok(None);
    };
    Ok(verify_signature(secret, value, signature)?.then(|| value.to_string()))
}

fn sign_value(secret: &str, value: &str) -> AuthResult<String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|error| AuthError::internal(format!("Failed to initialize HMAC: {}", error)))?;
    mac.update(value.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn verify_signature(secret: &str, value: &str, signature: &str) -> AuthResult<bool> {
    let decoded = match URL_SAFE_NO_PAD.decode(signature) {
        Ok(decoded) => decoded,
        Err(_) => return Ok(false),
    };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|error| AuthError::internal(format!("Failed to initialize HMAC: {}", error)))?;
    mac.update(value.as_bytes());
    Ok(mac.verify_slice(&decoded).is_ok())
}

fn derive_encryption_key(secret: &str) -> AuthResult<Key<Aes256Gcm>> {
    let hkdf = Hkdf::<Sha256>::new(None, secret.as_bytes());
    let mut okm = [0u8; 32];
    hkdf.expand(ENCRYPTION_INFO, &mut okm).map_err(|error| {
        AuthError::internal(format!("Failed to derive encryption key: {}", error))
    })?;
    Ok(*Key::<Aes256Gcm>::from_slice(&okm))
}

fn encrypt_value(secret: &str, plaintext: &str) -> AuthResult<String> {
    let cipher = Aes256Gcm::new(&derive_encryption_key(secret)?);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|error| {
            AuthError::internal(format!("Failed to encrypt two-factor data: {}", error))
        })?;
    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(output))
}

fn decrypt_value(secret: &str, encrypted: &str) -> AuthResult<String> {
    let cipher = Aes256Gcm::new(&derive_encryption_key(secret)?);
    let bytes = URL_SAFE_NO_PAD.decode(encrypted).map_err(|error| {
        AuthError::internal(format!(
            "Failed to decode encrypted two-factor data: {}",
            error
        ))
    })?;
    if bytes.len() < 12 {
        return Err(AuthError::internal(
            "Encrypted two-factor payload is missing the nonce",
        ));
    }
    let (nonce_bytes, ciphertext) = bytes.split_at(12);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|error| {
            AuthError::internal(format!("Failed to decrypt two-factor data: {}", error))
        })?;
    String::from_utf8(plaintext).map_err(|error| {
        AuthError::internal(format!(
            "Two-factor plaintext is not valid UTF-8: {}",
            error
        ))
    })
}

impl<S: better_auth_core::AuthSchema> ResolvedTwoFactorState<S> {
    fn user(&self) -> &S::User {
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
