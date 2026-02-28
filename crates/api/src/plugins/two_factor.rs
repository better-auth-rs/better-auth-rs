use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
use validator::Validate;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthSession, AuthTwoFactor, AuthUser, AuthVerification};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{
    AuthRequest, AuthResponse, CreateTwoFactor, CreateVerification, HttpMethod, UpdateUser,
};

use better_auth_core::utils::cookie_utils::create_session_cookie;

use super::StatusResponse;

/// Two-factor authentication plugin providing TOTP, OTP, and backup code flows.
pub struct TwoFactorPlugin {
    config: TwoFactorConfig,
}

#[derive(Debug, Clone)]
pub struct TwoFactorConfig {
    pub issuer: String,
    pub backup_code_count: usize,
    pub backup_code_length: usize,
    pub totp_period: u64,
    pub totp_digits: usize,
}

impl Default for TwoFactorConfig {
    fn default() -> Self {
        Self {
            issuer: "BetterAuth".to_string(),
            backup_code_count: 10,
            backup_code_length: 8,
            totp_period: 30,
            totp_digits: 6,
        }
    }
}

// -- Request types --

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
    #[allow(dead_code)]
    trust_device: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct VerifyOtpRequest {
    code: String,
    #[serde(rename = "trustDevice")]
    #[allow(dead_code)]
    trust_device: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct GenerateBackupCodesRequest {
    password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct VerifyBackupCodeRequest {
    code: String,
    #[serde(rename = "disableSession")]
    #[allow(dead_code)]
    disable_session: Option<String>,
    #[serde(rename = "trustDevice")]
    #[allow(dead_code)]
    trust_device: Option<String>,
}

// -- Response types --

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
pub(crate) struct VerifyTotpResponse<U: Serialize> {
    status: bool,
    token: String,
    user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyBackupCodeResponse<U: Serialize, S: Serialize> {
    user: U,
    session: S,
}

#[derive(Debug, Serialize)]
pub(crate) struct BackupCodesResponse {
    status: bool,
    #[serde(rename = "backupCodes")]
    backup_codes: Vec<String>,
}

impl TwoFactorPlugin {
    pub fn new() -> Self {
        Self {
            config: TwoFactorConfig::default(),
        }
    }

    pub fn with_config(config: TwoFactorConfig) -> Self {
        Self { config }
    }

    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.config.issuer = issuer.into();
        self
    }
}

// -- Free-standing helpers --

fn generate_backup_codes(config: &TwoFactorConfig) -> Vec<String> {
    use rand::Rng;
    (0..config.backup_code_count)
        .map(|_| {
            rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(config.backup_code_length)
                .map(char::from)
                .collect::<String>()
                .to_uppercase()
        })
        .collect()
}

async fn hash_backup_codes(codes: &[String]) -> AuthResult<String> {
    let mut hashed = Vec::with_capacity(codes.len());
    for code in codes {
        hashed.push(better_auth_core::hash_password(None, code).await?);
    }
    serde_json::to_string(&hashed).map_err(|e| AuthError::internal(e.to_string()))
}

fn build_totp(
    config: &TwoFactorConfig,
    secret: &[u8],
    email: &str,
    issuer: &str,
) -> AuthResult<TOTP> {
    TOTP::new(
        Algorithm::SHA1,
        config.totp_digits,
        1,
        config.totp_period,
        secret.to_vec(),
        Some(issuer.to_string()),
        email.to_string(),
    )
    .map_err(|e| AuthError::internal(format!("Failed to create TOTP: {}", e)))
}

async fn verify_user_password<U: AuthUser>(user: &U, password: &str) -> AuthResult<()> {
    let stored_hash = user
        .metadata()
        .get("password_hash")
        .and_then(|v| v.as_str())
        .ok_or(AuthError::InvalidCredentials)?;

    better_auth_core::verify_password(None, password, stored_hash).await
}

// -- Core functions (session-based) --

async fn enable_core<DB: DatabaseAdapter>(
    body: &EnableRequest,
    user: &DB::User,
    config: &TwoFactorConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<EnableResponse> {
    verify_user_password(user, &body.password).await?;

    // Generate TOTP secret
    let secret = Secret::generate_secret();
    let secret_encoded = secret.to_encoded().to_string();
    let secret_bytes = secret
        .to_bytes()
        .map_err(|e| AuthError::internal(format!("Failed to convert secret to bytes: {}", e)))?;

    let issuer = body.issuer.as_deref().unwrap_or(&config.issuer);
    let email = user.email().unwrap_or("user");

    let totp = build_totp(config, &secret_bytes, email, issuer)?;
    let totp_uri = totp.get_url();

    // Generate and hash backup codes
    let backup_codes = generate_backup_codes(config);
    let hashed_codes = hash_backup_codes(&backup_codes).await?;

    // Store 2FA record
    ctx.database
        .create_two_factor(CreateTwoFactor {
            user_id: user.id().to_string(),
            secret: secret_encoded,
            backup_codes: Some(hashed_codes),
        })
        .await?;

    // Update user flag
    ctx.database
        .update_user(
            user.id(),
            UpdateUser {
                two_factor_enabled: Some(true),
                ..Default::default()
            },
        )
        .await?;

    Ok(EnableResponse {
        totp_uri,
        backup_codes,
    })
}

async fn disable_core<DB: DatabaseAdapter>(
    body: &DisableRequest,
    user: &DB::User,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    verify_user_password(user, &body.password).await?;

    ctx.database.delete_two_factor(user.id()).await?;

    ctx.database
        .update_user(
            user.id(),
            UpdateUser {
                two_factor_enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;

    Ok(StatusResponse { status: true })
}

async fn get_totp_uri_core<DB: DatabaseAdapter>(
    body: &GetTotpUriRequest,
    user: &DB::User,
    config: &TwoFactorConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<TotpUriResponse> {
    verify_user_password(user, &body.password).await?;

    let two_factor = ctx
        .database
        .get_two_factor_by_user_id(user.id())
        .await?
        .ok_or_else(|| AuthError::not_found("Two-factor authentication not enabled"))?;

    let secret = Secret::Encoded(two_factor.secret().to_string());
    let secret_bytes = secret
        .to_bytes()
        .map_err(|e| AuthError::internal(format!("Failed to decode secret: {}", e)))?;

    let email = user.email().unwrap_or("user");
    let totp = build_totp(config, &secret_bytes, email, &config.issuer)?;

    Ok(TotpUriResponse {
        totp_uri: totp.get_url(),
    })
}

async fn generate_backup_codes_core<DB: DatabaseAdapter>(
    body: &GenerateBackupCodesRequest,
    user: &DB::User,
    config: &TwoFactorConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<BackupCodesResponse> {
    verify_user_password(user, &body.password).await?;

    // Generate new codes
    let backup_codes = generate_backup_codes(config);
    let hashed_codes = hash_backup_codes(&backup_codes).await?;

    ctx.database
        .update_two_factor_backup_codes(user.id(), &hashed_codes)
        .await?;

    Ok(BackupCodesResponse {
        status: true,
        backup_codes,
    })
}

// -- Session / auth helpers --

/// Extract the user_id from a `2fa_xxx` pending verification token.
async fn get_pending_2fa_user<DB: DatabaseAdapter>(
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<(DB::User, String)> {
    let token = req
        .headers
        .get("authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AuthError::Unauthenticated)?;

    if !token.starts_with("2fa_") {
        return Err(AuthError::bad_request("Invalid 2FA pending token"));
    }

    let identifier = format!("2fa_pending:{}", token);
    let verification = ctx
        .database
        .get_verification_by_identifier(&identifier)
        .await?
        .ok_or_else(|| AuthError::bad_request("Invalid or expired 2FA token"))?;

    if verification.expires_at() < chrono::Utc::now() {
        return Err(AuthError::bad_request("2FA token expired"));
    }

    let user_id = verification.value();
    let user = ctx
        .database
        .get_user_by_id(user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    Ok((user, verification.id().to_string()))
}

// -- Core functions (pending-2fa) --

/// Returns `(VerifyTotpResponse<DB::User>, session_token)`.
async fn verify_totp_core<DB: DatabaseAdapter>(
    body: &VerifyTotpRequest,
    user: &DB::User,
    verification_id: &str,
    config: &TwoFactorConfig,
    ctx: &AuthContext<DB>,
) -> AuthResult<(VerifyTotpResponse<DB::User>, String)> {
    let two_factor = ctx
        .database
        .get_two_factor_by_user_id(user.id())
        .await?
        .ok_or_else(|| AuthError::not_found("Two-factor authentication not enabled"))?;

    let secret = Secret::Encoded(two_factor.secret().to_string());
    let secret_bytes = secret
        .to_bytes()
        .map_err(|e| AuthError::internal(format!("Failed to decode secret: {}", e)))?;

    let email = user.email().unwrap_or("user");
    let totp = build_totp(config, &secret_bytes, email, &config.issuer)?;

    if !totp
        .check_current(&body.code)
        .map_err(|e| AuthError::internal(format!("TOTP check error: {}", e)))?
    {
        return Err(AuthError::bad_request("Invalid TOTP code"));
    }

    // Code valid — create session
    let session_manager =
        better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
    let session = session_manager.create_session(user, None, None).await?;

    // Delete the pending verification
    ctx.database.delete_verification(verification_id).await?;

    let token = session.token().to_string();
    let response = VerifyTotpResponse {
        status: true,
        token: token.clone(),
        user: user.clone(),
    };
    Ok((response, token))
}

async fn send_otp_core<DB: DatabaseAdapter>(
    user: &DB::User,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    // Generate 6-digit OTP
    use rand::Rng;
    let otp: String = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000u32));

    // Store the OTP verification (expires in 5 minutes)
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
    ctx.database
        .create_verification(CreateVerification {
            identifier: format!("2fa_otp:{}", user.id()),
            value: otp.clone(),
            expires_at,
        })
        .await?;

    // Send via email if provider is available
    if let Some(email) = user.email()
        && let Ok(provider) = ctx.email_provider()
    {
        let body = format!("Your 2FA verification code is: {}", otp);
        let _ = provider
            .send(email, "Your verification code", &body, &body)
            .await;
    }

    Ok(StatusResponse { status: true })
}

/// Returns `(VerifyTotpResponse<DB::User>, session_token)`.
async fn verify_otp_core<DB: DatabaseAdapter>(
    body: &VerifyOtpRequest,
    user: &DB::User,
    verification_id: &str,
    ctx: &AuthContext<DB>,
) -> AuthResult<(VerifyTotpResponse<DB::User>, String)> {
    // Look up the OTP verification
    let otp_identifier = format!("2fa_otp:{}", user.id());
    let otp_verification = ctx
        .database
        .get_verification_by_identifier(&otp_identifier)
        .await?
        .ok_or_else(|| AuthError::bad_request("No OTP found. Please request a new one."))?;

    if otp_verification.expires_at() < chrono::Utc::now() {
        return Err(AuthError::bad_request("OTP has expired"));
    }

    if otp_verification.value() != body.code {
        return Err(AuthError::bad_request("Invalid OTP code"));
    }

    // Valid — create session
    let session_manager =
        better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
    let session = session_manager.create_session(user, None, None).await?;

    // Clean up verifications
    ctx.database
        .delete_verification(otp_verification.id())
        .await?;
    ctx.database.delete_verification(verification_id).await?;

    let token = session.token().to_string();
    let response = VerifyTotpResponse {
        status: true,
        token: token.clone(),
        user: user.clone(),
    };
    Ok((response, token))
}

/// Returns `(VerifyBackupCodeResponse<DB::User, DB::Session>, session_token)`.
async fn verify_backup_code_core<DB: DatabaseAdapter>(
    body: &VerifyBackupCodeRequest,
    user: &DB::User,
    verification_id: &str,
    ctx: &AuthContext<DB>,
) -> AuthResult<(VerifyBackupCodeResponse<DB::User, DB::Session>, String)> {
    let two_factor = ctx
        .database
        .get_two_factor_by_user_id(user.id())
        .await?
        .ok_or_else(|| AuthError::not_found("Two-factor authentication not enabled"))?;

    let codes_json = two_factor
        .backup_codes()
        .ok_or_else(|| AuthError::bad_request("No backup codes available"))?;

    let hashed_codes: Vec<String> = serde_json::from_str(codes_json)
        .map_err(|e| AuthError::internal(format!("Failed to parse backup codes: {}", e)))?;

    // Try to match the provided code against each hashed code
    let mut matched_index: Option<usize> = None;

    for (i, hash_str) in hashed_codes.iter().enumerate() {
        if better_auth_core::verify_password(None, &body.code, hash_str)
            .await
            .is_ok()
        {
            matched_index = Some(i);
            break;
        }
    }

    let idx = matched_index.ok_or_else(|| AuthError::bad_request("Invalid backup code"))?;

    // Remove used code and update
    let mut remaining_codes = hashed_codes;
    remaining_codes.remove(idx);

    let updated_codes_json =
        serde_json::to_string(&remaining_codes).map_err(|e| AuthError::internal(e.to_string()))?;

    ctx.database
        .update_two_factor_backup_codes(user.id(), &updated_codes_json)
        .await?;

    // Create session
    let session_manager =
        better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
    let session = session_manager.create_session(user, None, None).await?;

    // Clean up pending verification
    ctx.database.delete_verification(verification_id).await?;

    let token = session.token().to_string();
    let response = VerifyBackupCodeResponse {
        user: user.clone(),
        session,
    };
    Ok((response, token))
}

// -- Old-style handlers (delegating to core functions) --

impl TwoFactorPlugin {
    async fn handle_enable<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: EnableRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = enable_core(&body, &user, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_disable<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: DisableRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = disable_core(&body, &user, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_get_totp_uri<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: GetTotpUriRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = get_totp_uri_core(&body, &user, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_verify_totp<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, verification_id) = get_pending_2fa_user(req, ctx).await?;
        let body: VerifyTotpRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let (response, token) =
            verify_totp_core(&body, &user, &verification_id, &self.config, ctx).await?;
        let cookie_header = create_session_cookie(&token, &ctx.config);
        Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
    }

    async fn handle_send_otp<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _verification_id) = get_pending_2fa_user(req, ctx).await?;
        let response = send_otp_core(&user, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_verify_otp<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, verification_id) = get_pending_2fa_user(req, ctx).await?;
        let body: VerifyOtpRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let (response, token) = verify_otp_core(&body, &user, &verification_id, ctx).await?;
        let cookie_header = create_session_cookie(&token, &ctx.config);
        Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
    }

    async fn handle_generate_backup_codes<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: GenerateBackupCodesRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = generate_backup_codes_core(&body, &user, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_verify_backup_code<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, verification_id) = get_pending_2fa_user(req, ctx).await?;
        let body: VerifyBackupCodeRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let (response, token) =
            verify_backup_code_core(&body, &user, &verification_id, ctx).await?;
        let cookie_header = create_session_cookie(&token, &ctx.config);
        Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
    }
}

impl Default for TwoFactorPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for TwoFactorPlugin {
    fn name(&self) -> &'static str {
        "two-factor"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/two-factor/enable", "enable_two_factor"),
            AuthRoute::post("/two-factor/disable", "disable_two_factor"),
            AuthRoute::post("/two-factor/get-totp-uri", "get_totp_uri"),
            AuthRoute::post("/two-factor/verify-totp", "verify_totp"),
            AuthRoute::post("/two-factor/send-otp", "send_otp"),
            AuthRoute::post("/two-factor/verify-otp", "verify_otp"),
            AuthRoute::post("/two-factor/generate-backup-codes", "generate_backup_codes"),
            AuthRoute::post("/two-factor/verify-backup-code", "verify_backup_code"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/two-factor/enable") => {
                Ok(Some(self.handle_enable(req, ctx).await?))
            }
            (HttpMethod::Post, "/two-factor/disable") => {
                Ok(Some(self.handle_disable(req, ctx).await?))
            }
            (HttpMethod::Post, "/two-factor/get-totp-uri") => {
                Ok(Some(self.handle_get_totp_uri(req, ctx).await?))
            }
            (HttpMethod::Post, "/two-factor/verify-totp") => {
                Ok(Some(self.handle_verify_totp(req, ctx).await?))
            }
            (HttpMethod::Post, "/two-factor/send-otp") => {
                Ok(Some(self.handle_send_otp(req, ctx).await?))
            }
            (HttpMethod::Post, "/two-factor/verify-otp") => {
                Ok(Some(self.handle_verify_otp(req, ctx).await?))
            }
            (HttpMethod::Post, "/two-factor/generate-backup-codes") => {
                Ok(Some(self.handle_generate_backup_codes(req, ctx).await?))
            }
            (HttpMethod::Post, "/two-factor/verify-backup-code") => {
                Ok(Some(self.handle_verify_backup_code(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(feature = "axum")]
mod axum_impl {
    use super::*;
    use std::sync::Arc;

    use axum::Json;
    use axum::extract::{Extension, State};
    use axum::http::header;
    use axum::response::IntoResponse;
    use better_auth_core::error::AuthError;
    use better_auth_core::extractors::{CurrentSession, Pending2faToken, ValidatedJson};
    use better_auth_core::plugin::AuthState;

    #[derive(Clone)]
    struct PluginState {
        config: TwoFactorConfig,
    }

    // -- Session-based handlers --

    async fn handle_enable<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<EnableRequest>,
    ) -> Result<Json<EnableResponse>, AuthError> {
        let ctx = state.to_context();
        let result = enable_core(&body, &user, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_disable<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<DisableRequest>,
    ) -> Result<Json<StatusResponse>, AuthError> {
        let ctx = state.to_context();
        let result = disable_core(&body, &user, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_get_totp_uri<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<GetTotpUriRequest>,
    ) -> Result<Json<TotpUriResponse>, AuthError> {
        let ctx = state.to_context();
        let result = get_totp_uri_core(&body, &user, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_generate_backup_codes<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<GenerateBackupCodesRequest>,
    ) -> Result<Json<BackupCodesResponse>, AuthError> {
        let ctx = state.to_context();
        let result = generate_backup_codes_core(&body, &user, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    // -- Pending-2fa handlers --

    async fn handle_verify_totp<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        Pending2faToken {
            user,
            verification_id,
        }: Pending2faToken<DB>,
        ValidatedJson(body): ValidatedJson<VerifyTotpRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let ctx = state.to_context();
        let (response, token) =
            verify_totp_core(&body, &user, &verification_id, &ps.config, &ctx).await?;
        let cookie = state.session_cookie(&token);
        Ok(([(header::SET_COOKIE, cookie)], Json(response)))
    }

    async fn handle_send_otp<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Pending2faToken { user, .. }: Pending2faToken<DB>,
    ) -> Result<Json<StatusResponse>, AuthError> {
        let ctx = state.to_context();
        let result = send_otp_core(&user, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_verify_otp<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Pending2faToken {
            user,
            verification_id,
        }: Pending2faToken<DB>,
        ValidatedJson(body): ValidatedJson<VerifyOtpRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let ctx = state.to_context();
        let (response, token) = verify_otp_core(&body, &user, &verification_id, &ctx).await?;
        let cookie = state.session_cookie(&token);
        Ok(([(header::SET_COOKIE, cookie)], Json(response)))
    }

    async fn handle_verify_backup_code<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Pending2faToken {
            user,
            verification_id,
        }: Pending2faToken<DB>,
        ValidatedJson(body): ValidatedJson<VerifyBackupCodeRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let ctx = state.to_context();
        let (response, token) =
            verify_backup_code_core(&body, &user, &verification_id, &ctx).await?;
        let cookie = state.session_cookie(&token);
        Ok(([(header::SET_COOKIE, cookie)], Json(response)))
    }

    impl<DB: DatabaseAdapter> better_auth_core::AxumPlugin<DB> for TwoFactorPlugin {
        fn name(&self) -> &'static str {
            "two-factor"
        }

        fn router(&self) -> axum::Router<AuthState<DB>> {
            use axum::routing::post;

            let plugin_state = Arc::new(PluginState {
                config: self.config.clone(),
            });
            axum::Router::new()
                .route("/two-factor/enable", post(handle_enable::<DB>))
                .route("/two-factor/disable", post(handle_disable::<DB>))
                .route("/two-factor/get-totp-uri", post(handle_get_totp_uri::<DB>))
                .route("/two-factor/verify-totp", post(handle_verify_totp::<DB>))
                .route("/two-factor/send-otp", post(handle_send_otp::<DB>))
                .route("/two-factor/verify-otp", post(handle_verify_otp::<DB>))
                .route(
                    "/two-factor/generate-backup-codes",
                    post(handle_generate_backup_codes::<DB>),
                )
                .route(
                    "/two-factor/verify-backup-code",
                    post(handle_verify_backup_code::<DB>),
                )
                .layer(Extension(plugin_state))
        }
    }
}
