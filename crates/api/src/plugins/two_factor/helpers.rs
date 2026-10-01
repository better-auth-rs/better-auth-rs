use super::*;
pub(super) fn build_totp(
    config: &TwoFactorConfig,
    secret: &str,
    request_issuer: Option<&str>,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<TOTP> {
    let issuer = request_issuer
        .map(str::to_owned)
        .unwrap_or_else(|| ctx.config.app_name.clone());
    let account_name = user.email().unwrap_or("user").to_string();
    TOTP::new(
        Algorithm::SHA1,
        if config.totp_digits == 0 {
            6
        } else {
            config.totp_digits
        },
        1,
        if config.totp_period == 0 {
            30
        } else {
            config.totp_period
        },
        secret.as_bytes().to_vec(),
        Some(issuer),
        account_name,
    )
    .map_err(|error| AuthError::internal(format!("Failed to create TOTP: {}", error)))
}

pub(super) async fn verify_user_password(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user: &impl AuthUser,
    password: Option<&str>,
    allow_passwordless: bool,
    hash_missing_password: bool,
) -> AuthResult<()> {
    let stored_hash = get_credential_password_hash(ctx, user).await?;
    if allow_passwordless && stored_hash.as_deref().is_none_or(str::is_empty) {
        return Ok(());
    }
    let password = password
        .filter(|password| !password.is_empty())
        .ok_or_else(|| AuthError::bad_request("Invalid password"))?;
    if password.encode_utf16().count() > ctx.password_policy.max_length {
        return Err(AuthError::bad_request("Password too long"));
    }
    let Some(stored_hash) = stored_hash.filter(|hash| !hash.is_empty()) else {
        if hash_missing_password {
            _ = better_auth_core::hash_password(ctx.password_policy.hasher.as_ref(), password)
                .await?;
        }
        return Err(AuthError::bad_request("Invalid password"));
    };
    match better_auth_core::verify_password(
        ctx.password_policy.hasher.as_ref(),
        password,
        &stored_hash,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(AuthError::InvalidCredentials) => Err(AuthError::bad_request("Invalid password")),
        Err(error) => Err(error),
    }
}

pub(super) fn generate_secret() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

pub(super) fn otp_verification_identifier(key: &str) -> String {
    format!("2fa-otp-{}", key)
}

pub(super) fn two_factor_cookie_max_age(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> i64 {
    ctx.get_metadata(METADATA_TWO_FACTOR_COOKIE_MAX_AGE)
        .and_then(|value| value.as_i64())
        .unwrap_or(DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS)
}

pub(super) fn trust_device_max_age(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> i64 {
    ctx.get_metadata(METADATA_TRUST_DEVICE_MAX_AGE)
        .and_then(|value| value.as_i64())
        .unwrap_or(DEFAULT_TRUST_DEVICE_MAX_AGE_SECS)
}

pub(super) fn clear_cookie_header(config: &better_auth_core::AuthConfig, suffix: &str) -> String {
    create_clear_cookie(&related_cookie_name(config, suffix), config)
}

pub(super) async fn create_trust_device_cookie_header(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<String> {
    let identifier = format!("trust-device-{}", uuid::Uuid::new_v4());
    let token = sign_value(
        ctx.config.signing_secret(),
        &format!("{}!{}", user.id().display_string()?, identifier),
    )?;
    let value = format!("{}!{}", token, identifier);
    let expires_at = Utc::now() + Duration::seconds(trust_device_max_age(ctx));
    _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: (identifier.clone()).into(),
            value: user.id().into_owned(),
            expires_at: (expires_at).into(),
            ..Default::default()
        })
        .await?;
    create_signed_cookie_header(
        ctx.config.signing_secret(),
        &ctx.config,
        TRUST_DEVICE_COOKIE_SUFFIX,
        &value,
        Some(trust_device_max_age(ctx)),
    )
}

pub(super) fn create_signed_cookie_header(
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

pub(super) fn read_signed_cookie<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    suffix: &str,
    ctx: &AuthContext<S>,
) -> AuthResult<Option<String>> {
    let cookie_name = related_cookie_name(&ctx.config, suffix);
    let Some(raw_cookie) = get_cookie(req, &cookie_name) else {
        return Ok(None);
    };
    verify_signed_cookie_value(ctx.config.signing_secret(), &raw_cookie)
}

pub(super) fn sign_cookie_value(secret: &str, value: &str) -> AuthResult<String> {
    Ok(format!("{}.{}", value, sign_value(secret, value)?))
}

pub(super) fn verify_signed_cookie_value(
    secret: &str,
    signed_value: &str,
) -> AuthResult<Option<String>> {
    let Some((value, signature)) = signed_value.rsplit_once('.') else {
        return Ok(None);
    };
    Ok(verify_signature(secret, value, signature)?.then(|| value.to_string()))
}

pub(super) fn sign_value(secret: &str, value: &str) -> AuthResult<String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|error| AuthError::internal(format!("Failed to initialize HMAC: {}", error)))?;
    mac.update(value.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

pub(super) fn verify_signature(secret: &str, value: &str, signature: &str) -> AuthResult<bool> {
    let decoded = match URL_SAFE_NO_PAD.decode(signature) {
        Ok(decoded) => decoded,
        Err(_) => return Ok(false),
    };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|error| AuthError::internal(format!("Failed to initialize HMAC: {}", error)))?;
    mac.update(value.as_bytes());
    Ok(mac.verify_slice(&decoded).is_ok())
}

pub(super) fn encrypt_value<'a>(
    secret: impl Into<better_auth_core::SecretKey<'a>>,
    plaintext: &str,
) -> AuthResult<String> {
    crate::plugins::symmetric::encrypt(secret, plaintext)
}

pub(super) fn decrypt_value<'a>(
    secret: impl Into<better_auth_core::SecretKey<'a>>,
    encrypted: &str,
) -> AuthResult<String> {
    crate::plugins::symmetric::decrypt(secret, encrypted)
}

pub(super) fn require_totp(config: &TwoFactorConfig) -> AuthResult<()> {
    if config.totp_disabled {
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOTP_NOT_CONFIGURED",
            message: "totp isn't configured",
        });
    }
    Ok(())
}
