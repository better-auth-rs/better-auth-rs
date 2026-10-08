use super::*;

pub(super) async fn issue_factor_session(
    req: &AuthRequest,
    owner: SchemaValue<String>,
    user: FieldValue,
    inherited_fields: FieldMap,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<better_auth_core::wire::SessionView> {
    admit_session_for_id(ctx, &owner, None)
        .await
        .map_err(SessionIssueError::into_auth_error)?;
    let meta = RequestMeta::from_request_with_config(req, &ctx.config.advanced.ip_address);
    let session = ctx
        .database
        .create_session_optional(better_auth_core::CreateSession {
            inherited_fields,
            additional_fields: Default::default(),
            user_id: owner,
            expires_at: (Utc::now() + ctx.config.session.expires_in()).into(),
            ip_address: meta.ip_address,
            user_agent: meta.user_agent,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?
        .ok_or_else(|| AuthError::internal("Cannot read properties of null (reading 'token')"))?;
    ctx.session_manager()
        .set_native_session_cookie(
            req,
            better_auth_core::session::NativeSessionData {
                user,
                session: session.clone(),
            },
            None,
        )
        .await?;
    Ok(session)
}

pub(super) async fn update_two_factor_user(
    user: &impl AuthUser,
    enabled: bool,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Option<UserView>> {
    ctx.database
        .update_user_by_id_value(
            &user.id().field_value(),
            UpdateUser {
                two_factor_enabled: Some(enabled),
                ..Default::default()
            },
        )
        .await
}

pub(super) async fn delete_factor_session(
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    ctx.database
        .delete_session_by_token_value(
            &session
                .field_values()?
                .get("token")
                .cloned()
                .unwrap_or_default(),
        )
        .await
}

pub(super) fn build_totp(
    config: &TwoFactorConfig,
    secret: &str,
    request_issuer: Option<&str>,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<totp::Totp> {
    let issuer = request_issuer
        .map(str::to_owned)
        .unwrap_or_else(|| ctx.config.app_name.clone());
    let account_name = user
        .field_values()?
        .get("email")
        .cloned()
        .unwrap_or_default()
        .display_utf16()?
        .to_utf8()
        .map_err(|_| AuthError::internal("URI malformed"))?;
    let inner = TOTP::new_unchecked(
        Algorithm::SHA1,
        if config.totp_digits == 0 {
            6
        } else {
            config.totp_digits
        },
        1,
        1,
        secret.as_bytes().to_vec(),
        Some(issuer),
        account_name,
    );
    Ok(totp::Totp::new(inner, config.totp_period))
}

pub(super) fn totp_verifier(config: &TwoFactorConfig, secret: &str) -> totp::Totp {
    totp::Totp::new(
        TOTP::new_unchecked(
            Algorithm::SHA1,
            if config.totp_digits == 0 {
                6
            } else {
                config.totp_digits
            },
            1,
            1,
            secret.as_bytes().to_vec(),
            None,
            String::new(),
        ),
        config.totp_period,
    )
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

pub(super) fn split_otp_record(value: &FieldValue) -> AuthResult<(FieldValue, f64)> {
    if value.is_null() || value.is_undefined() {
        return Ok((FieldValue::Undefined, 0.0));
    }
    let units = better_auth_core::query::field_string_units(value)
        .ok_or_else(|| AuthError::internal("consumed.value?.split is not a function"))?;
    let mut parts = units.split(|unit| *unit == u16::from(b':'));
    let otp =
        better_auth_core::Utf16String::from_units(parts.next().unwrap_or_default().to_vec()).into();
    let counter = String::from_utf16_lossy(parts.next().unwrap_or_default());
    let counter = counter
        .trim_start_matches(|ch: char| (ch.is_whitespace() && ch != '\u{85}') || ch == '\u{feff}');
    let (sign, counter) = if let Some(counter) = counter.strip_prefix('-') {
        (-1.0, counter)
    } else {
        (1.0, counter.strip_prefix('+').unwrap_or(counter))
    };
    let count = counter
        .bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0.0, |count, byte| count * 10.0 + f64::from(byte - b'0'));
    Ok((otp, sign * count))
}

pub(super) fn two_factor_cookie_max_age(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> f64 {
    ctx.extensions
        .get::<TwoFactorConfig>()
        .map_or(DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS, |config| {
            config.two_factor_cookie_max_age
        })
}

pub(super) fn trust_device_max_age(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> f64 {
    ctx.extensions
        .get::<TwoFactorConfig>()
        .map_or(DEFAULT_TRUST_DEVICE_MAX_AGE_SECS, |config| {
            config.trust_device_max_age
        })
}

pub(super) fn cookie_expires_at(seconds: f64) -> AuthResult<chrono::DateTime<Utc>> {
    better_auth_core::utils::date::from_milliseconds(
        Utc::now().timestamp_millis() as f64 + seconds * 1000.0,
    )
    .ok_or_else(|| AuthError::config("Two Factor cookie expiry is out of range"))
}

pub(super) fn clear_cookie_header(
    req: &AuthRequest,
    config: &better_auth_core::AuthConfig,
    suffix: &str,
) -> AuthResult<String> {
    let name = related_cookie_name(config, suffix);
    better_auth_core::utils::cookie_utils::remove_set_cookie_entries(req, None, &name)?;
    create_clear_cookie(&name, config)
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
    let max_age = trust_device_max_age(ctx);
    let expires_at = cookie_expires_at(max_age)?;
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
        Some(max_age),
    )
}

pub(super) fn create_signed_cookie_header(
    secret: &str,
    config: &better_auth_core::AuthConfig,
    suffix: &str,
    value: &str,
    max_age_seconds: Option<f64>,
) -> AuthResult<String> {
    let cookie_name = related_cookie_name(config, suffix);
    let signed_value = sign_cookie_value(secret, value)?;
    create_session_like_cookie(&cookie_name, &signed_value, max_age_seconds, config)
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
    Ok(better_auth_core::utils::cookie_utils::sign_cookie_value(
        value, secret,
    ))
}

pub(super) fn verify_signed_cookie_value(
    secret: &str,
    signed_value: &str,
) -> AuthResult<Option<String>> {
    Ok(better_auth_core::utils::cookie_utils::verify_cookie_value(
        signed_value,
        secret,
    ))
}

pub(super) fn sign_value(secret: &str, value: &str) -> AuthResult<String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|error| AuthError::internal(format!("Failed to initialize HMAC: {}", error)))?;
    mac.update(value.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

pub(super) fn encrypt_value<'a>(
    secret: impl Into<better_auth_core::SecretKey<'a>>,
    plaintext: &str,
) -> AuthResult<String> {
    crate::plugins::symmetric::encrypt(secret, plaintext)
}

#[cfg(test)]
pub(super) fn decrypt_value<'a>(
    secret: impl Into<better_auth_core::SecretKey<'a>>,
    encrypted: &SchemaValue<String>,
) -> AuthResult<String> {
    crate::plugins::symmetric::decrypt_field(secret, &encrypted.field_value())
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
