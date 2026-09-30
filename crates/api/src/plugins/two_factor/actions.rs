use super::*;

pub(super) async fn enable_core(
    body: &EnableRequest,
    user: &impl AuthUser,
    current_session: &impl AuthSession,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(EnableResponse, Vec<String>)> {
    verify_user_password(ctx, user, &body.password).await?;
    if body.method == EnrollmentMethod::Otp {
        if config.send_otp.is_none() {
            return Err(AuthError::Upstream {
                status: 400,
                code: "OTP_NOT_CONFIGURED",
                message: "otp isn't configured",
            });
        }
        let updated = ctx
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
            updated.id().as_ref(),
            current_session.ip_address().map(str::to_owned),
            current_session.user_agent().map(str::to_owned),
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?;
        ctx.database.delete_session(current_session.token()).await?;
        return Ok((
            EnableResponse {
                method: "otp",
                totp_uri: None,
                backup_codes: None,
            },
            vec![create_session_cookie(issued.session.token(), &ctx.config)],
        ));
    }
    let existing = ctx
        .database
        .get_two_factor_by_user_id(user.id().as_ref())
        .await?;
    if existing.as_ref().is_some_and(|factor| factor.verified) {
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOTP_ALREADY_ENABLED",
            message: "TOTP is already enabled",
        });
    }

    let secret = generate_secret();
    let encrypted_secret = encrypt_value(&ctx.config.secret, &secret)?;
    let backup_codes = generate_backup_codes();
    let encrypted_backup_codes =
        encrypt_value(&ctx.config.secret, &serde_json::to_string(&backup_codes)?)?;

    if let Some(existing) = existing {
        let _ = ctx
            .database
            .update_two_factor(
                &existing.id,
                better_auth_core::UpdateTwoFactor {
                    secret: Some(encrypted_secret),
                    backup_codes: Some(encrypted_backup_codes),
                    verified: Some(config.skip_verification_on_enable),
                },
            )
            .await?;
    } else {
        let _ = ctx
            .database
            .create_two_factor(CreateTwoFactor {
                user_id: user.id().to_string(),
                secret: encrypted_secret,
                backup_codes: encrypted_backup_codes,
                verified: config.skip_verification_on_enable,
            })
            .await?;
    }

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
            method: "totp",
            totp_uri: Some(totp_uri),
            backup_codes: Some(backup_codes),
        },
        set_cookie_headers,
    ))
}

pub(super) async fn disable_core(
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

pub(super) async fn get_totp_uri_core(
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

pub(super) async fn verify_totp_core(
    req: &AuthRequest,
    body: &VerifyTotpRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    let state = resolve_two_factor_state(req, ctx).await?;
    let two_factor = load_two_factor_record(state.user(), ctx).await?;
    if state.is_sign_in() && !two_factor.verified {
        return Err(AuthError::bad_request("TOTP not enabled"));
    }
    assert_not_locked(&state, &two_factor, &config.account_lockout, ctx).await?;
    let attempt = begin_attempt(&state, req, ctx).await?;
    let valid = (|| {
        let secret = decrypt_value(&ctx.config.secret, two_factor.secret())?;
        build_totp(config, &secret, None, state.user(), ctx)?
            .check_current(&body.code)
            .map_err(|error| AuthError::internal(format!("Failed to verify TOTP: {error}")))
    })();
    let valid = match valid {
        Ok(valid) => valid,
        Err(error) => {
            finish_attempt(attempt, false, ctx).await;
            return Err(error);
        }
    };
    if !valid {
        finish_attempt(attempt, true, ctx).await;
        record_failure(&state, &two_factor, &config.account_lockout, ctx).await?;
        return Err(AuthError::authentication_failed("Invalid code"));
    }
    reset_failures(&state, &two_factor, &config.account_lockout, ctx).await?;
    if !two_factor.verified {
        let _ = ctx
            .database
            .update_two_factor(
                &two_factor.id,
                better_auth_core::UpdateTwoFactor {
                    verified: Some(true),
                    ..Default::default()
                },
            )
            .await?;
    }

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            verify_existing_session_factor(user, *session, Some(EnrollmentMethod::Totp), ctx).await
        }
        ResolvedTwoFactorState::Pending(pending) => {
            finalize_pending_two_factor(pending, req, body.trust_device.unwrap_or(false), ctx).await
        }
    }
}

pub(super) async fn send_otp_core(
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
    let hashed_otp = hash_otp(&otp)?;
    let identifier = otp_verification_identifier(state.key());

    _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier,
            value: format!("{}:0", hashed_otp),
            expires_at: Utc::now() + Duration::seconds(DEFAULT_OTP_LIFETIME_SECS),
        })
        .await?;

    if let Err(error) = sender.send(state.user(), &otp).await {
        tracing::warn!(error = %error, "Failed to send two-factor OTP");
    }

    Ok(StatusResponse { status: true })
}

pub(super) async fn verify_otp_core(
    req: &AuthRequest,
    body: &VerifyOtpRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    let state = resolve_two_factor_state(req, ctx).await?;
    let factor = if state.is_sign_in() {
        ctx.database
            .get_two_factor_by_user_id(state.user().id().as_ref())
            .await?
    } else {
        None
    };
    if let Some(factor) = &factor {
        assert_not_locked(&state, factor, &config.account_lockout, ctx).await?;
    }
    let identifier = otp_verification_identifier(state.key());
    let Some(verification) = ctx
        .database
        .consume_verification_by_identifier(&identifier)
        .await?
    else {
        return Err(AuthError::bad_request("OTP has expired"));
    };

    let Some((stored_hash, counter)) = verification.value().rsplit_once(':') else {
        return Err(AuthError::internal("Malformed OTP verification payload"));
    };

    let attempts = counter.parse::<usize>().map_err(|error| {
        AuthError::internal(format!("Malformed OTP attempt counter: {}", error))
    })?;
    if attempts >= DEFAULT_OTP_ATTEMPT_LIMIT {
        return Err(AuthError::bad_request(
            "Too many attempts. Please request a new code.",
        ));
    }

    let is_valid = verify_otp(&body.code, stored_hash)?;

    if !is_valid {
        let next_value = format!("{}:{}", stored_hash, attempts + 1);
        let expires_at = verification.expires_at();
        let verification_identifier = verification.identifier().to_string();
        _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: verification_identifier,
                value: next_value,
                expires_at,
            })
            .await?;
        if let Some(factor) = &factor {
            record_failure(&state, factor, &config.account_lockout, ctx).await?;
        }
        return Err(AuthError::authentication_failed("Invalid code"));
    }
    if let Some(factor) = &factor {
        reset_failures(&state, factor, &config.account_lockout, ctx).await?;
    }

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            verify_existing_session_factor(user, *session, Some(EnrollmentMethod::Otp), ctx).await
        }
        ResolvedTwoFactorState::Pending(pending) => {
            finalize_pending_two_factor(pending, req, body.trust_device.unwrap_or(false), ctx).await
        }
    }
}

pub(super) async fn generate_backup_codes_core(
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

pub(super) async fn verify_backup_code_core(
    req: &AuthRequest,
    body: &VerifyBackupCodeRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    let state = resolve_two_factor_state(req, ctx).await?;
    let two_factor = ctx
        .database
        .get_two_factor_by_user_id(state.user().id().as_ref())
        .await?
        .ok_or_else(|| AuthError::bad_request("Backup codes aren't enabled"))?;
    assert_not_locked(&state, &two_factor, &config.account_lockout, ctx).await?;
    let attempt = begin_attempt(&state, req, ctx).await?;
    let decoded = match decrypt_backup_codes(two_factor.backup_codes(), &ctx.config.secret) {
        Ok(codes) => codes,
        Err(error) => {
            finish_attempt(attempt, false, ctx).await;
            return Err(error);
        }
    };
    let Some(mut backup_codes) = decoded else {
        finish_attempt(attempt, true, ctx).await;
        record_failure(&state, &two_factor, &config.account_lockout, ctx).await?;
        return Err(AuthError::authentication_failed("Invalid backup code"));
    };
    let Some(index) = backup_codes
        .iter()
        .position(|candidate| candidate == &body.code)
    else {
        finish_attempt(attempt, true, ctx).await;
        record_failure(&state, &two_factor, &config.account_lockout, ctx).await?;
        return Err(AuthError::authentication_failed("Invalid backup code"));
    };
    let _ = backup_codes.remove(index);

    let encrypted = encrypt_value(&ctx.config.secret, &serde_json::to_string(&backup_codes)?)?;
    if !ctx
        .database
        .compare_exchange_two_factor_backup_codes(
            &two_factor.id,
            &two_factor.backup_codes,
            &encrypted,
        )
        .await?
    {
        return Err(AuthError::conflict(
            "Failed to verify backup code. Please try again.",
        ));
    }
    reset_failures(&state, &two_factor, &config.account_lockout, ctx).await?;

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            if body.disable_session.unwrap_or(false) {
                Ok((
                    SessionTokenResponse {
                        token: Some(session.token().to_string()),
                        user: ctx.user_view(&user)?,
                    },
                    Vec::new(),
                ))
            } else {
                verify_existing_session_factor(user, *session, None, ctx).await
            }
        }
        ResolvedTwoFactorState::Pending(pending) => {
            if body.disable_session.unwrap_or(false) {
                return Ok((
                    SessionTokenResponse {
                        token: None,
                        user: pending.user,
                    },
                    Vec::new(),
                ));
            }
            finalize_pending_two_factor(pending, req, body.trust_device.unwrap_or(false), ctx).await
        }
    }
}

pub(super) async fn view_backup_codes_core<S: better_auth_core::AuthSchema>(
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
