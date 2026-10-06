use super::*;

pub(super) async fn enable_core<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    body: &EnableRequest,
    user: &impl AuthUser,
    current_session: &impl AuthSession,
    config: &TwoFactorConfig,
    ctx: &AuthContext<S>,
) -> AuthResult<(EnableResponse, Vec<String>)> {
    verify_user_password(
        ctx,
        user,
        body.password.as_deref(),
        config.allow_passwordless,
        false,
    )
    .await?;
    if body.method == EnrollmentMethod::Otp {
        if config.send_otp.is_none()
            && !ctx
                .extensions
                .get::<Arc<TwoFactorCallbacks<S>>>()
                .is_some_and(|callbacks| callbacks.sender.is_some())
        {
            return Err(AuthError::Upstream {
                status: 400,
                code: "OTP_NOT_CONFIGURED",
                message: "OTP is not available",
            });
        }
        let updated = ctx
            .database
            .update_user(
                user.id().typed()?,
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let issued = issue_user_session(
            ctx,
            updated.id().typed()?,
            current_session.ip_address().map(str::to_owned),
            current_session.user_agent().map(str::to_owned),
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?;
        let manager = ctx.session_manager();
        manager
            .set_session_cookie(
                req,
                manager.internal_data(&issued.user, &issued.session).await?,
                None,
            )
            .await?;
        ctx.database.delete_session(current_session.token()).await?;
        return Ok((
            EnableResponse {
                method: "otp",
                totp_uri: None,
                backup_codes: None,
            },
            Vec::new(),
        ));
    }
    if config.totp_disabled {
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOTP_NOT_CONFIGURED",
            message: "TOTP is not available",
        });
    }
    let existing = ctx
        .database
        .get_two_factor_by_user_id(user.id().typed()?)
        .await?;
    if existing
        .as_ref()
        .is_some_and(|factor| factor.verified != Some(false))
    {
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOTP_ALREADY_ENABLED",
            message: "TOTP is already enabled",
        });
    }

    let backup_codes = config.backup_code_options.generate();
    let encrypted_backup_codes = config
        .backup_code_options
        .storage
        .encode(&backup_codes, ctx.config.encryption_secret())
        .await?;
    let secret = generate_secret();
    let encrypted_secret = encrypt_value(ctx.config.encryption_secret(), &secret)?;

    let set_cookie_headers = Vec::new();
    if config.skip_verification_on_enable {
        let updated_user = ctx
            .database
            .update_user(
                user.id().typed()?,
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let issued = issue_user_session(
            ctx,
            updated_user.id().typed()?,
            current_session.ip_address().map(str::to_owned),
            current_session.user_agent().map(str::to_owned),
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?;
        let manager = ctx.session_manager();
        manager
            .set_session_cookie(
                req,
                manager.internal_data(&issued.user, &issued.session).await?,
                None,
            )
            .await?;
        ctx.database.delete_session(current_session.token()).await?;
    }

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
                user_id: user.id().typed()?.to_string(),
                secret: encrypted_secret,
                backup_codes: encrypted_backup_codes,
                verified: config.skip_verification_on_enable,
            })
            .await?;
    }

    let totp_uri = build_totp(
        config,
        &secret,
        body.issuer
            .as_deref()
            .filter(|issuer| !issuer.is_empty())
            .or(config.issuer.as_deref().filter(|issuer| !issuer.is_empty())),
        user,
        ctx,
    )?
    .get_url()?;
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
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(StatusResponse, Vec<String>)> {
    verify_user_password(
        ctx,
        user,
        body.password.as_deref(),
        config.allow_passwordless,
        false,
    )
    .await?;

    let updated_user = ctx
        .database
        .update_user(
            user.id().typed()?,
            UpdateUser {
                two_factor_enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;
    ctx.database.delete_two_factor(user.id().typed()?).await?;

    let issued = issue_user_session(
        ctx,
        updated_user.id().typed()?,
        current_session.ip_address().map(str::to_owned),
        current_session.user_agent().map(str::to_owned),
    )
    .await
    .map_err(SessionIssueError::into_auth_error)?;
    let manager = ctx.session_manager();
    manager
        .set_session_cookie(
            req,
            manager.internal_data(&issued.user, &issued.session).await?,
            None,
        )
        .await?;
    ctx.database.delete_session(current_session.token()).await?;

    let mut set_cookie_headers = Vec::new();

    if let Some(trust_cookie) = read_signed_cookie(req, TRUST_DEVICE_COOKIE_SUFFIX, ctx)? {
        if let Some(trust_identifier) = trust_cookie
            .split('!')
            .nth(1)
            .filter(|value| !value.is_empty())
        {
            ctx.database
                .delete_verification_by_identifier(trust_identifier)
                .await?;
        }
        set_cookie_headers.push(clear_cookie_header(
            req,
            &ctx.config,
            TRUST_DEVICE_COOKIE_SUFFIX,
        )?);
    }

    Ok((StatusResponse { status: true }, set_cookie_headers))
}

pub(super) async fn get_totp_uri_core(
    body: &GetTotpUriRequest,
    user: &impl AuthUser,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<TotpUriResponse> {
    require_totp(config)?;
    let two_factor = load_two_factor_record(user, ctx).await?;
    let secret = decrypt_value(ctx.config.encryption_secret(), two_factor.secret())?;
    verify_user_password(
        ctx,
        user,
        body.password.as_deref(),
        config
            .totp_allow_passwordless
            .unwrap_or(config.allow_passwordless),
        true,
    )
    .await?;
    Ok(TotpUriResponse {
        totp_uri: build_totp(config, &secret, None, user, ctx)?.get_url()?,
    })
}

pub(super) async fn verify_totp_core(
    req: &AuthRequest,
    body: &VerifyTotpRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    require_totp(config)?;
    let state = resolve_two_factor_state(req, ctx).await?;
    let two_factor = load_two_factor_record(state.user(), ctx).await?;
    if state.is_sign_in() && two_factor.verified == Some(false) {
        return Err(AuthError::bad_request("TOTP not enabled"));
    }
    assert_not_locked(&state, &two_factor, &config.account_lockout, ctx).await?;
    let attempt = begin_attempt(&state, req, ctx).await?;
    let valid = (|| {
        let secret = decrypt_value(ctx.config.encryption_secret(), two_factor.secret())?;
        build_totp(config, &secret, None, state.user(), ctx)?.check_current(&body.code)
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
    let needs_enrollment = two_factor.verified != Some(true);
    let update_enrollment = async {
        if needs_enrollment {
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
        Ok::<(), AuthError>(())
    };

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            verify_existing_session_factor(
                req,
                user,
                *session,
                needs_enrollment.then_some(EnrollmentMethod::Totp),
                ctx,
                update_enrollment,
            )
            .await
        }
        ResolvedTwoFactorState::Pending(pending) => {
            update_enrollment.await?;
            finalize_pending_two_factor(pending, req, body.trust_device.unwrap_or(false), ctx).await
        }
    }
}

pub(super) async fn send_otp_core<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<S>,
) -> AuthResult<StatusResponse> {
    enum Sender<C, L> {
        Callback(C),
        Legacy(L),
    }

    let body = request::read::<serde_json::Value>(req, false)?;
    let callback = ctx
        .extensions
        .get::<Arc<TwoFactorCallbacks<S>>>()
        .and_then(|callbacks| callbacks.sender.as_ref());
    let sender = match (callback, config.send_otp.as_ref()) {
        (Some(callback), _) => Sender::Callback(callback),
        (None, Some(sender)) => Sender::Legacy(sender),
        (None, None) => return Err(AuthError::bad_request("otp isn't configured")),
    };
    let state = resolve_two_factor_state(req, ctx).await?;
    let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(Some(req), body, ctx);
    if let ResolvedTwoFactorState::Session { user, session, .. } = &state {
        endpoint.session = Some((user.clone(), *session.clone()));
    }

    let otp: String = (0..config.otp_digits)
        .map(|_| char::from(b'0' + rand::thread_rng().gen_range(0..10)))
        .collect();
    let stored_otp = config
        .otp_storage
        .encode(&otp, ctx.config.encryption_secret())
        .await?;
    let identifier = otp_verification_identifier(state.key());

    _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: (identifier).into(),
            value: (format!("{}:0", stored_otp)).into(),
            expires_at: (Utc::now()
                + if config.otp_period.is_zero() {
                    Duration::minutes(3)
                } else {
                    config.otp_period
                })
            .into(),
            ..Default::default()
        })
        .await?;

    let task: Option<better_auth_core::background::BackgroundFuture> = match sender {
        Sender::Callback(callback) => callback(state.user(), &otp, &endpoint)?,
        Sender::Legacy(sender) => {
            let sender = sender.clone();
            let user = state.user().clone();
            Some(Box::pin(async move { sender.send(&user, &otp).await }))
        }
    };
    better_auth_core::background::run_or_await_with_error_message(
        task,
        ctx.config.advanced.background_tasks.as_ref(),
        &ctx.config.logger,
        "Failed to send two-factor OTP",
    )
    .await;

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
            .get_two_factor_by_user_id(state.user().id().typed()?)
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

    let value = verification.value.typed()?;
    let mut parts = value.split(':');
    let stored_otp = parts.next().unwrap_or_default();
    let attempts = parts
        .next()
        .and_then(|counter| counter.parse::<usize>().ok())
        .unwrap_or(0);
    if attempts
        >= if config.otp_allowed_attempts == 0 {
            5
        } else {
            config.otp_allowed_attempts
        }
    {
        return Err(AuthError::bad_request(
            "Too many attempts. Please request a new code.",
        ));
    }

    let is_valid = config
        .otp_storage
        .verify(stored_otp, &body.code, ctx.config.encryption_secret())
        .await?;

    if !is_valid {
        let next_value = format!("{}:{}", stored_otp, attempts + 1);
        let expires_at = verification.expires_at.clone();
        _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: (identifier).into(),
                value: (next_value).into(),
                expires_at,
                ..Default::default()
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
            verify_existing_session_factor(
                req,
                user,
                *session,
                Some(EnrollmentMethod::Otp),
                ctx,
                std::future::ready(Ok(())),
            )
            .await
        }
        ResolvedTwoFactorState::Pending(pending) => {
            finalize_pending_two_factor(pending, req, body.trust_device.unwrap_or(false), ctx).await
        }
    }
}

pub(super) async fn generate_backup_codes_core(
    body: &GenerateBackupCodesRequest,
    user: &impl AuthUser,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<BackupCodesResponse> {
    if !user.two_factor_enabled() {
        return Err(AuthError::bad_request("Two factor isn't enabled"));
    }

    verify_user_password(
        ctx,
        user,
        body.password.as_deref(),
        config
            .backup_code_options
            .allow_passwordless
            .unwrap_or(config.allow_passwordless),
        true,
    )
    .await?;
    let two_factor = load_two_factor_record(user, ctx).await?;

    let backup_codes = config.backup_code_options.generate();
    let encrypted = config
        .backup_code_options
        .storage
        .encode(&backup_codes, ctx.config.encryption_secret())
        .await?;
    _ = ctx
        .database
        .update_two_factor(
            &two_factor.id,
            better_auth_core::UpdateTwoFactor {
                backup_codes: Some(encrypted),
                ..Default::default()
            },
        )
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
        .get_two_factor_by_user_id(state.user().id().typed()?)
        .await?
        .ok_or_else(|| AuthError::bad_request("Backup codes aren't enabled"))?;
    assert_not_locked(&state, &two_factor, &config.account_lockout, ctx).await?;
    let attempt = begin_attempt(&state, req, ctx).await?;
    let decoded = match config
        .backup_code_options
        .storage
        .decode(two_factor.backup_codes(), ctx.config.encryption_secret())
        .await
    {
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
    if !backup_codes.contains(&body.code) {
        finish_attempt(attempt, true, ctx).await;
        record_failure(&state, &two_factor, &config.account_lockout, ctx).await?;
        return Err(AuthError::authentication_failed("Invalid backup code"));
    }
    backup_codes.retain(|candidate| candidate != &body.code);

    let encrypted = config
        .backup_code_options
        .storage
        .encode(&backup_codes, ctx.config.encryption_secret())
        .await?;
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
                        user: ctx.user_view(&user).await?,
                    },
                    Vec::new(),
                ))
            } else {
                verify_existing_session_factor(
                    req,
                    user,
                    *session,
                    None,
                    ctx,
                    std::future::ready(Ok(())),
                )
                .await
            }
        }
        ResolvedTwoFactorState::Pending(pending) => {
            if body.disable_session.unwrap_or(false) {
                return Ok((
                    SessionTokenResponse {
                        token: None,
                        user: ctx.user_view(&pending.user).await?,
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
    config: &BackupCodeOptions,
    ctx: &AuthContext<S>,
) -> AuthResult<Vec<String>> {
    let two_factor = ctx
        .database
        .get_two_factor_by_user_id(user_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Backup codes aren't enabled"))?;
    let Some(backup_codes) = config
        .storage
        .decode(two_factor.backup_codes(), ctx.config.encryption_secret())
        .await?
    else {
        return Err(AuthError::bad_request("Invalid backup code"));
    };
    Ok(backup_codes)
}
