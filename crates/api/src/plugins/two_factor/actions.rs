use super::*;

pub(super) async fn enable_core<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    body: &EnableRequest,
    data: &NativeSessionData,
    config: &TwoFactorConfig,
    ctx: &AuthContext<S>,
) -> AuthResult<(EnableResponse, Vec<String>)> {
    verify_user_password(
        ctx,
        data.user_property("id")?,
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
        let updated = update_two_factor_user(data.user_property("id")?, true, ctx)
            .await?
            .ok_or_else(|| AuthError::internal("Cannot read properties of null (reading 'id')"))?;
        let _ = issue_factor_session(
            req,
            updated.id().into_owned(),
            FieldMap::from(updated).into(),
            data.session.field_values()?,
            ctx,
        )
        .await?;
        delete_factor_session(&data.session, ctx).await?;
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
        .get_two_factor_by_user_id_value(&SchemaValue::from_field(
            data.user_property("id")?.clone(),
        ))
        .await?;
    if existing
        .as_ref()
        .is_some_and(|factor| !factor.verified.field_value().strict_equals(&false.into()))
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
        .encode(
            &backup_codes
                .iter()
                .cloned()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
            ctx.config.encryption_secret(),
        )
        .await?;
    let secret = generate_secret();
    let encrypted_secret = encrypt_value(ctx.config.encryption_secret(), &secret)?;

    let set_cookie_headers = Vec::new();
    if config.skip_verification_on_enable {
        let updated_user = update_two_factor_user(data.user_property("id")?, true, ctx)
            .await?
            .ok_or_else(|| AuthError::internal("Cannot read properties of null (reading 'id')"))?;
        let _ = issue_factor_session(
            req,
            updated_user.id().into_owned(),
            FieldMap::from(updated_user).into(),
            data.session.field_values()?,
            ctx,
        )
        .await?;
        delete_factor_session(&data.session, ctx).await?;
    }

    let mut fields = FieldMap::from([
        ("secret".into(), encrypted_secret.into()),
        ("backupCodes".into(), encrypted_backup_codes),
        ("verified".into(), config.skip_verification_on_enable.into()),
    ]);
    if let Some(existing) = existing {
        let _ = ctx
            .database
            .update_two_factor_record(&existing.id, fields)
            .await?;
    } else {
        let _ = fields.insert("userId".into(), data.user_property("id")?.clone());
        let _ = ctx.database.create_two_factor_record(fields).await?;
    }

    let totp_uri = build_totp(
        config,
        &secret,
        body.issuer
            .as_deref()
            .filter(|issuer| !issuer.is_empty())
            .or(config.issuer.as_deref().filter(|issuer| !issuer.is_empty())),
        data.user_property("email")?,
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
    data: &NativeSessionData,
    req: &AuthRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(StatusResponse, Vec<String>)> {
    verify_user_password(
        ctx,
        data.user_property("id")?,
        body.password.as_deref(),
        config.allow_passwordless,
        false,
    )
    .await?;

    let updated_user = update_two_factor_user(data.user_property("id")?, false, ctx)
        .await?
        .ok_or_else(|| AuthError::internal("Cannot read properties of null (reading 'id')"))?;
    ctx.database
        .delete_two_factor_by_user_id_value(&updated_user.id().into_owned())
        .await?;
    let _ = issue_factor_session(
        req,
        updated_user.id().into_owned(),
        FieldMap::from(updated_user).into(),
        data.session.field_values()?,
        ctx,
    )
    .await?;
    delete_factor_session(&data.session, ctx).await?;

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
    data: &NativeSessionData,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<TotpUriResponse> {
    require_totp(config)?;
    let two_factor = load_two_factor_record(data.user_property("id")?, ctx).await?;
    let secret = crate::plugins::symmetric::decrypt_field(
        ctx.config.encryption_secret(),
        &two_factor.secret.field_value(),
    )?;
    verify_user_password(
        ctx,
        data.user_property("id")?,
        body.password.as_deref(),
        config
            .totp_allow_passwordless
            .unwrap_or(config.allow_passwordless),
        true,
    )
    .await?;
    Ok(TotpUriResponse {
        totp_uri: build_totp(config, &secret, None, data.user_property("email")?, ctx)?
            .with_default_period()
            .get_url()?,
    })
}

pub(super) async fn verify_totp_core(
    req: &AuthRequest,
    body: &VerifyTotpRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionTokenResponse, Vec<String>)> {
    require_totp(config)?;
    let state = resolve_two_factor_state(req, ctx).await?;
    let two_factor = load_two_factor_record(&state.user_id()?, ctx).await?;
    if state.is_sign_in()
        && two_factor
            .verified
            .field_value()
            .strict_equals(&false.into())
    {
        return Err(AuthError::bad_request("TOTP not enabled"));
    }
    assert_not_locked(&state, &two_factor, &config.account_lockout, ctx).await?;
    let attempt = begin_attempt(&state, req, ctx).await?;
    let valid = (|| {
        let secret = crate::plugins::symmetric::decrypt_field(
            ctx.config.encryption_secret(),
            &two_factor.secret.field_value(),
        )?;
        totp_verifier(config, &secret)
            .with_default_period()
            .check_current(&body.code)
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
    let needs_enrollment = !two_factor
        .verified
        .field_value()
        .strict_equals(&true.into());
    let update_enrollment = async {
        if needs_enrollment {
            let _ = ctx
                .database
                .update_two_factor_record(
                    &two_factor.id,
                    FieldMap::from([("verified".into(), true.into())]),
                )
                .await?;
        }
        Ok::<(), AuthError>(())
    };

    match state {
        ResolvedTwoFactorState::Session { data, .. } => {
            verify_existing_session_factor(
                req,
                *data,
                needs_enrollment.then_some(EnrollmentMethod::Totp),
                ctx,
                update_enrollment,
            )
            .await
        }
        ResolvedTwoFactorState::Pending(pending) => {
            if needs_enrollment
                && !pending
                    .user
                    .field_values()?
                    .get("twoFactorEnabled")
                    .is_some_and(FieldValue::is_truthy)
            {
                let updated =
                    update_two_factor_user(&pending.user.id.field_value(), true, ctx).await?;
                let _ = issue_factor_session(
                    req,
                    pending.user.id.clone(),
                    updated.map_or(FieldValue::Null, |user| FieldMap::from(user).into()),
                    FieldMap::new(),
                    ctx,
                )
                .await?;
                return Err(AuthError::internal(
                    "Cannot read properties of null (reading 'token')",
                ));
            }
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
    let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        Some(req),
        better_auth_core::FieldValue::from_json(body)?,
        ctx,
    );
    if let ResolvedTwoFactorState::Session { data, .. } = &state {
        endpoint.session = Some(*data.clone());
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
        .create_verification_optional(CreateVerification {
            identifier: (identifier).into(),
            value: SchemaValue::from_field(better_auth_core::query::field_add(
                &stored_otp.display_utf16()?.into(),
                &":0".into(),
            )?),
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
        Sender::Callback(callback) => callback(&state.user(), &otp, &endpoint)?,
        Sender::Legacy(sender) => {
            let sender = sender.clone();
            let user = state.user();
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
) -> AuthResult<(SessionTokenResponse, Vec<String>)> {
    let state = resolve_two_factor_state(req, ctx).await?;
    let factor = if state.is_sign_in() {
        ctx.database
            .get_two_factor_by_user_id_value(&SchemaValue::from_field(state.user_id()?))
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

    let (stored_otp, attempts) = split_otp_record(&verification.value.field_value())?;
    if attempts
        >= if config.otp_allowed_attempts == 0 {
            5.0
        } else {
            config.otp_allowed_attempts as f64
        }
    {
        return Err(AuthError::bad_request(
            "Too many attempts. Please request a new code.",
        ));
    }

    let is_valid = config
        .otp_storage
        .verify(&stored_otp, &body.code, ctx.config.encryption_secret())
        .await?;

    if !is_valid {
        let next_value = better_auth_core::query::field_add(
            &stored_otp.display_utf16()?.into(),
            &FieldValue::from(format!(
                ":{}",
                better_auth_core::schema_value::number_string(attempts + 1.0)
            )),
        )?;
        let expires_at = verification.expires_at.clone();
        _ = ctx
            .database
            .create_verification_optional(CreateVerification {
                identifier: (identifier).into(),
                value: SchemaValue::from_field(next_value),
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
        ResolvedTwoFactorState::Session { data, .. } => {
            verify_existing_session_factor(
                req,
                *data,
                Some(EnrollmentMethod::Otp),
                ctx,
                std::future::ready(Ok(())),
            )
            .await
        }
        ResolvedTwoFactorState::Pending(pending) => {
            if !pending
                .user
                .field_values()?
                .get("twoFactorEnabled")
                .is_some_and(FieldValue::is_truthy)
            {
                return Err(AuthError::Upstream {
                    status: 400,
                    code: "FAILED_TO_CREATE_SESSION",
                    message: "Failed to create session",
                });
            }
            finalize_pending_two_factor(pending, req, body.trust_device.unwrap_or(false), ctx).await
        }
    }
}

pub(super) async fn generate_backup_codes_core(
    body: &GenerateBackupCodesRequest,
    data: &NativeSessionData,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<BackupCodesResponse> {
    if !data.user_property("twoFactorEnabled")?.is_truthy() {
        return Err(AuthError::bad_request("Two factor isn't enabled"));
    }

    verify_user_password(
        ctx,
        data.user_property("id")?,
        body.password.as_deref(),
        config
            .backup_code_options
            .allow_passwordless
            .unwrap_or(config.allow_passwordless),
        true,
    )
    .await?;
    let two_factor = load_two_factor_record(data.user_property("id")?, ctx).await?;

    let backup_codes = config.backup_code_options.generate();
    let encrypted = config
        .backup_code_options
        .storage
        .encode(
            &backup_codes
                .iter()
                .cloned()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
            ctx.config.encryption_secret(),
        )
        .await?;
    _ = ctx
        .database
        .update_two_factor_record(
            &two_factor.id,
            FieldMap::from([("backupCodes".into(), encrypted)]),
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
) -> AuthResult<(SessionTokenResponse, Vec<String>)> {
    let state = resolve_two_factor_state(req, ctx).await?;
    let two_factor = ctx
        .database
        .get_two_factor_by_user_id_value(&SchemaValue::from_field(state.user_id()?))
        .await?
        .ok_or_else(|| AuthError::bad_request("Backup codes aren't enabled"))?;
    assert_not_locked(&state, &two_factor, &config.account_lockout, ctx).await?;
    let attempt = begin_attempt(&state, req, ctx).await?;
    let decoded = match config
        .backup_code_options
        .storage
        .decode(
            &two_factor.backup_codes.field_value(),
            ctx.config.encryption_secret(),
        )
        .await
    {
        Ok(codes) => options::remaining_backup_codes(&codes, &body.code),
        Err(error) => {
            finish_attempt(attempt, false, ctx).await;
            return Err(error);
        }
    };
    let decoded = match decoded {
        Ok(codes) => codes,
        Err(error) => {
            finish_attempt(attempt, false, ctx).await;
            return Err(error);
        }
    };
    let Some(backup_codes) = decoded else {
        finish_attempt(attempt, true, ctx).await;
        record_failure(&state, &two_factor, &config.account_lockout, ctx).await?;
        return Err(AuthError::authentication_failed("Invalid backup code"));
    };

    let encrypted = config
        .backup_code_options
        .storage
        .encode(&backup_codes, ctx.config.encryption_secret())
        .await?;
    if !ctx
        .database
        .compare_exchange_two_factor_backup_codes(
            &two_factor.id,
            &two_factor.backup_codes.field_value(),
            encrypted,
        )
        .await?
    {
        return Err(AuthError::conflict(
            "Failed to verify backup code. Please try again.",
        ));
    }
    reset_failures(&state, &two_factor, &config.account_lockout, ctx).await?;

    match state {
        ResolvedTwoFactorState::Session { data, .. } => {
            if body.disable_session.unwrap_or(false) {
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
            } else {
                verify_existing_session_factor(req, *data, None, ctx, std::future::ready(Ok(())))
                    .await
            }
        }
        ResolvedTwoFactorState::Pending(pending) => {
            if body.disable_session.unwrap_or(false) {
                return Ok((
                    SessionTokenResponse {
                        token: FieldValue::Undefined,
                        user: FieldMap::from(ctx.user_view(&pending.user).await?).into(),
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
) -> AuthResult<FieldValue> {
    let two_factor = ctx
        .database
        .get_two_factor_by_user_id(user_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Backup codes aren't enabled"))?;
    let backup_codes = config
        .storage
        .decode(
            &two_factor.backup_codes.field_value(),
            ctx.config.encryption_secret(),
        )
        .await?;
    if !backup_codes.is_truthy() {
        return Err(AuthError::bad_request("Invalid backup code"));
    };
    Ok(backup_codes)
}
