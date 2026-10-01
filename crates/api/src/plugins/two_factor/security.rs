use super::*;

pub(super) async fn assert_not_locked(
    state: &ResolvedTwoFactorState,
    factor: &TwoFactor,
    config: &AccountLockout,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if !state.is_sign_in() || !config.enabled {
        return Ok(());
    }
    if let Some(until) = factor.locked_until {
        if until > Utc::now() {
            return Err(AuthError::Upstream {
                status: 429,
                code: "ACCOUNT_TEMPORARILY_LOCKED",
                message: "Too many failed verification attempts. Your account is temporarily locked. Please try again later.",
            });
        }
        ctx.database
            .reset_two_factor_failures(&factor.id, Some(Utc::now()))
            .await?;
    }
    Ok(())
}

pub(super) async fn record_failure(
    state: &ResolvedTwoFactorState,
    factor: &TwoFactor,
    config: &AccountLockout,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if state.is_sign_in() && config.enabled {
        ctx.database
            .record_two_factor_failure(
                &factor.id,
                config.max_failed_attempts,
                Utc::now() + Duration::seconds(config.duration_seconds),
            )
            .await?;
    }
    Ok(())
}

pub(super) async fn reset_failures(
    state: &ResolvedTwoFactorState,
    factor: &TwoFactor,
    config: &AccountLockout,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if state.is_sign_in() && config.enabled {
        ctx.database
            .reset_two_factor_failures(&factor.id, None)
            .await?;
    }
    Ok(())
}

pub(super) struct ChallengeAttempt {
    identifier: String,
    failures: usize,
    expires_at: better_auth_core::SchemaValue<chrono::DateTime<Utc>>,
}

pub(super) async fn begin_attempt<S: better_auth_core::AuthSchema>(
    state: &ResolvedTwoFactorState,
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<Option<ChallengeAttempt>> {
    let ResolvedTwoFactorState::Pending(pending) = state else {
        return Ok(None);
    };
    let identifier = format!("2fa-attempts-{}", pending.key);
    let consumed = match ctx
        .database
        .consume_verification_by_identifier(&identifier)
        .await
    {
        Ok(consumed) => consumed,
        Err(error) => {
            better_auth_core::observability::logger::current().warn(
                "Failed to consume two-factor attempt counter",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
            None
        }
    }
    .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    let attempts = consumed
        .value
        .display_string()?
        .parse::<usize>()
        .unwrap_or(CHALLENGE_ATTEMPT_LIMIT);
    if attempts >= CHALLENGE_ATTEMPT_LIMIT {
        let invalidation = ctx
            .database
            .consume_verification_by_identifier(&pending.key)
            .await;
        req.append_response_header(
            "Set-Cookie",
            clear_cookie_header(&ctx.config, TWO_FACTOR_COOKIE_SUFFIX),
        )?;
        if let Err(error) = invalidation {
            better_auth_core::observability::logger::current().error(
                "Failed to invalidate two-factor challenge",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
            return Err(AuthError::Upstream {
                status: 500,
                code: "FAILED_TO_INVALIDATE_TWO_FACTOR_CHALLENGE",
                message: "Failed to invalidate two-factor challenge",
            });
        }
        return Err(AuthError::bad_request(
            "Too many attempts. Please request a new code.",
        ));
    }
    Ok(Some(ChallengeAttempt {
        identifier,
        failures: attempts,
        expires_at: consumed.expires_at.clone(),
    }))
}

pub(super) async fn finish_attempt(
    attempt: Option<ChallengeAttempt>,
    failed: bool,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) {
    if let Some(attempt) = attempt {
        let verification = CreateVerification {
            identifier: (attempt.identifier).into(),
            value: ((attempt.failures + usize::from(failed)).to_string()).into(),
            expires_at: attempt.expires_at,
            ..Default::default()
        };
        // Upstream keeps the credential failure if rearming fails. The missing
        // counter invalidates the challenge on the next request.
        if let Err(error) = ctx.database.create_verification(verification).await {
            better_auth_core::observability::logger::current().warn(
                "Failed to rearm two-factor challenge",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
        }
    }
}
