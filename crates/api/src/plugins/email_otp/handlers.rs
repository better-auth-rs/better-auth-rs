use super::{
    EmailOtpPlugin, EmailOtpType,
    otp::invalid_otp,
    request::{Body, validate_email},
};
use crate::plugins::helpers::{
    SessionIssueError, apply_default_role, apply_user_create_fields, get_credential_account,
    issue_user_session,
};
use better_auth_core::utils::{cookie_utils::create_session_cookie, password};
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthAccount, AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema,
    AuthSession, AuthUser, CreateAccount, CreateUser, RequestMeta, UpdateAccount, UpdateUser,
};
use serde_json::json;

macro_rules! body {
    ($req:expr, [$($required:expr),*], [$($optional:expr),*]) => {
        match Body::parse($req, &[$($required),*], &[$($optional),*]) { Ok(body) => body, Err(response) => return Ok(response) }
    };
}

fn success() -> AuthResult<AuthResponse> {
    Ok(AuthResponse::json(200, &json!({"success": true}))?)
}
fn user_not_found() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: "USER_NOT_FOUND",
        message: "User not found",
    }
}

impl EmailOtpPlugin {
    pub(super) async fn send(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req, ["email", "type"], []);
        if self.config.sender.is_none() {
            return Err(AuthError::bad_request(
                "send email verification is not implemented",
            ));
        }
        let email = body.get("email").to_lowercase();
        validate_email(&email)?;
        let kind = body.kind();
        if kind == EmailOtpType::ChangeEmail {
            return Err(AuthError::bad_request("Invalid OTP type"));
        }
        let otp = self.resolve_otp(ctx, &email, kind).await?;
        if ctx.database.get_user_by_email(&email).await?.is_none()
            && !(kind == EmailOtpType::SignIn && !self.config.disable_sign_up)
        {
            ctx.database
                .delete_verification_by_identifier(&kind.identifier(&email))
                .await?;
            return success();
        }
        self.deliver(&email, otp, kind).await?;
        success()
    }

    pub(super) async fn check(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req, ["email", "type", "otp"], []);
        let email = body.get("email").to_lowercase();
        validate_email(&email)?;
        self.verify_otp(ctx, &body.kind().identifier(&email), body.get("otp"), false)
            .await?;
        let _ = ctx
            .database
            .get_user_by_email(&email)
            .await?
            .ok_or_else(user_not_found)?;
        success()
    }

    pub(super) async fn verify_email(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req, ["email", "otp"], []);
        let email = body.get("email").to_lowercase();
        validate_email(&email)?;
        self.verify_otp(
            ctx,
            &EmailOtpType::EmailVerification.identifier(&email),
            body.get("otp"),
            true,
        )
        .await?;
        let user = ctx
            .database
            .get_user_by_email(&email)
            .await?
            .ok_or_else(user_not_found)?;
        let user = self.mark_verified(ctx, &user, email).await?;
        if ctx
            .email_verification_policy
            .auto_sign_in_after_verification
        {
            return self.session_response(req, ctx, &user.id(), true).await;
        }
        let manager = ctx.session_manager();
        if let Some(mut current) = manager
            .resolve(req, better_auth_core::session::SessionRead::Cached)
            .await?
            .data
            && current.user.id() == user.id()
        {
            current.user.email_verified = true;
            manager
                .write_cache(req, &current, manager.dont_remember(req))
                .await?;
        }
        Ok(AuthResponse::json(
            200,
            &json!({"status": true, "token": null, "user": ctx.user_view(&user)?}),
        )?)
    }

    pub(super) async fn sign_in(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req, ["email", "otp"], ["name", "image"]);
        let email = body.get("email").to_lowercase();
        self.verify_otp(
            ctx,
            &EmailOtpType::SignIn.identifier(&email),
            body.get("otp"),
            true,
        )
        .await?;
        let user = match ctx.database.get_user_by_email(&email).await? {
            Some(user) if !user.email_verified() => ctx
                .database
                .verify_user_and_revoke_unproven_access(&user.id())
                .await?
                .ok_or_else(invalid_otp)?,
            Some(user) => user,
            None => {
                if self.config.disable_sign_up {
                    return Err(invalid_otp());
                }
                let mut input = CreateUser::new()
                    .with_email(email)
                    .with_name(body.get("name"))
                    .with_email_verified(true);
                input.image = body.optional("image").map(str::to_owned);
                apply_user_create_fields(ctx, body.fields(), &mut input).await?;
                apply_default_role(ctx, &mut input);
                ctx.database.create_user(input).await?
            }
        };
        self.session_response(req, ctx, &user.id(), false).await
    }

    pub(super) async fn request_password_reset(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req, ["email"], []);
        let email = body.get("email").to_lowercase();
        let kind = EmailOtpType::ForgetPassword;
        let otp = self.resolve_otp(ctx, &email, kind).await?;
        if ctx.database.get_user_by_email(&email).await?.is_none() {
            ctx.database
                .delete_verification_by_identifier(&kind.identifier(&email))
                .await?;
            return success();
        }
        self.deliver(&email, otp, kind).await?;
        success()
    }

    pub(super) async fn reset_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req, ["email", "otp", "password"], []);
        let email = body.get("email").to_lowercase();
        password::validate_password(
            body.get("password"),
            ctx.password_policy.min_length,
            ctx.password_policy.max_length,
            ctx,
        )?;
        self.verify_otp(
            ctx,
            &EmailOtpType::ForgetPassword.identifier(&email),
            body.get("otp"),
            true,
        )
        .await?;
        let user = ctx
            .database
            .get_user_by_email(&email)
            .await?
            .ok_or_else(user_not_found)?;
        let hash =
            password::hash_password(ctx.password_policy.hasher.as_ref(), body.get("password"))
                .await?;
        if let Some(account) = get_credential_account(ctx, user.id()).await? {
            let _ = ctx
                .database
                .update_account(
                    &account.id(),
                    UpdateAccount {
                        password: Some(hash),
                        ..Default::default()
                    },
                )
                .await?;
        } else {
            let _ = ctx
                .database
                .create_account(CreateAccount {
                    user_id: user.id().to_string(),
                    account_id: user.id().to_string(),
                    provider_id: "credential".to_owned(),
                    password: Some(hash),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                })
                .await?;
        }
        if let Some(hook) = &ctx.password_policy.on_password_reset {
            hook(serde_json::to_value(ctx.user_view(&user)?)?).await?;
        }
        if !user.email_verified() {
            let _ = ctx
                .database
                .update_user(
                    &user.id(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?;
        }
        if ctx.password_policy.revoke_sessions_on_password_reset {
            ctx.database.delete_user_sessions(&user.id()).await?;
        }
        success()
    }

    pub(super) async fn request_email_change(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req, ["newEmail"], ["otp"]);
        let (user, _) = ctx
            .require_authoritative_session(req)
            .await
            .map_err(session_error)?;
        let (email, new_email) = self.change_addresses(&user, &body)?;
        if self.config.verify_current_email {
            let otp = body
                .optional("otp")
                .filter(|otp| !otp.is_empty())
                .ok_or_else(|| AuthError::bad_request("OTP is required to verify current email"))?;
            self.verify_otp(
                ctx,
                &EmailOtpType::EmailVerification.identifier(&email),
                otp,
                true,
            )
            .await?;
        }
        let kind = EmailOtpType::ChangeEmail;
        let identifier = kind.identifier(&format!("{email}-{new_email}"));
        let otp = self.create_otp(ctx, &new_email, kind, &identifier).await?;
        if ctx.database.get_user_by_email(&new_email).await?.is_some() {
            ctx.database
                .delete_verification_by_identifier(&identifier)
                .await?;
            return success();
        }
        self.deliver(&new_email, otp, kind).await?;
        success()
    }

    pub(super) async fn handle_change_email(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req, ["newEmail", "otp"], []);
        let (user, session) = ctx
            .require_authoritative_session(req)
            .await
            .map_err(session_error)?;
        let (email, new_email) = self.change_addresses(&user, &body)?;
        self.verify_otp(
            ctx,
            &EmailOtpType::ChangeEmail.identifier(&format!("{email}-{new_email}")),
            body.get("otp"),
            true,
        )
        .await?;
        let user = ctx
            .database
            .get_user_by_email(&email)
            .await?
            .ok_or_else(user_not_found)?;
        if ctx.database.get_user_by_email(&new_email).await?.is_some() {
            return Err(AuthError::bad_request("Email already in use"));
        }
        let _ = self.mark_verified(ctx, &user, new_email).await?;
        Ok(success()?.with_header(
            "Set-Cookie",
            create_session_cookie(session.token(), &ctx.config),
        ))
    }

    fn change_addresses(&self, user: &UserView, body: &Body) -> AuthResult<(String, String)> {
        if !self.config.change_email {
            return Err(AuthError::bad_request("Change email with OTP is disabled"));
        }
        let email = user.email().unwrap_or_default().to_lowercase();
        let new_email = body.get("newEmail").to_lowercase();
        validate_email(&new_email)?;
        if email == new_email {
            return Err(AuthError::bad_request("Email is the same"));
        }
        Ok((email, new_email))
    }

    async fn mark_verified<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        user: &S::User,
        email: String,
    ) -> AuthResult<S::User> {
        if let Some(hook) = &ctx.email_verification_policy.before_email_verification {
            hook(&ctx.user_view(user)?).await?;
        }
        let user = ctx
            .database
            .update_user(
                &user.id(),
                UpdateUser {
                    email: Some(email),
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        if let Some(hook) = &ctx.email_verification_policy.after_email_verification {
            hook(&ctx.user_view(&user)?).await?;
        }
        Ok(user)
    }

    async fn session_response(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
        user_id: &str,
        verification: bool,
    ) -> AuthResult<AuthResponse> {
        let meta = RequestMeta::from_request(req);
        let issued = issue_user_session(ctx, user_id, meta.ip_address, meta.user_agent)
            .await
            .map_err(SessionIssueError::into_auth_error)?;
        let user = ctx.user_view(&issued.user)?;
        let body = if verification {
            json!({"status": true, "token": issued.session.token(), "user": user})
        } else {
            json!({"token": issued.session.token(), "user": user})
        };
        Ok(AuthResponse::json(200, &body)?.with_header(
            "Set-Cookie",
            create_session_cookie(issued.session.token(), &ctx.config),
        ))
    }
}

fn session_error(error: AuthError) -> AuthError {
    match error {
        AuthError::Unauthenticated => AuthError::Upstream {
            status: 401,
            code: "UNAUTHORIZED",
            message: "Unauthorized",
        },
        other => other,
    }
}
