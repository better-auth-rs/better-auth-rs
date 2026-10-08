use super::{
    EmailOtpPlugin, EmailOtpType,
    otp::invalid_otp,
    request::{Body, validate_email},
};
use crate::plugins::endpoint_context::EndpointContext;
use crate::plugins::helpers::{
    SessionIssueError, apply_user_create_fields, get_credential_account,
    issue_selected_user_session_optional,
};
use better_auth_core::utils::password;
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, AuthSession,
    AuthUser, CreateAccount, CreateUser, RequestMeta, UpdateAccount, UpdateUser,
};
use serde_json::json;

macro_rules! body {
    ($req:expr) => {
        match Body::parse($req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        }
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
        let body = body!(req);
        let endpoint = EndpointContext::new(
            Some(req),
            better_auth_core::FieldValue::from_json(body.value())?,
            ctx,
        );
        if !self.has_sender(ctx) {
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
        let otp = self.resolve_otp(&endpoint, &email, kind).await?;
        if ctx.database.get_user_by_email(&email).await?.is_none()
            && !(kind == EmailOtpType::SignIn && !self.config.disable_sign_up)
        {
            ctx.database
                .delete_verification_by_identifier(&kind.identifier(&email))
                .await?;
            return success();
        }
        self.deliver(&endpoint, &email, otp, kind).await?;
        success()
    }

    pub(super) async fn check(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req);
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
        let body = body!(req);
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
            return self.session_response(req, ctx, &user, true).await;
        }
        let manager = ctx.session_manager();
        if let Some(mut current) = manager
            .resolve(req, better_auth_core::session::SessionRead::Cached)
            .await?
            .data
            && current.user.id() == user.id()
        {
            current.user.set_field("emailVerified", true.into());
            manager
                .write_cache(req, &current, manager.dont_remember(req))
                .await?;
        }
        Ok(AuthResponse::json(
            200,
            &json!({"status": true, "token": null, "user": ctx.user_view(&user).await?}),
        )?)
    }

    pub(super) async fn sign_in(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req);
        let email = body.get("email").to_lowercase();
        self.verify_otp(
            ctx,
            &EmailOtpType::SignIn.identifier(&email),
            body.get("otp"),
            true,
        )
        .await?;
        let user = match ctx.database.get_user_by_email(&email).await? {
            Some(user) if !user.email_verified().is_truthy()? => ctx
                .database
                .verify_user_and_revoke_unproven_access(user.id().typed()?)
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
                input.image = body
                    .optional("image")
                    .map(|image| Some(image.to_owned()).into())
                    .unwrap_or_default();
                apply_user_create_fields(ctx, body.fields(), &mut input)?;

                let endpoint = EndpointContext::new(
                    Some(req),
                    better_auth_core::FieldValue::from_json(serde_json::Value::Object(
                        body.fields().clone(),
                    ))?,
                    ctx,
                );
                crate::plugins::user_admission::create_user_optional(input, "email-otp", &endpoint)
                    .await?
                    .ok_or_else(|| {
                        AuthError::internal("Cannot read properties of null (reading 'id')")
                    })?
            }
        };
        self.session_response(req, ctx, &user, false).await
    }

    pub(super) async fn request_password_reset(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req);
        let endpoint = EndpointContext::new(
            Some(req),
            better_auth_core::FieldValue::from_json(body.value())?,
            ctx,
        );
        let email = body.get("email").to_lowercase();
        let kind = EmailOtpType::ForgetPassword;
        let otp = self.resolve_otp(&endpoint, &email, kind).await?;
        if ctx.database.get_user_by_email(&email).await?.is_none() {
            ctx.database
                .delete_verification_by_identifier(&kind.identifier(&email))
                .await?;
            return success();
        }
        self.deliver(&endpoint, &email, otp, kind).await?;
        success()
    }

    pub(super) async fn reset_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req);
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
        if let Some(account) = get_credential_account(ctx, user.id().into_owned()).await? {
            let _ = ctx
                .database
                .update_account(
                    account.id.typed()?,
                    UpdateAccount {
                        password: (Some(hash))
                            .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                            .unwrap_or_default(),
                        ..Default::default()
                    },
                )
                .await?;
        } else {
            let _ = ctx
                .database
                .create_account_optional(CreateAccount {
                    user_id: user.id().into_owned(),
                    account_id: user.id().into_owned(),
                    provider_id: ("credential".to_owned()).into(),
                    password: (Some(hash))
                        .map(|value| better_auth_core::SchemaValue::Typed(Some(value)))
                        .unwrap_or_default(),
                    access_token: Default::default(),
                    refresh_token: Default::default(),
                    id_token: Default::default(),
                    access_token_expires_at: Default::default(),
                    refresh_token_expires_at: Default::default(),
                    scope: Default::default(),
                    ..Default::default()
                })
                .await?;
        }
        if let Some(hook) = &ctx.password_policy.on_password_reset {
            hook(password::PasswordResetEvent {
                user: ctx.internal_user_view(&user).await?,
                request: Some(req.clone()),
            })
            .await?;
        }
        if !user.email_verified().is_truthy()? {
            let _ = ctx
                .database
                .update_user(
                    user.id().typed()?,
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?;
        }
        if ctx.password_policy.revoke_sessions_on_password_reset {
            ctx.database
                .delete_user_sessions(user.id().typed()?)
                .await?;
        }
        success()
    }

    pub(super) async fn request_email_change(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req);
        let mut endpoint = EndpointContext::new(
            Some(req),
            better_auth_core::FieldValue::from_json(body.value())?,
            ctx,
        );
        let (user, session) = ctx
            .require_authoritative_session(req)
            .await
            .map_err(session_error)?;
        let (email, new_email) = self.change_addresses(&user, &body)?;
        endpoint.session = Some((user.clone(), session));
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
        let otp = self
            .create_otp(&endpoint, &new_email, kind, &identifier)
            .await?;
        if ctx.database.get_user_by_email(&new_email).await?.is_some() {
            ctx.database
                .delete_verification_by_identifier(&identifier)
                .await?;
            return success();
        }
        self.deliver(&endpoint, &new_email, otp, kind).await?;
        success()
    }

    pub(super) async fn handle_change_email(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = body!(req);
        let (user, session) = ctx
            .require_authoritative_session(req)
            .await
            .map_err(session_error)?;
        let (email, new_email) = self.change_addresses(&user, &body)?;
        let authenticated_user = user.clone();
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
        let _ = self.mark_verified(ctx, &user, new_email.clone()).await?;
        let mut user = authenticated_user;
        user.set_field("email", new_email.into());
        user.set_field("emailVerified", true.into());
        ctx.session_manager()
            .set_session_cookie(
                req,
                better_auth_core::session::SessionData { session, user },
                None,
            )
            .await?;
        success()
    }

    fn change_addresses(&self, user: &UserView, body: &Body) -> AuthResult<(String, String)> {
        if !self.config.change_email {
            return Err(AuthError::bad_request("Change email with OTP is disabled"));
        }
        let email = crate::plugins::helpers::user_email(user)?.to_lowercase();
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
        user: &better_auth_core::wire::UserView,
        email: String,
    ) -> AuthResult<better_auth_core::wire::UserView> {
        if let Some(hook) = &ctx.email_verification_policy.before_email_verification {
            hook(&ctx.user_view(user).await?).await?;
        }
        let user = ctx
            .database
            .update_user(
                user.id().typed()?,
                UpdateUser {
                    email: Some(email),
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        if let Some(hook) = &ctx.email_verification_policy.after_email_verification {
            hook(&ctx.user_view(&user).await?).await?;
        }
        Ok(user)
    }

    async fn session_response(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
        user: &UserView,
        verification: bool,
    ) -> AuthResult<AuthResponse> {
        let meta = RequestMeta::from_request_with_config(req, &ctx.config.advanced.ip_address);
        let issued = issue_selected_user_session_optional(
            ctx,
            better_auth_core::FieldMap::from(ctx.internal_user_view(user).await?).into(),
            &meta,
            ctx.config.session.expires_in(),
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?
        .ok_or_else(|| AuthError::internal("Cannot read properties of null (reading 'token')"))?;
        let token = issued.session.token().field_value();
        ctx.session_manager()
            .set_native_session_cookie(req, issued, None)
            .await?;
        let user = ctx.user_view(user).await?;
        let mut body = better_auth_core::FieldMap::new();
        if verification {
            let _ = body.insert("status".into(), true.into());
        }
        body.extend([
            ("token".into(), token),
            ("user".into(), better_auth_core::FieldMap::from(user).into()),
        ]);
        Ok(AuthResponse::native(200, body.into()))
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
