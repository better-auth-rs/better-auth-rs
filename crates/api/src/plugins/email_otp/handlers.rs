use super::{
    EmailOtpPlugin, EmailOtpType,
    otp::invalid_otp,
    request::{Body, validate_email},
};
use crate::plugins::endpoint_context::EndpointContext;
use crate::plugins::helpers::{
    SessionIssueError, get_credential_account, issue_selected_user_session_optional,
};
use better_auth_core::utils::password;
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, AuthSession,
    AuthUser, CreateAccount, CreateUser, FieldMap, FieldValue, RequestMeta, UpdateUser,
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
    AuthResponse::json(None, &json!({"success": true}))
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
        let user = self.mark_verified(req, ctx, &user, email).await?;
        if ctx
            .email_verification_policy
            .auto_sign_in_after_verification
        {
            let user = user.as_ref().ok_or_else(|| {
                AuthError::type_error("Cannot read properties of null (reading 'id')")
            })?;
            return self.session_response(req, ctx, user, true).await;
        }
        let manager = ctx.session_manager();
        if let Some(mut current) = ctx
            .native_session(req, better_auth_core::session::SessionRead::Cached)
            .await?
        {
            let updated = user.as_ref().ok_or_else(|| {
                AuthError::type_error("Cannot read properties of null (reading 'emailVerified')")
            })?;
            if updated.email_verified.is_truthy()?
                && current
                    .user_property("id")?
                    .strict_equals(&updated.id.field_value())
            {
                let mut fields = current.user.enumerable_fields()?;
                let _ = fields.insert("emailVerified".into(), true.into());
                current.user = fields.into();
                manager
                    .write_native_cache(req, &current, manager.dont_remember(req))
                    .await?;
            }
        }
        let user = match user {
            Some(user) => FieldMap::from(ctx.user_view(&user).await?).into(),
            None => FieldValue::Null,
        };
        Ok(AuthResponse::native(
            None,
            FieldMap::from([
                ("status".into(), true.into()),
                ("token".into(), FieldValue::Null),
                ("user".into(), user),
            ])
            .into(),
        ))
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
                .verify_user_and_revoke_unproven_access_value(&user.id().field_value())
                .await?
                .ok_or_else(invalid_otp)?,
            Some(user) => user,
            None => {
                if self.config.disable_sign_up {
                    return Err(invalid_otp());
                }
                let rest = body
                    .fields()
                    .iter()
                    .filter(|(name, _)| !["email", "otp", "name", "image"].contains(&name.as_str()))
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect();
                let mut fields = ctx.parse_user_input(&rest, true)?;
                fields.extend([
                    ("email".into(), email.into()),
                    ("emailVerified".into(), true.into()),
                    ("name".into(), body.get("name").into()),
                    (
                        "image".into(),
                        body.optional("image")
                            .map_or(FieldValue::Undefined, Into::into),
                    ),
                ]);
                let input = CreateUser {
                    additional_fields: fields,
                    ..Default::default()
                };

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
        if get_credential_account(ctx, user.id().into_owned())
            .await?
            .is_some()
        {
            crate::plugins::helpers::update_password(ctx, &user.id().field_value(), hash).await?;
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
                .update_user_by_id_value(
                    &user.id().field_value(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?;
        }
        if ctx.password_policy.revoke_sessions_on_password_reset {
            ctx.database
                .delete_user_sessions_by_user_value(&user.id().field_value())
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
        let session = ctx
            .require_authoritative_native_session(req)
            .await
            .map_err(session_error)?;
        let (email, new_email) = self.change_addresses(&session.user, &body)?;
        endpoint.session = Some(session);
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
        let mut session = ctx
            .require_authoritative_native_session(req)
            .await
            .map_err(session_error)?;
        let (email, new_email) = self.change_addresses(&session.user, &body)?;
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
        let _ = self
            .mark_verified(req, ctx, &user, new_email.clone())
            .await?;
        let mut user = session.user.enumerable_fields()?;
        let _ = user.insert("email".into(), new_email.into());
        let _ = user.insert("emailVerified".into(), true.into());
        session.user = user.into();
        ctx.session_manager()
            .set_native_session_cookie(req, session, None)
            .await?;
        success()
    }

    fn change_addresses(&self, user: &FieldValue, body: &Body) -> AuthResult<(String, String)> {
        if !self.config.change_email {
            return Err(AuthError::bad_request("Change email with OTP is disabled"));
        }
        let email = crate::plugins::helpers::user_email_field(user.model_property("email")?)?
            .to_lowercase();
        let new_email = body.get("newEmail").to_lowercase();
        validate_email(&new_email)?;
        if email == new_email {
            return Err(AuthError::bad_request("Email is the same"));
        }
        Ok((email, new_email))
    }

    async fn mark_verified<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
        user: &better_auth_core::wire::UserView,
        email: String,
    ) -> AuthResult<Option<better_auth_core::wire::UserView>> {
        let endpoint = EndpointContext::new(Some(req), req.input_field_value()?, ctx);
        crate::plugins::email_verification::delivery::before(
            &FieldMap::from(user.clone()).into(),
            None,
            &endpoint,
        )
        .await?;
        let user = ctx
            .database
            .update_user_by_id_value(
                &user.id().field_value(),
                UpdateUser {
                    email: Some(email),
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let after = user
            .as_ref()
            .map(|user| FieldMap::from(user.clone()).into())
            .unwrap_or(FieldValue::Null);
        crate::plugins::email_verification::delivery::after(&after, None, &endpoint).await?;
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
        Ok(AuthResponse::native(None, body.into()))
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
