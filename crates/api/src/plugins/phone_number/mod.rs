use std::{future::Future, pin::Pin, sync::Arc};

use better_auth_core::utils::password::{hash_password, verify_password};
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, AuthSession,
    AuthUser, CreateAccount, CreateUser, CreateVerification, RequestMeta, UpdateUser,
};
use chrono::{Duration, Utc};
use rand::Rng;
use serde_json::{Value, json};

use super::helpers::{
    SessionIssueError, get_credential_account, issue_selected_user_session_optional,
};

mod callbacks;
mod native;
mod request;
#[cfg(test)]
mod signup_input_tests;
use crate::plugins::endpoint_context::EndpointContext;
use callbacks::Delivery;
pub use callbacks::{PhoneCallbackFuture, PhoneNumberCallbacks};
pub use native::PhoneNumberApi;

type CallbackFuture<T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send>>;
type OtpSender = dyn Fn(PhoneOtp, AuthRequest) -> CallbackFuture<()> + Send + Sync;
type OtpVerifier = dyn Fn(PhoneOtp, AuthRequest) -> CallbackFuture<bool> + Send + Sync;
type Validator = dyn Fn(String) -> CallbackFuture<bool> + Send + Sync;
type VerifiedCallback = dyn Fn(PhoneVerification, AuthRequest) -> CallbackFuture<()> + Send + Sync;
type TempField = dyn Fn(&str) -> String + Send + Sync;

/// A phone number and its verification or password reset code.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhoneOtp {
    /// Destination number accepted by the configured validator.
    pub phone_number: String,
    /// Generated code, or the code submitted for external verification.
    pub code: String,
}
/// Persisted identity delivered to the verification callback.
#[derive(Debug, Clone)]
pub struct PhoneVerification {
    /// Phone number proven by the consumed OTP.
    pub phone_number: String,
    /// User after the phone number has been verified.
    pub user: UserView,
}

/// Phone authentication backed by atomic, single-use verification records.
#[derive(Clone)]
pub struct PhoneNumberPlugin {
    send_otp: Option<Arc<OtpSender>>,
    verify_otp: Option<Arc<OtpVerifier>>,
    send_password_reset_otp: Option<Arc<OtpSender>>,
    phone_number_validator: Option<Arc<Validator>>,
    callback_on_verification: Option<Arc<VerifiedCallback>>,
    temp_email: Option<Arc<TempField>>,
    temp_name: Option<Arc<TempField>>,
    expires_in: f64,
    otp_length: usize,
    allowed_attempts: u64,
    require_verification: bool,
}
impl Default for PhoneNumberPlugin {
    fn default() -> Self {
        Self {
            send_otp: None,
            verify_otp: None,
            send_password_reset_otp: None,
            phone_number_validator: None,
            callback_on_verification: None,
            temp_email: None,
            temp_name: None,
            expires_in: 300.0,
            otp_length: 6,
            allowed_attempts: 3,
            require_verification: false,
        }
    }
}
impl PhoneNumberPlugin {
    /// Use upstream OTP defaults without enabling automatic registration.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set the generated decimal code length; the default is six digits.
    pub fn otp_length(mut self, length: usize) -> Self {
        self.otp_length = length;
        self
    }
    /// Set code validity in seconds, including fractional values; the default is 300.
    /// An explicit zero remains zero.
    pub fn expires_in(mut self, seconds: f64) -> Self {
        self.expires_in = seconds;
        self
    }
    /// Set the incorrect attempt budget; the default is three.
    pub fn allowed_attempts(mut self, attempts: u64) -> Self {
        self.allowed_attempts = attempts;
        self
    }
    /// Require a verified number before password sign-in.
    pub fn require_verification(mut self, require: bool) -> Self {
        self.require_verification = require;
        self
    }
    /// Create users after successful verification with the supplied temporary email.
    pub fn sign_up_on_verification(
        mut self,
        email: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> Self {
        self.temp_email = Some(Arc::new(email));
        self
    }
    /// Generate names for new users; the default name is the phone number.
    pub fn temporary_name(mut self, name: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        self.temp_name = Some(Arc::new(name));
        self
    }
    /// Deliver verification codes through the application's SMS provider.
    pub fn send_otp<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(PhoneOtp, AuthRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<()>> + Send + 'static,
    {
        self.send_otp = Some(Arc::new(move |otp, req| Box::pin(callback(otp, req))));
        self
    }
    /// Deliver password reset codes for registered phone numbers.
    pub fn send_password_reset_otp<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(PhoneOtp, AuthRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<()>> + Send + 'static,
    {
        self.send_password_reset_otp = Some(Arc::new(move |otp, req| Box::pin(callback(otp, req))));
        self
    }
    /// Delegate phone verification to the SMS provider instead of checking a stored code.
    pub fn verify_otp<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(PhoneOtp, AuthRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<bool>> + Send + 'static,
    {
        self.verify_otp = Some(Arc::new(move |otp, req| Box::pin(callback(otp, req))));
        self
    }
    /// Validate numbers before sending verification codes or accepting password sign-in.
    pub fn phone_number_validator<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<bool>> + Send + 'static,
    {
        self.phone_number_validator = Some(Arc::new(move |phone| Box::pin(callback(phone))));
        self
    }
    /// Run after persisting the verified user and before returning or issuing a session.
    pub fn callback_on_verification<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(PhoneVerification, AuthRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<()>> + Send + 'static,
    {
        self.callback_on_verification =
            Some(Arc::new(move |data, req| Box::pin(callback(data, req))));
        self
    }

    async fn validate(&self, phone: &str) -> AuthResult<()> {
        if let Some(validate) = &self.phone_number_validator
            && !validate(phone.to_owned()).await?
        {
            return Err(error(400, "INVALID_PHONE_NUMBER", "Invalid phone number"));
        }
        Ok(())
    }
    async fn save_otp(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        identifier: String,
        with_attempts: bool,
    ) -> AuthResult<String> {
        let code: String = (0..self.otp_length)
            .map(|_| char::from(b'0' + rand::thread_rng().gen_range(0..10)))
            .collect();
        let _ = ctx
            .database
            .create_verification_optional(CreateVerification {
                identifier: (identifier).into(),
                value: (if with_attempts {
                    format!("{code}:0")
                } else {
                    code.clone()
                })
                .into(),
                expires_at: better_auth_core::utils::date::from_milliseconds(
                    Utc::now().timestamp_millis() as f64 + self.expires_in * 1000.0,
                )
                .ok_or_else(|| AuthError::config("Phone OTP expiry is out of range"))?
                .into(),
                ..Default::default()
            })
            .await?;
        Ok(code)
    }
    async fn verify_stored_otp(
        &self,
        endpoint: &EndpointContext<'_, impl AuthSchema>,
        identifier: &str,
        code: &str,
    ) -> AuthResult<()> {
        let ctx = endpoint.auth;
        let existing = match endpoint.transaction {
            Some(transaction) => {
                transaction
                    .get_verification_including_expired(identifier)
                    .await?
            }
            None => {
                ctx.database
                    .get_verification_including_expired(identifier)
                    .await?
            }
        }
        .ok_or_else(|| error(400, "OTP_NOT_FOUND", "OTP not found"))?;
        if existing.expires_at.is_before(Utc::now())? {
            native::delete_verification(endpoint, identifier).await?;
            return Err(error(400, "OTP_EXPIRED", "OTP expired"));
        }
        if attempts(existing.value.typed()?) >= self.allowed_attempts {
            native::delete_verification(endpoint, identifier).await?;
            return Err(error(403, "TOO_MANY_ATTEMPTS", "Too many attempts"));
        }
        let consumed = match endpoint.transaction {
            Some(transaction) => {
                transaction
                    .consume_verification_by_identifier(identifier)
                    .await?
            }
            None => {
                ctx.database
                    .consume_verification_by_identifier(identifier)
                    .await?
            }
        }
        .ok_or_else(|| error(400, "INVALID_OTP", "Invalid OTP"))?;
        let count = attempts(consumed.value.typed()?);
        if count >= self.allowed_attempts {
            return Err(error(403, "TOO_MANY_ATTEMPTS", "Too many attempts"));
        }
        let expected = consumed
            .value
            .typed()?
            .split(':')
            .next()
            .unwrap_or_default();
        if expected != code {
            let input = CreateVerification {
                identifier: (identifier.to_owned()).into(),
                value: (format!("{expected}:{}", count + 1)).into(),
                expires_at: consumed.expires_at.clone(),
                ..Default::default()
            };
            let _ = match endpoint.transaction {
                Some(transaction) => transaction.create_verification_optional(input).await?,
                None => ctx.database.create_verification_optional(input).await?,
            };
            return Err(error(400, "INVALID_OTP", "Invalid OTP"));
        }
        Ok(())
    }
    /// Consume an OTP without updating a user or creating a session.
    pub async fn consume_otp(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        req: &AuthRequest,
        otp: PhoneOtp,
    ) -> AuthResult<()> {
        let endpoint = EndpointContext::new(
            Some(req),
            better_auth_core::FieldValue::from_json(
                json!({"phoneNumber":otp.phone_number,"code":otp.code}),
            )?,
            ctx,
        );
        self.consume_with_context(&endpoint, otp).await
    }
    async fn consume_with_context<S: AuthSchema>(
        &self,
        endpoint: &EndpointContext<'_, S>,
        otp: PhoneOtp,
    ) -> AuthResult<()> {
        let ctx = endpoint.auth;
        let verified = if let Some(verify) = ctx
            .extensions
            .get::<Arc<PhoneNumberCallbacks<S>>>()
            .and_then(|callbacks| callbacks.verify.as_ref())
        {
            Some(verify(&otp, endpoint).await?)
        } else if let Some(verify) = &self.verify_otp {
            let request = endpoint
                .request
                .ok_or_else(|| AuthError::config("Legacy phone callbacks require a request"))?;
            Some(verify(otp.clone(), request.clone()).await?)
        } else {
            None
        };
        match verified {
            Some(false) => Err(error(400, "INVALID_OTP", "Invalid OTP")),
            Some(true) => native::delete_verification(endpoint, &otp.phone_number).await,
            None => {
                self.verify_stored_otp(endpoint, &otp.phone_number, &otp.code)
                    .await
            }
        }
    }
    async fn send(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = match request::read(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        let phone = string(&body, "phoneNumber");
        if !self.has_sender(ctx, Delivery::Verification) {
            return Err(error(
                501,
                "SEND_OTP_NOT_IMPLEMENTED",
                "sendOTP not implemented",
            ));
        }
        let endpoint = EndpointContext::new(
            Some(req),
            better_auth_core::FieldValue::from_json(body.clone())?,
            ctx,
        );
        self.validate(phone).await?;
        let code = self.save_otp(ctx, phone.to_owned(), true).await?;
        let task = self.delivery(
            PhoneOtp {
                phone_number: phone.to_owned(),
                code,
            },
            &endpoint,
            Delivery::Verification,
        )?;
        if ctx.config.advanced.background_tasks.is_some() {
            better_auth_core::background::run_or_await(
                task,
                ctx.config.advanced.background_tasks.as_ref(),
                &ctx.config.logger,
            )
            .await;
        } else if let Some(task) = task {
            // The direct send endpoint propagates asynchronous failures without a handler.
            task.await?;
        }
        Ok(AuthResponse::json(None, &json!({"message":"code sent"}))?)
    }
    async fn verify(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = match request::read(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        let phone = string(&body, "phoneNumber");
        let mut endpoint = EndpointContext::new(
            Some(req),
            better_auth_core::FieldValue::from_json(body.clone())?,
            ctx,
        );
        self.consume_with_context(
            &endpoint,
            PhoneOtp {
                phone_number: phone.to_owned(),
                code: string(&body, "code").to_owned(),
            },
        )
        .await?;
        let update_phone = body.get("updatePhoneNumber") == Some(&Value::Bool(true));
        let existing_session = if update_phone {
            Some(ctx.require_native_session(req).await.map_err(|error| {
                if matches!(error, AuthError::Unauthenticated) {
                    self::error(401, "USER_NOT_FOUND", "User not found")
                } else {
                    error
                }
            })?)
        } else {
            None
        };
        let found = ctx.database.get_user_by_phone_number(phone).await?;
        let user = if let Some(session) = &existing_session {
            if found.is_some() {
                return Err(error(
                    400,
                    "PHONE_NUMBER_EXIST",
                    "Phone number already exists",
                ));
            }
            ctx.database
                .update_user_by_id_value(
                    session.user_property("id")?,
                    UpdateUser {
                        phone_number: Some(Some(phone.to_owned())),
                        phone_number_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?
                .ok_or_else(|| error(500, "FAILED_TO_UPDATE_USER", "Failed to update user"))?
        } else if let Some(user) = found {
            ctx.database
                .update_user_by_id_value(
                    &user.id().field_value(),
                    UpdateUser {
                        phone_number_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?
                .ok_or_else(|| error(500, "FAILED_TO_UPDATE_USER", "Failed to update user"))?
        } else if let Some(email) = &self.temp_email {
            let rest = body
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(key, _)| {
                    !["phoneNumber", "code", "disableSession", "updatePhoneNumber"]
                        .contains(&key.as_str())
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            let mut fields = ctx.parse_user_input(&rest, true)?;
            fields.extend([
                ("email".into(), email(phone).into()),
                (
                    "name".into(),
                    self.temp_name
                        .as_ref()
                        .map_or_else(|| phone.to_owned(), |name| name(phone))
                        .into(),
                ),
                ("phoneNumber".into(), phone.into()),
                ("phoneNumberVerified".into(), true.into()),
            ]);
            let create = CreateUser {
                additional_fields: fields,
                ..Default::default()
            };

            super::user_admission::create_user_optional(create, "phone-number", &endpoint)
                .await?
                .ok_or_else(|| error(500, "FAILED_TO_CREATE_USER", "Failed to create user"))?
        } else {
            return Err(error(500, "FAILED_TO_UPDATE_USER", "Failed to update user"));
        };
        endpoint.session = existing_session.clone();
        self.notify_verified(
            PhoneVerification {
                phone_number: phone.to_owned(),
                user: ctx.internal_user_view(&user).await?,
            },
            &endpoint,
        )
        .await?;
        if let Some(session) = existing_session {
            return Ok(AuthResponse::native(
                None,
                better_auth_core::FieldMap::from([
                    ("status".into(), true.into()),
                    ("token".into(), session.session.token.field_value()),
                    (
                        "user".into(),
                        better_auth_core::FieldMap::from(ctx.user_view(&user).await?).into(),
                    ),
                ])
                .into(),
            ));
        }
        if body.get("disableSession") == Some(&Value::Bool(true)) {
            return Ok(AuthResponse::json(
                None,
                &json!({"status":true,"token":null,"user":ctx.user_view(&user).await?}),
            )?);
        }
        self.session_response(ctx, req, &user, false, true).await
    }
    async fn sign_in(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = match request::read(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        let phone = string(&body, "phoneNumber");
        let password = string(&body, "password");
        self.validate(phone).await?;
        check_password_length(ctx, password, false)?;
        let user = ctx
            .database
            .get_user_by_phone_number(phone)
            .await?
            .ok_or_else(invalid_credentials)?;
        if self.require_verification && !user.phone_number_verified().is_truthy()? {
            let code = self.save_otp(ctx, phone.to_owned(), false).await?;
            if self.has_sender(ctx, Delivery::Verification) {
                let endpoint = EndpointContext::new(
                    Some(req),
                    better_auth_core::FieldValue::from_json(body.clone())?,
                    ctx,
                );
                let task = self.delivery(
                    PhoneOtp {
                        phone_number: phone.to_owned(),
                        code,
                    },
                    &endpoint,
                    Delivery::Verification,
                )?;
                better_auth_core::background::run_or_await(
                    task,
                    ctx.config.advanced.background_tasks.as_ref(),
                    &ctx.config.logger,
                )
                .await;
            }
            return Err(error(
                401,
                "PHONE_NUMBER_NOT_VERIFIED",
                "Phone number not verified",
            ));
        }
        let account = get_credential_account(ctx, user.id().into_owned())
            .await?
            .ok_or_else(invalid_credentials)?;
        if account.password.is_absent() {
            return Err(error(401, "UNEXPECTED_ERROR", "Unexpected error"));
        }
        let hash = account
            .password
            .typed()?
            .as_deref()
            .ok_or_else(|| error(401, "UNEXPECTED_ERROR", "Unexpected error"))?;
        match verify_password(ctx.password_policy.hasher.as_ref(), password, hash).await {
            Err(AuthError::InvalidCredentials) => return Err(invalid_credentials()),
            result => result?,
        }
        self.session_response(
            ctx,
            req,
            &user,
            body.get("rememberMe") == Some(&Value::Bool(false)),
            false,
        )
        .await
    }
    async fn session_response<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        req: &AuthRequest,
        user: &better_auth_core::wire::UserView,
        dont_remember: bool,
        status: bool,
    ) -> AuthResult<AuthResponse> {
        let meta = RequestMeta::from_request_with_config(req, &ctx.config.advanced.ip_address);
        let lifetime = if dont_remember {
            Duration::days(1)
        } else {
            ctx.config.session.expires_in()
        };
        let issued = issue_selected_user_session_optional(
            ctx,
            better_auth_core::FieldMap::from(ctx.internal_user_view(user).await?).into(),
            &meta,
            lifetime,
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?
        .ok_or_else(|| {
            if !status {
                ctx.config.logger.error("Failed to create session", &[]);
            }
            error(
                if status { 500 } else { 401 },
                "FAILED_TO_CREATE_SESSION",
                "Failed to create session",
            )
        })?;
        let mut output = better_auth_core::FieldMap::from([
            ("token".into(), issued.session.token().field_value()),
            (
                "user".into(),
                better_auth_core::FieldMap::from(ctx.user_view(user).await?).into(),
            ),
        ]);
        if status {
            let _ = output.insert("status".into(), true.into());
        }
        let manager = ctx.session_manager();
        manager
            .set_native_session_cookie(req, issued, Some(dont_remember))
            .await?;
        Ok(AuthResponse::native(None, output.into()))
    }
    async fn request_reset(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = match request::read(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        let phone = string(&body, "phoneNumber");
        let user = ctx.database.get_user_by_phone_number(phone).await?;
        let code = self
            .save_otp(ctx, format!("{phone}-request-password-reset"), true)
            .await?;
        if user.is_some() && self.has_sender(ctx, Delivery::PasswordReset) {
            let endpoint = EndpointContext::new(
                Some(req),
                better_auth_core::FieldValue::from_json(body.clone())?,
                ctx,
            );
            let task = self.delivery(
                PhoneOtp {
                    phone_number: phone.to_owned(),
                    code,
                },
                &endpoint,
                Delivery::PasswordReset,
            )?;
            better_auth_core::background::run_or_await(
                task,
                ctx.config.advanced.background_tasks.as_ref(),
                &ctx.config.logger,
            )
            .await;
        }
        Ok(AuthResponse::json(None, &json!({"status":true}))?)
    }
    async fn reset(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = match request::read(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        let phone = string(&body, "phoneNumber");
        let password = string(&body, "newPassword");
        self.verify_stored_otp(
            &EndpointContext::new(
                Some(req),
                better_auth_core::FieldValue::from_json(body.clone())?,
                ctx,
            ),
            &format!("{phone}-request-password-reset"),
            string(&body, "otp"),
        )
        .await?;
        let user = ctx
            .database
            .get_user_by_phone_number(phone)
            .await?
            .ok_or_else(|| error(400, "UNEXPECTED_ERROR", "Unexpected error"))?;
        check_password_length(ctx, password, true)?;
        let hash = hash_password(ctx.password_policy.hasher.as_ref(), password).await?;
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
                    provider_id: "credential".into(),
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
        if let Some(callback) = &ctx.password_policy.on_password_reset {
            callback(better_auth_core::utils::password::PasswordResetEvent {
                user: ctx.internal_user_view(&user).await?,
                request: Some(req.clone()),
            })
            .await?;
        }
        if ctx.password_policy.revoke_sessions_on_password_reset {
            ctx.database
                .delete_user_sessions(user.id().typed()?)
                .await?;
        }
        Ok(AuthResponse::json(None, &json!({"status":true}))?)
    }
}

fn check_password_length(
    ctx: &AuthContext<impl AuthSchema>,
    password: &str,
    check_min: bool,
) -> AuthResult<()> {
    if check_min && password.encode_utf16().count() < ctx.password_policy.min_length {
        return Err(error(400, "PASSWORD_TOO_SHORT", "Password too short"));
    }
    if password.encode_utf16().count() > ctx.password_policy.max_length {
        return Err(error(400, "PASSWORD_TOO_LONG", "Password too long"));
    }
    Ok(())
}
fn attempts(value: &str) -> u64 {
    value
        .split(':')
        .nth(1)
        .and_then(|value| value.parse().ok())
        .filter(|count| *count <= 9_007_199_254_740_991)
        .unwrap_or(0)
}
fn invalid_credentials() -> AuthError {
    error(
        401,
        "INVALID_PHONE_NUMBER_OR_PASSWORD",
        "Invalid phone number or password",
    )
}
fn error(status: u16, code: &'static str, message: &'static str) -> AuthError {
    AuthError::Upstream {
        status,
        code,
        message,
    }
}
fn string<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key).and_then(Value::as_str).unwrap_or_default()
}

better_auth_core::impl_auth_plugin!(PhoneNumberPlugin, "phone-number";
    routes {
        post "/sign-in/phone-number" => sign_in, "signInPhoneNumber", body = request::validate;
        post "/phone-number/send-otp" => send, "sendPhoneNumberOTP", body = request::validate;
        post "/phone-number/verify" => verify, "verifyPhoneNumber", body = request::validate;
        post "/phone-number/request-password-reset" => request_reset, "requestPasswordResetPhoneNumber", body = request::validate;
        post "/phone-number/reset-password" => reset, "resetPasswordPhoneNumber", body = request::validate;
    }
    extra {
        async fn on_init(
            &self,
            ctx: &mut better_auth_core::AuthInitContext<S>,
        ) -> AuthResult<()> {
            S::User::require_plugin_fields(
                "phone-number",
                &["phone_number", "phone_number_verified"],
            )?;
            ctx.register_native_user_fields("phone-number.enabled");
            ctx.set_metadata("phone-number.enabled", json!(true));
            ctx.extensions.insert(self.clone());
            Ok(())
        }
        fn rate_limits(
            &self,
        ) -> AuthResult<Vec<better_auth_core::middleware::PluginRateLimit>> {
            Ok(vec![better_auth_core::middleware::PluginRateLimit::prefix(
                "/phone-number",
                better_auth_core::middleware::EndpointRateLimit {
                    window: 60.0,
                    max_requests: 10.0,
                },
            )])
        }
        async fn before_request(
            &self,
            req: &AuthRequest,
            _ctx: &AuthContext<S>,
        ) -> AuthResult<Option<better_auth_core::BeforeRequestAction>> {
            if req.path() == "/update-user" {
                let body = match super::json_body::parse(req) {
                    Ok(body) => body,
                    Err(response) => {
                        return Ok(Some(better_auth_core::BeforeRequestAction::Respond(response)));
                    }
                };
                if body
                    .as_ref()
                    .and_then(|body| body.get("phoneNumber"))
                    .is_some_and(|value| !value.is_null())
                {
                    return better_auth_core::observability::instrumentation::with_endpoint_hook(&_ctx.config, req, "before", "plugin:phone-number", async {
                        Err(error(400, "PHONE_NUMBER_CANNOT_BE_UPDATED", "Phone number cannot be updated"))
                    }).await;
                }
            }
            Ok(None)
        }
    }
);
