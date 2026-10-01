use better_auth_core::{
    AuthContext, AuthRequest, AuthResponse, AuthResult, AuthSchema, RequestMeta,
};
use serde_json::json;

use super::config::error;
use super::{UsernamePlugin, UsernameValidationOrder, request};
use crate::plugins::email_password::{
    EmailPasswordConfig, SignInCoreResult, SignInUsernameFailure, sign_in_username_core,
};

impl UsernamePlugin {
    pub(crate) async fn available<S: AuthSchema>(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let username = request::availability(request).map_err(better_auth_core::AuthError::from)?;
        if username.is_empty() {
            return Err(error(422, "INVALID_USERNAME", "Username is invalid"));
        }
        if let Some((code, message)) = self.config.validate_raw(&username).await? {
            return Err(error(422, code, message));
        }
        let found = context
            .database
            .get_user_by_username(&self.config.normalize(&username)?)
            .await?;
        Ok(AuthResponse::json(
            200,
            &json!({"available": found.is_none()}),
        )?)
    }

    pub(super) async fn sign_in<S: AuthSchema>(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        self.sign_in_with_verification(request, context, None).await
    }

    pub(crate) async fn sign_in_with_verification<S: AuthSchema>(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
        verification: Option<&crate::plugins::email_verification::EmailVerificationPlugin>,
    ) -> AuthResult<AuthResponse> {
        let body = request::sign_in(request).map_err(better_auth_core::AuthError::from)?;
        if body.username.is_empty() || body.password.is_empty() {
            return Err(error(
                401,
                "INVALID_USERNAME_OR_PASSWORD",
                "Invalid username or password",
            ));
        }
        let username = if self.config.username_validation_order
            == Some(UsernameValidationOrder::PreNormalization)
        {
            self.config.normalize(&body.username)?
        } else {
            body.username.clone()
        };
        if let Some((code, message)) = self.config.validate_raw(&username).await? {
            return Err(error(422, code, message));
        }
        let username = self.config.normalize(&username)?;
        let fallback = EmailPasswordConfig::default();
        let password = context
            .extensions
            .get::<EmailPasswordConfig>()
            .unwrap_or(&fallback);
        let meta =
            RequestMeta::from_request_with_config(request, &context.config.advanced.ip_address);
        let result = sign_in_username_core(
            request,
            &body,
            &username,
            password,
            verification,
            &meta,
            context,
        )
        .await;
        match result {
            Ok(SignInCoreResult::Success {
                response,
                set_cookie_headers,
            }) => {
                let mut response = AuthResponse::json(200, &response)?;
                for value in set_cookie_headers {
                    response.headers.append("Set-Cookie", value);
                }
                if let Some(callback) = body.callback_url.filter(|value| !value.is_empty()) {
                    let _ = response.headers.insert("Location", callback);
                }
                Ok(response)
            }
            Ok(SignInCoreResult::TwoFactorRedirect {
                response,
                set_cookie_headers,
            }) => {
                let mut response = AuthResponse::json(200, &response)?;
                for value in set_cookie_headers {
                    response.headers.append("Set-Cookie", value);
                }
                Ok(response)
            }
            Err(SignInUsernameFailure::InvalidUsernameOrPassword) => Err(error(
                401,
                "INVALID_USERNAME_OR_PASSWORD",
                "Invalid username or password",
            )),
            Err(SignInUsernameFailure::EmailNotVerified) => {
                Err(error(403, "EMAIL_NOT_VERIFIED", "Email not verified"))
            }
            Err(SignInUsernameFailure::Auth(error)) => Err(error),
        }
    }
}
