use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    AuthContext, AuthError, AuthResult, AuthSchema, AuthVerification, CreateVerification,
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};

use super::{EmailOtpMessage, EmailOtpPlugin, EmailOtpStorage, EmailOtpType};
use crate::plugins::symmetric::{decrypt, encrypt};

pub(super) struct VerificationSender<S: AuthSchema> {
    pub(super) config: super::EmailOtpConfig,
    pub(super) context: AuthContext<S>,
}

#[async_trait::async_trait]
impl<S: AuthSchema> better_auth_core::email::SendVerificationEmail for VerificationSender<S> {
    async fn send(
        &self,
        user: &better_auth_core::wire::UserView,
        _url: &str,
        _token: &str,
    ) -> AuthResult<()> {
        let email = user
            .email
            .as_deref()
            .ok_or_else(|| AuthError::bad_request("Invalid email"))?;
        let plugin = EmailOtpPlugin::with_config(self.config.clone());
        let kind = EmailOtpType::EmailVerification;
        let otp = plugin.resolve_otp(&self.context, email, kind).await?;
        if self
            .context
            .database
            .get_user_by_email(email)
            .await?
            .is_none()
        {
            self.context
                .database
                .delete_verification_by_identifier(&kind.identifier(email))
                .await?;
            return Ok(());
        }
        plugin.deliver(email, otp, kind).await
    }
}

pub(super) fn invalid_otp() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: "INVALID_OTP",
        message: "Invalid OTP",
    }
}
fn expired_otp() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: "OTP_EXPIRED",
        message: "OTP expired",
    }
}
fn too_many_attempts() -> AuthError {
    AuthError::Upstream {
        status: 403,
        code: "TOO_MANY_ATTEMPTS",
        message: "Too many attempts",
    }
}

impl EmailOtpPlugin {
    fn attempts(&self) -> u32 {
        if self.config.allowed_attempts == 0 {
            3
        } else {
            self.config.allowed_attempts
        }
    }
    fn generate(&self, email: &str, kind: EmailOtpType) -> String {
        self.config
            .generate_otp
            .as_ref()
            .and_then(|generate| generate(email, kind))
            .filter(|otp| !otp.is_empty())
            .unwrap_or_else(|| {
                (0..self.config.otp_length)
                    .map(|_| char::from(b'0' + rand::thread_rng().gen_range(0..10)))
                    .collect()
            })
    }
    async fn store_code(&self, code: &str, secret: &str) -> AuthResult<String> {
        match &self.config.storage {
            EmailOtpStorage::Plain => Ok(code.to_owned()),
            EmailOtpStorage::Hashed => Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(code.as_bytes()))),
            EmailOtpStorage::Encrypted => encrypt(secret, code),
            EmailOtpStorage::Custom(codec) => codec.encode(code).await,
        }
    }
    async fn recover(&self, code: &str, secret: &str) -> AuthResult<Option<String>> {
        match &self.config.storage {
            EmailOtpStorage::Plain => Ok(Some(code.to_owned())),
            EmailOtpStorage::Hashed => Ok(None),
            EmailOtpStorage::Encrypted => decrypt(secret, code).map(Some),
            EmailOtpStorage::Custom(codec) => codec.decode(code).await,
        }
    }
    async fn matches(&self, stored: &str, provided: &str, secret: &str) -> AuthResult<bool> {
        let (stored, provided) = match self.recover(stored, secret).await? {
            Some(plaintext) => (plaintext, provided.to_owned()),
            None => (stored.to_owned(), self.store_code(provided, secret).await?),
        };
        // HMAC verification compares fixed-size tags without exposing a matching code prefix.
        let mut expected = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .map_err(|error| AuthError::internal(error.to_string()))?;
        expected.update(stored.as_bytes());
        let mut actual = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .map_err(|error| AuthError::internal(error.to_string()))?;
        actual.update(provided.as_bytes());
        Ok(actual
            .verify_slice(&expected.finalize().into_bytes())
            .is_ok())
    }
    pub(super) async fn deliver(
        &self,
        email: &str,
        otp: String,
        kind: EmailOtpType,
    ) -> AuthResult<()> {
        let sender =
            self.config.sender.as_ref().ok_or_else(|| {
                AuthError::bad_request("send email verification is not implemented")
            })?;
        // Upstream runInBackgroundOrAwait logs sender failures without changing the HTTP response.
        if let Err(error) = sender
            .send(&EmailOtpMessage {
                email: email.to_owned(),
                otp,
                kind,
            })
            .await
        {
            tracing::error!(plugin = "email-otp", %error, "Failed to run background task");
        }
        Ok(())
    }
    pub(super) async fn create_otp(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        email: &str,
        kind: EmailOtpType,
        identifier: &str,
    ) -> AuthResult<String> {
        let otp = self.generate(email, kind);
        let stored = self.store_code(&otp, &ctx.config.secret).await?;
        let _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: identifier.to_owned(),
                value: format!("{stored}:0"),
                expires_at: Utc::now() + self.config.expires_in,
            })
            .await?;
        Ok(otp)
    }
    pub(super) async fn resolve_otp(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        email: &str,
        kind: EmailOtpType,
    ) -> AuthResult<String> {
        let identifier = kind.identifier(email);
        if self.config.reuse_otp
            && let Some(existing) = ctx
                .database
                .get_verification_including_expired(&identifier)
                .await?
        {
            let (stored, attempts) = split(existing.value());
            if existing.expires_at() >= Utc::now()
                && attempts < self.attempts()
                && let Some(otp) = self
                    .recover(stored, &ctx.config.secret)
                    .await?
                    .filter(|otp| !otp.is_empty())
            {
                ctx.database
                    .update_verification_by_identifier(
                        &identifier,
                        None,
                        Some(Utc::now() + self.config.expires_in),
                    )
                    .await?;
                return Ok(otp);
            }
        }
        self.create_otp(ctx, email, kind, &identifier).await
    }
    pub(super) async fn verify_otp(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        identifier: &str,
        provided: &str,
        consume: bool,
    ) -> AuthResult<()> {
        let existing = ctx
            .database
            .get_verification_including_expired(identifier)
            .await?;
        if existing
            .as_ref()
            .is_some_and(|row| row.expires_at() < Utc::now())
        {
            ctx.database
                .delete_verification_by_identifier(identifier)
                .await?;
            return Err(expired_otp());
        }
        let record = if consume {
            ctx.database
                .consume_verification_by_identifier(identifier)
                .await?
        } else {
            existing
        }
        .ok_or_else(invalid_otp)?;
        let (stored, attempts) = split(record.value());
        if attempts >= self.attempts() {
            if !consume {
                ctx.database
                    .delete_verification_by_identifier(identifier)
                    .await?;
            }
            return Err(too_many_attempts());
        }
        if !self.matches(stored, provided, &ctx.config.secret).await? {
            let value = format!("{stored}:{}", attempts + 1);
            if consume {
                let _ = ctx
                    .database
                    .create_verification(CreateVerification {
                        identifier: identifier.to_owned(),
                        value,
                        expires_at: record.expires_at(),
                    })
                    .await?;
            } else {
                ctx.database
                    .update_verification_by_identifier(identifier, Some(value), None)
                    .await?;
            }
            return Err(invalid_otp());
        }
        Ok(())
    }
}

fn split(value: &str) -> (&str, u32) {
    value
        .rsplit_once(':')
        .map_or((value, 0), |(code, attempts)| {
            (code, attempts.parse().unwrap_or(0))
        })
}
