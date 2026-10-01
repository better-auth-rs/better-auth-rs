use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    AuthContext, AuthError, AuthResult, AuthSchema, AuthVerification, CreateVerification,
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};

use super::EmailOtpCallbacks;
use super::{EmailOtpMessage, EmailOtpPlugin, EmailOtpStorage, EmailOtpType};
use crate::plugins::endpoint_context::EndpointContext;
use crate::plugins::symmetric::{decrypt, encrypt};
use std::sync::Arc;

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
    pub(super) fn has_sender<S: AuthSchema>(&self, ctx: &AuthContext<S>) -> bool {
        self.config.sender.is_some()
            || ctx
                .extensions
                .get::<Arc<EmailOtpCallbacks<S>>>()
                .is_some_and(|callbacks| callbacks.sender.is_some())
    }
    fn generate<S: AuthSchema>(
        &self,
        endpoint: &EndpointContext<'_, S>,
        email: &str,
        kind: EmailOtpType,
    ) -> AuthResult<String> {
        let code = if let Some(generator) = endpoint
            .auth
            .extensions
            .get::<Arc<EmailOtpCallbacks<S>>>()
            .and_then(|callbacks| callbacks.generator.as_ref())
        {
            generator(email, kind, endpoint)?
        } else {
            self.config
                .generate_otp
                .as_ref()
                .and_then(|generate| generate(email, kind))
        };
        Ok(code.filter(|otp| !otp.is_empty()).unwrap_or_else(|| {
            (0..self.config.otp_length)
                .map(|_| char::from(b'0' + rand::thread_rng().gen_range(0..10)))
                .collect()
        }))
    }
    async fn store_code(
        &self,
        code: &str,
        secret: better_auth_core::SecretKey<'_>,
    ) -> AuthResult<String> {
        match &self.config.storage {
            EmailOtpStorage::Plain => Ok(code.to_owned()),
            EmailOtpStorage::Hashed => Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(code.as_bytes()))),
            EmailOtpStorage::Encrypted => encrypt(secret, code),
            EmailOtpStorage::CustomHash(hash) => hash(code.to_owned()).await,
            EmailOtpStorage::CustomEncryption(codec) => codec.encode(code).await,
        }
    }
    pub(super) async fn recover(
        &self,
        code: &str,
        secret: better_auth_core::SecretKey<'_>,
    ) -> AuthResult<Option<String>> {
        match &self.config.storage {
            EmailOtpStorage::Plain => Ok(Some(code.to_owned())),
            EmailOtpStorage::Hashed | EmailOtpStorage::CustomHash(_) => Ok(None),
            EmailOtpStorage::Encrypted => decrypt(secret, code).map(Some),
            EmailOtpStorage::CustomEncryption(codec) => codec.decode(code).await.map(Some),
        }
    }
    async fn matches(
        &self,
        stored: &str,
        provided: &str,
        secret: better_auth_core::SecretKey<'_>,
    ) -> AuthResult<bool> {
        let (stored, provided) = match self.recover(stored, secret).await? {
            Some(plaintext) => (plaintext, provided.to_owned()),
            None => (stored.to_owned(), self.store_code(provided, secret).await?),
        };
        // HMAC verification compares fixed-size tags without exposing a matching code prefix.
        let secret = secret.current()?;
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
    pub(super) async fn deliver<S: AuthSchema>(
        &self,
        endpoint: &EndpointContext<'_, S>,
        email: &str,
        otp: String,
        kind: EmailOtpType,
    ) -> AuthResult<()> {
        let message = EmailOtpMessage {
            email: email.to_owned(),
            otp,
            kind,
        };
        let result = if let Some(sender) = endpoint
            .auth
            .extensions
            .get::<Arc<EmailOtpCallbacks<S>>>()
            .and_then(|callbacks| callbacks.sender.as_ref())
        {
            sender(&message, endpoint).await
        } else {
            self.config
                .sender
                .as_ref()
                .ok_or_else(|| {
                    AuthError::bad_request("send email verification is not implemented")
                })?
                .send(&message)
                .await
        };
        // Upstream logs notification failures without changing the endpoint result.
        if let Err(error) = result {
            tracing::error!(plugin = "email-otp", %error, "Failed to run background task");
        }
        Ok(())
    }
    pub(super) async fn create_otp(
        &self,
        endpoint: &EndpointContext<'_, impl AuthSchema>,
        email: &str,
        kind: EmailOtpType,
        identifier: &str,
    ) -> AuthResult<String> {
        let ctx = endpoint.auth;
        let otp = self.generate(endpoint, email, kind)?;
        let stored = self
            .store_code(&otp, ctx.config.encryption_secret())
            .await?;
        let input = CreateVerification {
            identifier: identifier.to_owned(),
            value: format!("{stored}:0"),
            expires_at: Utc::now() + self.config.expires_in,
        };
        let _ = match endpoint.transaction {
            Some(transaction) => transaction.create_verification(input).await?,
            None => ctx.database.create_verification(input).await?,
        };
        Ok(otp)
    }
    pub(super) async fn resolve_otp(
        &self,
        endpoint: &EndpointContext<'_, impl AuthSchema>,
        email: &str,
        kind: EmailOtpType,
    ) -> AuthResult<String> {
        let ctx = endpoint.auth;
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
                    .recover(stored, ctx.config.encryption_secret())
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
        self.create_otp(endpoint, email, kind, &identifier).await
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
        if !self
            .matches(stored, provided, ctx.config.encryption_secret())
            .await?
        {
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

pub(super) fn split(value: &str) -> (&str, u32) {
    value
        .rsplit_once(':')
        .map_or((value, 0), |(code, attempts)| {
            (code, attempts.parse().unwrap_or(0))
        })
}
