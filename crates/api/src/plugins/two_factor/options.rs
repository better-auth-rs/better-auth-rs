use std::{future::Future, pin::Pin, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthError, AuthResult, FieldValue, SecretKey};
use rand::{Rng, distributions::Alphanumeric};
use sha2::{Digest, Sha256};

/// Application hashing callback for stored second-factor codes.
pub type TwoFactorHasher =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = AuthResult<String>> + Send>> + Send + Sync>;

/// Reversible application encryption for OTPs or serialized backup codes.
#[async_trait]
pub trait TwoFactorCipher: Send + Sync {
    /// Encrypt plaintext before persistence.
    async fn encrypt(&self, plaintext: &str) -> AuthResult<String>;
    /// Decrypt a stored value before verification.
    async fn decrypt(&self, ciphertext: &str) -> AuthResult<String>;
    /// Encrypt plaintext without restricting the stored representation to a string.
    async fn encrypt_native(&self, plaintext: &str) -> AuthResult<FieldValue> {
        self.encrypt(plaintext).await.map(Into::into)
    }
    /// Receive the projected ciphertext before JSON parsing or text encoding.
    async fn decrypt_native(&self, ciphertext: &FieldValue) -> AuthResult<FieldValue> {
        self.decrypt(&ciphertext_string(ciphertext)?)
            .await
            .map(Into::into)
    }
}

/// Storage protection for delivered second-factor OTPs.
#[derive(Clone, Default)]
pub enum TwoFactorOtpStorage {
    /// Store the original code, matching the upstream default.
    #[default]
    Plain,
    /// Store an unpadded base64url SHA-256 digest.
    Hashed,
    /// Encrypt using the authentication secret.
    Encrypted,
    /// Hash using an asynchronous application callback.
    CustomHash(TwoFactorHasher),
    /// Encrypt and decrypt using application callbacks.
    CustomEncryption(Arc<dyn TwoFactorCipher>),
}

impl TwoFactorOtpStorage {
    pub(super) async fn encode(
        &self,
        value: &str,
        secret: SecretKey<'_>,
    ) -> AuthResult<FieldValue> {
        let encoded = match self {
            Self::Plain => Ok(value.to_owned()),
            Self::Hashed => Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))),
            Self::Encrypted => crate::plugins::symmetric::encrypt(secret, value),
            Self::CustomHash(hash) => hash(value.to_owned()).await,
            Self::CustomEncryption(cipher) => return cipher.encrypt_native(value).await,
        }?;
        Ok(encoded.into())
    }

    pub(super) async fn verify(
        &self,
        stored: &FieldValue,
        input: &str,
        secret: SecretKey<'_>,
    ) -> AuthResult<bool> {
        let (stored, input) = match self {
            Self::Encrypted => (
                crate::plugins::symmetric::decrypt_field(secret, stored)?.into(),
                input.into(),
            ),
            Self::CustomEncryption(cipher) => (cipher.decrypt_native(stored).await?, input.into()),
            _ => (stored.clone(), self.encode(input, secret).await?),
        };
        let stored = text_encoder_bytes(&stored)?;
        let input = text_encoder_bytes(&input)?;
        Ok(stored.len() == input.len() && openssl::memcmp::eq(&stored, &input))
    }
}

/// Storage protection for the JSON array of backup codes.
#[derive(Clone, Default)]
pub enum BackupCodeStorage {
    /// Store the serialized JSON array unchanged.
    Plain,
    /// Encrypt using the authentication secret, matching the upstream default.
    #[default]
    Encrypted,
    /// Encrypt and decrypt the serialized array using application callbacks.
    Custom(Arc<dyn TwoFactorCipher>),
}

impl BackupCodeStorage {
    pub(super) async fn encode(
        &self,
        codes: &FieldValue,
        secret: SecretKey<'_>,
    ) -> AuthResult<FieldValue> {
        let json = codes
            .stringify()?
            .ok_or_else(|| AuthError::internal("Cannot encode undefined backup codes"))?;
        let encoded = match self {
            Self::Plain => Ok(json),
            Self::Encrypted => crate::plugins::symmetric::encrypt(secret, &json),
            Self::Custom(cipher) => return cipher.encrypt_native(&json).await,
        }?;
        Ok(encoded.into())
    }

    pub(super) async fn decode(
        &self,
        stored: &FieldValue,
        secret: SecretKey<'_>,
    ) -> AuthResult<FieldValue> {
        let value = match self {
            Self::Plain => stored.clone(),
            Self::Encrypted => crate::plugins::symmetric::decrypt_field(secret, stored)?.into(),
            Self::Custom(cipher) => cipher.decrypt_native(stored).await?,
        };
        better_auth_core::utils::json::safe_parse_field(&value)
    }
}

fn ciphertext_string(value: &FieldValue) -> AuthResult<String> {
    match value {
        FieldValue::String(value) => Ok(value.clone()),
        FieldValue::Utf16String(value) => value
            .to_utf8()
            .map_err(|error| AuthError::internal(error.to_string())),
        _ => Err(AuthError::internal(
            "The string cipher callback requires string ciphertext",
        )),
    }
}

fn text_encoder_bytes(value: &FieldValue) -> AuthResult<Vec<u8>> {
    if value.is_undefined() {
        return Ok(Vec::new());
    }
    Ok(String::from_utf16_lossy(value.display_utf16()?.as_utf16()).into_bytes())
}

/// Preserve the distinct invalid-code and method-call failure paths before consuming a code.
pub(super) fn remaining_backup_codes(
    codes: &FieldValue,
    code: &str,
) -> AuthResult<Option<FieldValue>> {
    if !codes.is_truthy() {
        return Ok(None);
    }
    let Some(codes) = codes.as_array() else {
        return Err(AuthError::internal(if codes.is_string() {
            "codes.filter is not a function"
        } else {
            "codes.includes is not a function"
        }));
    };
    let code = FieldValue::from(code);
    if !codes
        .iter()
        .any(|candidate| candidate.same_value_zero(&code))
    {
        return Ok(None);
    }
    Ok(Some(
        codes
            .iter()
            .filter(|candidate| !candidate.strict_equals(&code))
            .cloned()
            .collect::<Vec<_>>()
            .into(),
    ))
}

/// Recovery-code generation and passwordless management policy.
#[derive(Clone)]
pub struct BackupCodeOptions {
    /// Number of generated codes. Zero produces an empty list.
    pub amount: usize,
    /// Number of random characters, before the separator after character five.
    pub length: usize,
    /// Replace random generation with application-supplied codes.
    pub generate: Option<Arc<dyn Fn() -> Vec<String> + Send + Sync>>,
    /// Stored backup-code representation.
    pub storage: BackupCodeStorage,
    /// Override the plugin's passwordless policy for regeneration.
    pub allow_passwordless: Option<bool>,
}

impl Default for BackupCodeOptions {
    fn default() -> Self {
        Self {
            amount: 10,
            length: 10,
            generate: None,
            storage: BackupCodeStorage::Encrypted,
            allow_passwordless: None,
        }
    }
}

impl BackupCodeOptions {
    pub(super) fn generate(&self) -> Vec<String> {
        if let Some(generate) = &self.generate {
            return generate();
        }
        (0..self.amount)
            .map(|_| {
                let code: String = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(self.length)
                    .map(char::from)
                    .collect();
                let (prefix, suffix) = code.split_at(code.len().min(5));
                format!("{prefix}-{suffix}")
            })
            .collect()
    }
}
