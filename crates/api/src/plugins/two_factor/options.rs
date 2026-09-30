use std::{future::Future, pin::Pin, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::AuthResult;
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
    pub(super) async fn encode(&self, value: &str, secret: &str) -> AuthResult<String> {
        match self {
            Self::Plain => Ok(value.to_owned()),
            Self::Hashed => Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))),
            Self::Encrypted => crate::plugins::symmetric::encrypt(secret, value),
            Self::CustomHash(hash) => hash(value.to_owned()).await,
            Self::CustomEncryption(cipher) => cipher.encrypt(value).await,
        }
    }

    pub(super) async fn verify(&self, stored: &str, input: &str, secret: &str) -> AuthResult<bool> {
        let (stored, input) = match self {
            Self::Encrypted => (
                crate::plugins::symmetric::decrypt(secret, stored)?,
                input.to_owned(),
            ),
            Self::CustomEncryption(cipher) => (cipher.decrypt(stored).await?, input.to_owned()),
            _ => (stored.to_owned(), self.encode(input, secret).await?),
        };
        Ok(stored.len() == input.len() && openssl::memcmp::eq(stored.as_bytes(), input.as_bytes()))
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
    pub(super) async fn encode(&self, codes: &[String], secret: &str) -> AuthResult<String> {
        let json = serde_json::to_string(codes)?;
        match self {
            Self::Plain => Ok(json),
            Self::Encrypted => crate::plugins::symmetric::encrypt(secret, &json),
            Self::Custom(cipher) => cipher.encrypt(&json).await,
        }
    }

    pub(super) async fn decode(
        &self,
        stored: &str,
        secret: &str,
    ) -> AuthResult<Option<Vec<String>>> {
        let json = match self {
            Self::Plain => stored.to_owned(),
            Self::Encrypted => crate::plugins::symmetric::decrypt(secret, stored)?,
            Self::Custom(cipher) => cipher.decrypt(stored).await?,
        };
        // Upstream safeJSONParse treats malformed backup-code JSON as an invalid code.
        Ok(serde_json::from_str(&json).ok())
    }
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
