//! Verification identifier storage and migration policies.

use crate::AuthResult;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Application identifier transformation. Errors abort the storage operation.
#[async_trait]
pub trait VerificationIdentifierHasher: Send + Sync {
    /// Transform the complete logical identifier before persistence.
    async fn hash(&self, identifier: &str) -> AuthResult<String>;
}

/// Persistence strategy for verification identifiers.
#[derive(Clone, Default)]
pub enum VerificationIdentifierStorage {
    /// Persist identifiers without transformation.
    #[default]
    Plain,
    /// Persist unpadded URL-safe SHA-256 digests.
    Hashed,
    /// Use an application-supplied asynchronous hash function.
    Custom(Arc<dyn VerificationIdentifierHasher>),
}

impl std::fmt::Debug for VerificationIdentifierStorage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Plain => "Plain",
            Self::Hashed => "Hashed",
            Self::Custom(_) => "Custom(..)",
        })
    }
}

/// Ordered prefix overrides match upstream object insertion order.
#[derive(Debug, Clone, Default)]
pub struct VerificationIdentifierConfig {
    /// Strategy used when no prefix matches.
    pub default: VerificationIdentifierStorage,
    /// First matching prefix wins. Prefixes match the logical identifier.
    pub overrides: Vec<(String, VerificationIdentifierStorage)>,
}

impl VerificationIdentifierConfig {
    /// Whether all identifiers retain their original representation.
    pub fn is_plain(&self) -> bool {
        matches!(self.default, VerificationIdentifierStorage::Plain)
            && self
                .overrides
                .iter()
                .all(|(_, strategy)| matches!(strategy, VerificationIdentifierStorage::Plain))
    }

    pub(crate) async fn process(&self, identifier: &str) -> AuthResult<(String, bool)> {
        let strategy = self
            .overrides
            .iter()
            .find(|(prefix, _)| identifier.starts_with(prefix))
            .map_or(&self.default, |(_, strategy)| strategy);
        match strategy {
            VerificationIdentifierStorage::Plain => Ok((identifier.to_owned(), false)),
            VerificationIdentifierStorage::Hashed => Ok((
                URL_SAFE_NO_PAD.encode(Sha256::digest(identifier.as_bytes())),
                true,
            )),
            VerificationIdentifierStorage::Custom(hash) => Ok((hash.hash(identifier).await?, true)),
        }
    }
}
