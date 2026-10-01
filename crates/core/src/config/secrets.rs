use std::collections::HashSet;

use crate::{AuthError, AuthResult};

mod environment;
pub(super) use environment::DEFAULT_SECRET;
pub(crate) use environment::parse_secret_version;

/// An encryption key retained under a stable version during rotation.
#[derive(Clone)]
pub struct VersionedSecret {
    pub version: u128,
    pub value: String,
}

impl VersionedSecret {
    pub fn new(version: u128, value: impl Into<String>) -> Self {
        Self {
            version,
            value: value.into(),
        }
    }
}

impl std::fmt::Debug for VersionedSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VersionedSecret")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// Borrowed encryption keys. The first versioned key encrypts new data.
#[derive(Clone, Copy)]
pub enum SecretKey<'a> {
    Single(&'a str),
    Versioned {
        keys: &'a [VersionedSecret],
        legacy_secret: Option<&'a str>,
    },
}

impl<'a> From<&'a str> for SecretKey<'a> {
    fn from(secret: &'a str) -> Self {
        Self::Single(secret)
    }
}

impl<'a> From<&'a String> for SecretKey<'a> {
    fn from(secret: &'a String) -> Self {
        Self::Single(secret)
    }
}

impl<'a> SecretKey<'a> {
    pub fn current(self) -> AuthResult<&'a str> {
        match self {
            Self::Single(secret) => Ok(secret),
            Self::Versioned { keys, .. } => {
                keys.first().map(|key| key.value.as_str()).ok_or_else(|| {
                    AuthError::config("`secrets` array must contain at least one entry.")
                })
            }
        }
    }

    pub(crate) fn validate(self) -> AuthResult<()> {
        let Self::Versioned { keys, .. } = self else {
            return Ok(());
        };
        let _ = self.current()?;
        let mut versions = HashSet::new();
        for key in keys {
            if parse_secret_version(&key.version.to_string()) != Some(key.version) {
                return Err(AuthError::config(format!(
                    "Invalid version {} in `secrets`. Version must be a canonical non-negative JavaScript integer below 1e21.",
                    key.version
                )));
            }
            if key.value.is_empty() {
                return Err(AuthError::config(format!(
                    "Empty secret value for version {} in `secrets`.",
                    key.version
                )));
            }
            if !versions.insert(key.version) {
                return Err(AuthError::config(format!(
                    "Duplicate version {} in `secrets`. Each version must be unique.",
                    key.version
                )));
            }
        }
        warn_secret_strength(self.current()?);
        Ok(())
    }
}

pub(super) fn warn_secret_strength(secret: &str) {
    let length = secret.encode_utf16().count();
    if length < 32 {
        tracing::warn!("The authentication secret should be at least 32 characters long");
    }
    let unique = secret.chars().collect::<HashSet<_>>().len();
    if (unique as f64).log2() * (length as f64) < 120.0 {
        tracing::warn!(
            "The authentication secret appears low-entropy; use a randomly generated secret for production"
        );
    }
}
