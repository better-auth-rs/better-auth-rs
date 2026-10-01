use super::{SecretKey, VersionedSecret, warn_secret_strength};
use crate::{AuthConfig, AuthError, AuthResult};

pub(crate) const DEFAULT_SECRET: &str = "better-auth-secret-12345678901234567890";

#[derive(Default)]
struct SecretEnvironment {
    secrets: Option<String>,
    secret: Option<String>,
    auth_secret: Option<String>,
    node_env: Option<String>,
    test: Option<String>,
}

impl SecretEnvironment {
    fn read() -> AuthResult<Self> {
        fn variable(name: &str) -> AuthResult<Option<String>> {
            match std::env::var(name) {
                Ok(value) => Ok(Some(value)),
                Err(std::env::VarError::NotPresent) => Ok(None),
                Err(std::env::VarError::NotUnicode(_)) => Err(AuthError::config(format!(
                    "{name} must contain valid Unicode"
                ))),
            }
        }
        Ok(Self {
            secrets: variable("BETTER_AUTH_SECRETS")?,
            secret: variable("BETTER_AUTH_SECRET")?,
            auth_secret: variable("AUTH_SECRET")?,
            node_env: variable("NODE_ENV")?,
            test: variable("TEST")?,
        })
    }

    fn is_test(&self) -> bool {
        self.node_env.as_deref() == Some("test")
            || self
                .test
                .as_deref()
                .is_some_and(|value| !value.is_empty() && value != "false")
    }
}

impl AuthConfig {
    /// Resolve secret environment variables and validate the selected keys.
    ///
    /// The builder calls this before plugins initialize. Explicit configuration takes
    /// precedence over environment variables. Production rejects the development key.
    pub fn resolve_secrets(&mut self) -> AuthResult<()> {
        self.resolve_secret_environment(&SecretEnvironment::read()?)
    }

    fn resolve_secret_environment(&mut self, env: &SecretEnvironment) -> AuthResult<()> {
        let keys = match &self.secrets {
            Some(keys) => Some(keys.clone()),
            None => parse_secrets_env(env.secrets.as_deref())?,
        };
        let legacy = [
            Some(self.secret.as_str()),
            env.secret.as_deref(),
            env.auth_secret.as_deref(),
        ]
        .into_iter()
        .flatten()
        .find(|value| !value.is_empty())
        .unwrap_or("");
        if let Some(keys) = &keys {
            SecretKey::Versioned {
                keys,
                legacy_secret: None,
            }
            .validate(&self.logger)?;
        } else if !env.is_test() {
            let secret = if legacy.is_empty() {
                DEFAULT_SECRET
            } else {
                legacy
            };
            if secret == DEFAULT_SECRET && env.node_env.as_deref() == Some("production") {
                return Err(AuthError::config(
                    "You are using the default secret. Please set `BETTER_AUTH_SECRET` in your environment variables or pass `secret` in your auth config.",
                ));
            }
            warn_secret_strength(secret, &self.logger);
        }
        self.secret = if keys.is_none() && legacy.is_empty() {
            DEFAULT_SECRET
        } else {
            legacy
        }
        .to_owned();
        self.secrets = keys;
        Ok(())
    }
}

fn js_whitespace(character: char) -> bool {
    matches!(character, '\u{9}'..='\u{d}' | '\u{20}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}

fn parse_version_number(value: &str) -> Option<f64> {
    let value = value.trim_start_matches(js_whitespace);
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    let digits = unsigned.bytes().take_while(u8::is_ascii_digit).count();
    let number: f64 = unsigned.get(..digits)?.parse().ok()?;
    let number = if value.starts_with('-') {
        -number
    } else {
        number
    };
    (number.is_finite() && number >= 0.0).then_some(number)
}

/// Parse the decimal prefix with the same rounding and canonical range as JavaScript versions.
pub(crate) fn parse_secret_version(value: &str) -> Option<u128> {
    let number = parse_version_number(value)?;
    if number >= 1e21 {
        return None;
    }
    if number == 0.0 {
        return Some(0);
    }
    number.to_string().parse().ok()
}

fn parse_secrets_env(value: Option<&str>) -> AuthResult<Option<Vec<VersionedSecret>>> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    value.split(',').map(|entry| {
        let entry = entry.trim_matches(js_whitespace);
        let (version, value) = entry.split_once(':').ok_or_else(|| AuthError::config(format!("Invalid BETTER_AUTH_SECRETS entry: \"{entry}\". Expected format: \"<version>:<secret>\"")))?;
        let number = parse_version_number(version).ok_or_else(|| AuthError::config(format!("Invalid version in BETTER_AUTH_SECRETS: \"{version}\". Version must be a non-negative integer.")))?;
        let version = parse_secret_version(version).ok_or_else(|| AuthError::config(format!("Invalid version {number:e} in `secrets`. Version must be a non-negative integer.")))?;
        let value = value.trim_matches(js_whitespace);
        if value.is_empty() {
            return Err(AuthError::config(format!("Empty secret value for version {version} in BETTER_AUTH_SECRETS.")));
        }
        Ok(VersionedSecret::new(version, value))
    }).collect::<AuthResult<Vec<_>>>().map(Some)
}

#[cfg(test)]
mod tests;
