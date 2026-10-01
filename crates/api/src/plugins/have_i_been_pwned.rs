//! Password compromise checks at the password hashing boundary.

use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, PasswordHasher, ScryptPasswordHasher,
};
use sha1::{Digest, Sha1};

const RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
const COMPROMISED: &str =
    "The password you entered has been compromised. Please choose a different password.";
const CHECK_FAILED: &str = "Failed to check password. Please try again later.";

fn check_error(message: impl AsRef<str>) -> AuthError {
    match AuthResponse::json(500, &serde_json::json!({ "message": message.as_ref() })) {
        Ok(response) => response.into(),
        Err(error) => error.into(),
    }
}
const DEFAULT_PATHS: &[&str] = &[
    "/sign-up/email",
    "/change-password",
    "/reset-password",
    "/email-otp/reset-password",
    "/phone-number/reset-password",
    "/admin/create-user",
    "/admin/set-user-password",
];

/// HTTP client for the public HIBP range service or a compatible self-hosted mirror.
#[derive(Clone, Debug)]
pub struct PasswordCompromiseClient {
    client: reqwest::Client,
    range_url: String,
}

impl Default for PasswordCompromiseClient {
    fn default() -> Self {
        Self::new(RANGE_URL)
    }
}

impl PasswordCompromiseClient {
    /// Use a range URL to which the five-character prefix is appended.
    pub fn new(range_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            range_url: range_url.into(),
        }
    }

    /// Configure HTTP transport, including proxy and TLS settings.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Check the original password without sending the password or its complete hash.
    pub async fn is_password_compromised(&self, password: &str) -> AuthResult<bool> {
        let hash = hex::encode_upper(Sha1::digest(password.as_bytes()));
        let (prefix, suffix) = hash.split_at(5);
        let response = self
            .client
            .get(format!("{}{prefix}", self.range_url))
            .header("Add-Padding", "true")
            .header("User-Agent", "BetterAuth Password Checker")
            .send()
            .await
            .map_err(|_| check_error(CHECK_FAILED))?;
        if !response.status().is_success() {
            return Err(check_error(format!(
                "Failed to check password. Status: {}",
                response.status().as_u16()
            )));
        }
        if let Some(content_type) = response.headers().get("content-type") {
            let content_type = content_type
                .to_str()
                .map_err(|_| check_error(CHECK_FAILED))?;
            let media_type = content_type.split(';').next().unwrap_or("");
            let lower = media_type.to_ascii_lowercase();
            let json = lower == "application/json"
                || (lower.starts_with("application/") && lower.ends_with("+json"));
            if !json
                && !media_type.starts_with("text/")
                && !matches!(
                    media_type,
                    "image/svg" | "application/xml" | "application/xhtml" | "application/html"
                )
            {
                return Err(check_error(CHECK_FAILED));
            }
        }
        let body = response
            .text()
            .await
            .map_err(|_| check_error(CHECK_FAILED))?;
        let body = match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(serde_json::Value::String(body)) => body,
            Ok(_) => return Err(check_error(CHECK_FAILED)),
            Err(_) => body,
        };
        compromised(&body, suffix).ok_or_else(|| check_error(CHECK_FAILED))
    }
}

/// Check a password against the official HIBP range service.
pub async fn is_password_compromised(password: &str) -> AuthResult<bool> {
    PasswordCompromiseClient::default()
        .is_password_compromised(password)
        .await
}

fn compromised(body: &str, suffix: &str) -> Option<bool> {
    for line in body.lines() {
        let Some((candidate, count)) = line.split_once(':') else {
            continue;
        };
        if !candidate.eq_ignore_ascii_case(suffix) {
            continue;
        }
        let value = count.parse::<u64>().ok()?;
        if value > 9_007_199_254_740_991 || value.to_string() != count {
            return None;
        }
        return Some(value > 0);
    }
    Some(false)
}

/// Options matching Better Auth's haveIBeenPwned plugin.
#[derive(Clone, Debug)]
pub struct HaveIBeenPwnedConfig {
    /// Disable checks while retaining the configured password hasher.
    pub enabled: bool,
    /// Normalized endpoint paths. An empty list disables checks on every endpoint.
    pub paths: Vec<String>,
    /// Replacement rejection message; an empty string uses the default message.
    pub custom_password_compromised_message: Option<String>,
}

impl Default for HaveIBeenPwnedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: DEFAULT_PATHS
                .iter()
                .map(|path| (*path).to_owned())
                .collect(),
            custom_password_compromised_message: None,
        }
    }
}

/// Reject compromised passwords immediately before the configured hasher executes.
#[derive(Clone, Debug, Default)]
pub struct HaveIBeenPwnedPlugin {
    config: HaveIBeenPwnedConfig,
    client: PasswordCompromiseClient,
}

impl HaveIBeenPwnedPlugin {
    /// Enable the default password-writing endpoints.
    pub fn new() -> Self {
        Self::default()
    }

    /// Select the endpoint paths, rejection message, and enabled state.
    pub fn with_config(config: HaveIBeenPwnedConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Use a compatible range service and HTTP client.
    pub fn client(mut self, client: PasswordCompromiseClient) -> Self {
        self.client = client;
        self
    }
}

struct CheckedHasher {
    inner: Arc<dyn PasswordHasher>,
    config: HaveIBeenPwnedConfig,
    client: PasswordCompromiseClient,
    base_path: String,
}

#[async_trait]
impl PasswordHasher for CheckedHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        if self.config.enabled {
            let request = better_auth_core::hooks::current_request_hook_context()
                .ok_or_else(|| AuthError::internal("No auth context found"))?;
            let path = if self.base_path.is_empty() || self.base_path == "/" {
                request.path.as_str()
            } else {
                request
                    .path
                    .strip_prefix(&self.base_path)
                    .unwrap_or(&request.path)
            };
            if !path.is_empty()
                && self
                    .config
                    .paths
                    .iter()
                    .any(|configured| configured == path)
                && self.client.is_password_compromised(password).await?
            {
                return Err(AuthResponse::json(
                    400,
                    &serde_json::json!({
                        "code": "PASSWORD_COMPROMISED",
                        "message": self.config.custom_password_compromised_message.as_deref()
                            .filter(|message| !message.is_empty()).unwrap_or(COMPROMISED),
                    }),
                )?
                .into());
            }
        }
        self.inner.hash(password).await
    }

    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        self.inner.verify(hash, password).await
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for HaveIBeenPwnedPlugin {
    fn name(&self) -> &'static str {
        "have-i-been-pwned"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        ctx.password_policy.hasher = Some(Arc::new(CheckedHasher {
            inner: ctx
                .password_policy
                .hasher
                .clone()
                .unwrap_or_else(|| Arc::new(ScryptPasswordHasher)),
            config: self.config.clone(),
            client: self.client.clone(),
            base_path: ctx.config.base_path.clone(),
        }));
        Ok(())
    }

    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::compromised;

    #[test]
    fn range_count_requires_canonical_safe_integer_and_uses_first_match() {
        assert_eq!(compromised("other:3\r\nABC:0\r\nabc:7", "abc"), Some(false));
        assert_eq!(compromised("abc:9007199254740991", "ABC"), Some(true));
        for count in [
            "",
            "00",
            "01",
            "+1",
            "-1",
            "1.0",
            "1 ",
            "1e3",
            "9007199254740992",
        ] {
            assert_eq!(compromised(&format!("abc:{count}"), "abc"), None, "{count}");
        }
        assert_eq!(compromised("other:invalid", "abc"), Some(false));
    }
}
