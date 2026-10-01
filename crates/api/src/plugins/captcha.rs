//! CAPTCHA verification before endpoint parsing, authentication, and application hooks.

mod path;

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, user_fields::is_truthy,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_ENDPOINTS: &[&str] = &[
    "/sign-up/email",
    "/sign-in/email",
    "/request-password-reset",
];

/// A BotID verdict supplied by the application's Vercel integration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BotIdVerification {
    pub is_bot: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_verified_bot: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_bot_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_bot_category: Option<String>,
}

/// Call the application's BotID SDK for the current request.
#[async_trait]
pub trait BotIdChecker: Send + Sync {
    async fn check(&self) -> AuthResult<BotIdVerification>;
}

/// Override the default decision that only `is_bot == false` is accepted.
#[async_trait]
pub trait BotIdRequestValidator: Send + Sync {
    async fn validate(
        &self,
        request: &AuthRequest,
        verification: &BotIdVerification,
    ) -> AuthResult<bool>;
}

/// Provider-specific options. Secrets are never included in plugin diagnostics.
#[derive(Clone)]
pub enum CaptchaProvider {
    CloudflareTurnstile {
        secret_key: String,
        expected_action: Option<String>,
        allowed_hostnames: Vec<String>,
    },
    GoogleRecaptcha {
        secret_key: String,
        min_score: f64,
        expected_action: Option<String>,
        allowed_hostnames: Vec<String>,
    },
    HCaptcha {
        secret_key: String,
        site_key: Option<String>,
    },
    CaptchaFox {
        secret_key: String,
        site_key: Option<String>,
    },
    VercelBotId {
        check_bot_id: Arc<dyn BotIdChecker>,
        validate_request: Option<Arc<dyn BotIdRequestValidator>>,
    },
}

impl CaptchaProvider {
    pub fn cloudflare_turnstile(secret_key: impl Into<String>) -> Self {
        Self::CloudflareTurnstile {
            secret_key: secret_key.into(),
            expected_action: None,
            allowed_hostnames: Vec::new(),
        }
    }
    pub fn google_recaptcha(secret_key: impl Into<String>) -> Self {
        Self::GoogleRecaptcha {
            secret_key: secret_key.into(),
            min_score: 0.5,
            expected_action: None,
            allowed_hostnames: Vec::new(),
        }
    }
    pub fn hcaptcha(secret_key: impl Into<String>) -> Self {
        Self::HCaptcha {
            secret_key: secret_key.into(),
            site_key: None,
        }
    }
    pub fn captchafox(secret_key: impl Into<String>) -> Self {
        Self::CaptchaFox {
            secret_key: secret_key.into(),
            site_key: None,
        }
    }
    pub fn vercel_bot_id(check_bot_id: Arc<dyn BotIdChecker>) -> Self {
        Self::VercelBotId {
            check_bot_id,
            validate_request: None,
        }
    }

    fn token_settings(&self) -> Option<(&str, &str, Option<&str>)> {
        match self {
            Self::CloudflareTurnstile { secret_key, .. } => Some((
                secret_key,
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                None,
            )),
            Self::GoogleRecaptcha { secret_key, .. } => Some((
                secret_key,
                "https://www.google.com/recaptcha/api/siteverify",
                None,
            )),
            Self::HCaptcha {
                secret_key,
                site_key,
            } => Some((
                secret_key,
                "https://api.hcaptcha.com/siteverify",
                site_key.as_deref(),
            )),
            Self::CaptchaFox {
                secret_key,
                site_key,
            } => Some((
                secret_key,
                "https://api.captchafox.com/siteverify",
                site_key.as_deref(),
            )),
            Self::VercelBotId { .. } => None,
        }
    }
}

/// Protect HTTP authentication endpoints. Native API calls bypass this plugin.
#[derive(Clone)]
pub struct CaptchaPlugin {
    provider: CaptchaProvider,
    endpoints: Vec<String>,
    site_verify_url_override: Option<String>,
    client: reqwest::Client,
}

impl CaptchaPlugin {
    pub fn new(provider: CaptchaProvider) -> Self {
        Self {
            provider,
            endpoints: Vec::new(),
            site_verify_url_override: None,
            client: reqwest::Client::new(),
        }
    }

    /// Protect exact paths or wildcard patterns. An empty list selects the upstream defaults.
    pub fn endpoints(mut self, endpoints: Vec<String>) -> Self {
        self.endpoints = endpoints;
        self
    }

    /// Use a provider-compatible verification service. An empty URL selects the provider default.
    pub fn site_verify_url_override(mut self, url: impl Into<String>) -> Self {
        self.site_verify_url_override = Some(url.into());
        self
    }

    async fn verify(
        &self,
        request: &AuthRequest,
        ip: Option<String>,
    ) -> AuthResult<Option<AuthResponse>> {
        if let CaptchaProvider::VercelBotId {
            check_bot_id,
            validate_request,
        } = &self.provider
        {
            let checker = check_bot_id.clone();
            let validator = validate_request.clone();
            let request = request.clone();
            let hook_context = better_auth_core::hooks::current_request_hook_context();
            // Promise.race does not cancel the application callback when its deadline expires.
            let task = tokio::spawn(async move {
                let verify = async {
                    let verdict = checker.check().await?;
                    match validator {
                        Some(validator) => validator.validate(&request, &verdict).await,
                        None => Ok(!verdict.is_bot),
                    }
                };
                match hook_context {
                    Some(context) => {
                        better_auth_core::hooks::with_request_hook_context_value(context, verify)
                            .await
                    }
                    None => verify.await,
                }
            });
            let valid = tokio::time::timeout(TIMEOUT, task)
                .await
                .map_err(|_| AuthError::internal("CAPTCHA verification timed out"))?
                .map_err(|_| AuthError::internal("CAPTCHA callback failed"))??;
            return if valid {
                Ok(None)
            } else {
                failure(403, "VERIFICATION_FAILED", "Captcha verification failed").map(Some)
            };
        }
        let (secret, default_url, site_key) = self
            .provider
            .token_settings()
            .ok_or_else(|| AuthError::internal("Missing CAPTCHA provider"))?;
        if secret.is_empty() {
            return Err(AuthError::internal("Missing CAPTCHA secret key"));
        }
        let response = request
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("x-captcha-response"))
            .map(|(_, value)| value.as_str())
            .filter(|value| !value.is_empty());
        let Some(response) = response else {
            return failure(400, "MISSING_RESPONSE", "Missing CAPTCHA response").map(Some);
        };
        let url = self
            .site_verify_url_override
            .as_deref()
            .filter(|url| !url.is_empty())
            .unwrap_or(default_url);
        let mut body = vec![("secret", secret), ("response", response)];
        if let Some(site_key) = site_key.filter(|value| !value.is_empty()) {
            body.push(("sitekey", site_key));
        }
        if let Some(ip) = ip.as_deref() {
            body.push((
                if matches!(self.provider, CaptchaProvider::CaptchaFox { .. }) {
                    "remoteIp"
                } else {
                    "remoteip"
                },
                ip,
            ));
        }
        let post = self.client.post(url);
        let post = if matches!(self.provider, CaptchaProvider::CloudflareTurnstile { .. }) {
            post.json(
                &body
                    .into_iter()
                    .collect::<std::collections::BTreeMap<_, _>>(),
            )
        } else {
            post.form(&body)
        };
        // better-fetch clears its timer after fetch resolves, before reading the response body.
        let response = tokio::time::timeout(TIMEOUT, post.send())
            .await
            .map_err(|_| AuthError::internal("CAPTCHA verification timed out"))?
            .map_err(|_| AuthError::internal("CAPTCHA service unavailable"))?;
        if !response.status().is_success() {
            return Err(AuthError::internal("CAPTCHA service unavailable"));
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|header| header.to_str().ok())
            .unwrap_or("");
        let media_type = content_type.split(';').next().unwrap_or("");
        let is_text = content_type.is_empty()
            || media_type.starts_with("text/")
            || matches!(
                media_type,
                "image/svg" | "application/xml" | "application/xhtml" | "application/html"
            )
            || media_type
                .to_ascii_lowercase()
                .strip_prefix("application/")
                .is_some_and(|subtype| subtype == "json" || subtype.ends_with("+json"));
        let text = response
            .text()
            .await
            .map_err(|_| AuthError::internal("CAPTCHA response read failed"))?;
        if !is_text {
            return failure(403, "VERIFICATION_FAILED", "Captcha verification failed").map(Some);
        }
        // better-fetch keeps non-JSON text as a string; a nonempty string fails verification.
        let data: Value = serde_json::from_str(&text).unwrap_or_else(|_| Value::String(text));
        if !is_truthy(&data) {
            return Err(AuthError::internal("CAPTCHA service unavailable"));
        }
        let mut valid = data.get("success").is_some_and(is_truthy);
        if let CaptchaProvider::GoogleRecaptcha { min_score, .. } = &self.provider
            && data
                .get("score")
                .and_then(Value::as_f64)
                .is_some_and(|score| score < *min_score)
        {
            valid = false;
        }
        if let CaptchaProvider::CloudflareTurnstile {
            expected_action,
            allowed_hostnames,
            ..
        }
        | CaptchaProvider::GoogleRecaptcha {
            expected_action,
            allowed_hostnames,
            ..
        } = &self.provider
        {
            if let Some(action) = expected_action
                .as_deref()
                .filter(|action| !action.is_empty())
                && data.get("action").and_then(Value::as_str) != Some(action)
            {
                valid = false;
            }
            if !allowed_hostnames.is_empty()
                && !data
                    .get("hostname")
                    .and_then(Value::as_str)
                    .is_some_and(|hostname| {
                        allowed_hostnames.iter().any(|allowed| allowed == hostname)
                    })
            {
                valid = false;
            }
        }
        if valid {
            Ok(None)
        } else {
            failure(403, "VERIFICATION_FAILED", "Captcha verification failed").map(Some)
        }
    }
}

fn failure(status: u16, code: &str, message: &str) -> AuthResult<AuthResponse> {
    Ok(
        AuthResponse::json(status, &json!({ "message": message, "code": code }))?
            .with_header("content-type", "text/plain;charset=UTF-8"),
    )
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for CaptchaPlugin {
    fn name(&self) -> &'static str {
        "captcha"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_http_request(
        &self,
        request: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let pathname = request.url().map_or(request.path(), |url| url.path());
        let path = path::normalize(pathname, &ctx.config.base_path);
        let endpoints: Vec<&str> = if self.endpoints.is_empty() {
            DEFAULT_ENDPOINTS.to_vec()
        } else {
            self.endpoints.iter().map(String::as_str).collect()
        };
        let result = async {
            for endpoint in endpoints {
                if path::matches(endpoint, &path)? {
                    return self
                        .verify(request, ctx.config.advanced.ip_address.resolve(request))
                        .await;
                }
            }
            Ok(None)
        }
        .await;
        match result {
            Ok(response) => Ok(response),
            Err(_) => {
                better_auth_core::observability::logger::current()
                    .error("CAPTCHA verification service or callback failed", &[]);
                failure(500, "UNKNOWN_ERROR", "Something went wrong").map(Some)
            }
        }
    }
    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}
