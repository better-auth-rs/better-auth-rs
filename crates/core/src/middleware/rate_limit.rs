use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use async_trait::async_trait;

use super::Middleware;
use crate::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema};

mod memory;
mod types;
pub use types::*;

static IP_WARNING_LOGGED: AtomicBool = AtomicBool::new(false);

pub struct RateLimitMiddleware {
    config: RateLimitConfig,
    default_rule: EndpointRateLimit,
    enabled: bool,
    ip_address: crate::config::IpAddressConfig,
    base_path: Box<dyn Fn() -> String + Send + Sync>,
    plugin_limits: Vec<PluginRateLimit>,
    storage: Option<Arc<dyn RateLimitStorage>>,
}

impl RateLimitMiddleware {
    pub fn new(config: RateLimitConfig) -> Self {
        let default_rule = config.default_rule();
        let enabled = config
            .enabled
            .unwrap_or_else(|| std::env::var("NODE_ENV").is_ok_and(|value| value == "production"));
        let storage = config.custom_storage.clone().or_else(|| {
            matches!(config.storage, None | Some(RateLimitStorageKind::Memory))
                .then(|| Arc::new(memory::MemoryRateLimitStorage) as Arc<dyn RateLimitStorage>)
        });
        Self {
            config,
            default_rule,
            enabled,
            ip_address: Default::default(),
            base_path: Box::new(String::new),
            plugin_limits: Vec::new(),
            storage,
        }
    }

    pub fn from_context<S: AuthSchema>(
        config: RateLimitConfig,
        context: &AuthContext<S>,
        plugin_limits: Vec<PluginRateLimit>,
    ) -> Self {
        let mut limiter = Self::new(config);
        limiter.ip_address = context.config.advanced.ip_address.clone();
        let identity = context.runtime_identity();
        let base_path = context.base_path().to_owned();
        limiter.base_path = Box::new(move || {
            identity.current::<S>().map_or_else(
                || base_path.clone(),
                |context| context.base_path().to_owned(),
            )
        });
        limiter.plugin_limits = plugin_limits;
        if limiter.config.custom_storage.is_none() {
            let kind = limiter.config.storage.unwrap_or_else(|| {
                if context.secondary_storage.is_some() {
                    RateLimitStorageKind::Secondary
                } else {
                    RateLimitStorageKind::Memory
                }
            });
            limiter.storage = Some(match kind {
                RateLimitStorageKind::Memory => Arc::new(memory::MemoryRateLimitStorage),
                RateLimitStorageKind::Secondary => Arc::new(SecondaryRateLimitStorage {
                    storage: context.secondary_storage.clone(),
                }),
                RateLimitStorageKind::Database => Arc::new(DatabaseRateLimitStorage {
                    store: context.database.clone(),
                    cleanup_window: limiter.configured_window(),
                }),
            });
        }
        limiter
    }

    pub fn ip_address_config(mut self, config: crate::config::IpAddressConfig) -> Self {
        self.ip_address = config;
        self
    }

    fn configured_window(&self) -> f64 {
        std::iter::once(self.default_rule.window)
            .chain(self.plugin_limits.iter().map(|rule| rule.limit.window))
            .chain(
                self.config
                    .custom_rules
                    .values()
                    .filter_map(|rule| match rule {
                        CustomRateLimitRule::Fixed(RateLimitOverride::Limit(rule)) => {
                            Some(rule.window)
                        }
                        _ => None,
                    }),
            )
            .filter(|window| window.is_finite() && *window > 0.0)
            .fold(60.0, f64::max)
    }

    async fn resolve(
        &self,
        request: &AuthRequest,
        path: &str,
    ) -> AuthResult<Option<EndpointRateLimit>> {
        let mut rule = self.default_rule;
        if ["/sign-in", "/sign-up", "/change-password", "/change-email"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
        {
            rule = EndpointRateLimit {
                window: 10.0,
                max_requests: 3.0,
            };
        } else if matches!(
            path,
            "/request-password-reset"
                | "/send-verification-email"
                | "/email-otp/send-verification-otp"
                | "/email-otp/request-password-reset"
        ) || path.starts_with("/forget-password")
        {
            rule = EndpointRateLimit {
                window: 60.0,
                max_requests: 3.0,
            };
        }
        for plugin in &self.plugin_limits {
            if plugin.matches(path)? {
                rule = plugin.limit;
                break;
            }
        }
        for (pattern, custom) in &self.config.custom_rules {
            if !crate::utils::path::matches(pattern, path)? {
                continue;
            }
            let resolved = match custom {
                CustomRateLimitRule::Fixed(rule) => *rule,
                CustomRateLimitRule::Dynamic(resolver) => resolver.resolve(request, rule).await?,
            };
            match resolved {
                RateLimitOverride::Unchanged => {}
                RateLimitOverride::Disabled => return Ok(None),
                RateLimitOverride::Limit(replacement) => rule = replacement,
            }
            break;
        }
        Ok(Some(rule))
    }
}

#[async_trait]
impl Middleware for RateLimitMiddleware {
    fn name(&self) -> &'static str {
        "rate-limit"
    }

    async fn before_request(&self, request: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        if !self.enabled || self.ip_address.disable_ip_tracking() {
            return Ok(None);
        }
        let path = request.url().map_or(request.path(), |url| url.path());
        let base_path = (self.base_path)();
        let path = normalize_path(path, &base_path);
        let ip = self.ip_address.resolve(request);
        if ip.is_none() && !IP_WARNING_LOGGED.swap(true, Ordering::Relaxed) {
            crate::observability::logger::current().warn("Rate limiting could not determine a client IP; requests share one per-path bucket. Configure trusted client IP headers or proxies.", &[]);
        }
        let Some(rule) = self.resolve(request, path).await? else {
            return Ok(None);
        };
        let key = format!("{}|{path}", ip.as_deref().unwrap_or("no-trusted-ip"));
        let storage = self.storage.as_ref().ok_or_else(|| {
            AuthError::config(
                "Configure database or secondary rate limiting through the BetterAuth builder",
            )
        })?;
        let decision = storage.consume(&key, rule).await?;
        if decision.allowed {
            return Ok(None);
        }
        Ok(Some(
            AuthResponse::json(
                429,
                &crate::types::ErrorCodeMessageResponse {
                    code: None,
                    message: "Too many requests. Please try again later.".to_owned(),
                },
            )?
            .with_header("content-type", "text/plain;charset=utf-8")
            .with_header(
                "X-Retry-After",
                crate::schema_value::number_string(decision.retry_after.unwrap_or(rule.window)),
            ),
        ))
    }
}

fn normalize_path<'a>(path: &'a str, base_path: &str) -> &'a str {
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or("/")
        .trim_end_matches('/');
    let base = base_path.trim_end_matches('/');
    let path = if path == base {
        "/"
    } else if let Some(suffix) = path
        .strip_prefix(base)
        .filter(|suffix| suffix.starts_with('/'))
    {
        suffix
    } else {
        path
    };
    if path.is_empty() { "/" } else { path }
}

struct SecondaryRateLimitStorage {
    storage: Option<Arc<dyn crate::store::SecondaryStorage>>,
}

#[async_trait]
impl RateLimitStorage for SecondaryRateLimitStorage {
    async fn consume(&self, key: &str, rule: EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        let storage = self.storage.as_ref().ok_or_else(|| {
            AuthError::config(
                "Secondary-storage rate limiting requires SecondaryStorage.increment.",
            )
        })?;
        let allowed = storage.increment(key, rule.window).await? <= rule.max_requests;
        Ok(RateLimitDecision {
            allowed,
            retry_after: (!allowed).then_some(rule.window),
        })
    }
}

struct DatabaseRateLimitStorage<S: AuthSchema> {
    store: Arc<dyn crate::store::AuthStore<S>>,
    cleanup_window: f64,
}

#[async_trait]
impl<S: AuthSchema> RateLimitStorage for DatabaseRateLimitStorage<S> {
    async fn consume(&self, key: &str, rule: EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        let cleanup_window = if rule.window > self.cleanup_window {
            rule.window
        } else {
            self.cleanup_window
        };
        self.store
            .consume_rate_limit(key, rule, cleanup_window)
            .await
    }
}

#[cfg(test)]
mod tests;
