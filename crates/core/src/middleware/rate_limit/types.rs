use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use indexmap::IndexMap;

use crate::{AuthRequest, AuthResult};

/// Upstream windows use seconds and accept fractional numeric values.
#[derive(Debug, Clone, Copy)]
pub struct EndpointRateLimit {
    pub window: f64,
    pub max_requests: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub retry_after: Option<f64>,
}

/// Consume one request atomically, including the decision and counter update.
#[async_trait]
pub trait RateLimitStorage: Send + Sync {
    async fn consume(&self, key: &str, rule: EndpointRateLimit) -> AuthResult<RateLimitDecision>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitStorageKind {
    Memory,
    Database,
    Secondary,
}

#[derive(Debug, Clone, Copy)]
pub enum RateLimitOverride {
    Unchanged,
    Disabled,
    Limit(EndpointRateLimit),
}

#[async_trait]
pub trait RateLimitRuleResolver: Send + Sync {
    async fn resolve(
        &self,
        request: &AuthRequest,
        current: EndpointRateLimit,
    ) -> AuthResult<RateLimitOverride>;
}

#[derive(Clone)]
pub enum CustomRateLimitRule {
    Fixed(RateLimitOverride),
    Dynamic(Arc<dyn RateLimitRuleResolver>),
}

impl From<EndpointRateLimit> for CustomRateLimitRule {
    fn from(rule: EndpointRateLimit) -> Self {
        Self::Fixed(RateLimitOverride::Limit(rule))
    }
}

impl From<RateLimitOverride> for CustomRateLimitRule {
    fn from(rule: RateLimitOverride) -> Self {
        Self::Fixed(rule)
    }
}

impl std::fmt::Debug for CustomRateLimitRule {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fixed(rule) => rule.fmt(formatter),
            Self::Dynamic(_) => formatter.write_str("Dynamic(<resolver>)"),
        }
    }
}

type PathMatcher = dyn Fn(&str) -> AuthResult<bool> + Send + Sync;

#[derive(Clone)]
pub struct PluginRateLimit {
    pub limit: EndpointRateLimit,
    matcher: Arc<PathMatcher>,
}

impl PluginRateLimit {
    pub fn new(
        limit: EndpointRateLimit,
        matcher: impl Fn(&str) -> AuthResult<bool> + Send + Sync + 'static,
    ) -> Self {
        Self {
            limit,
            matcher: Arc::new(matcher),
        }
    }

    pub fn exact(path: impl Into<String>, limit: EndpointRateLimit) -> Self {
        let path = path.into();
        Self::new(limit, move |candidate| Ok(candidate == path))
    }

    pub fn prefix(path: impl Into<String>, limit: EndpointRateLimit) -> Self {
        let path = path.into();
        Self::new(limit, move |candidate| Ok(candidate.starts_with(&path)))
    }

    pub(super) fn matches(&self, path: &str) -> AuthResult<bool> {
        (self.matcher)(path)
    }
}

/// Rules retain insertion order. The first matching rule takes precedence.
#[derive(Clone)]
pub struct RateLimitConfig {
    pub default: EndpointRateLimit,
    pub custom_rules: IndexMap<String, CustomRateLimitRule>,
    pub enabled: bool,
    /// Omission selects secondary storage when configured, otherwise process memory.
    pub storage: Option<RateLimitStorageKind>,
    /// Custom storage takes precedence over the selected built-in backend.
    pub custom_storage: Option<Arc<dyn RateLimitStorage>>,
}

impl std::fmt::Debug for RateLimitConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RateLimitConfig")
            .field("default", &self.default)
            .field("custom_rules", &self.custom_rules)
            .field("enabled", &self.enabled)
            .field("storage", &self.storage)
            .field(
                "custom_storage",
                &self.custom_storage.as_ref().map(|_| "<storage>"),
            )
            .finish()
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default: EndpointRateLimit {
                window: 10.0,
                max_requests: 100.0,
            },
            custom_rules: IndexMap::new(),
            enabled: std::env::var("NODE_ENV").is_ok_and(|value| value == "production"),
            storage: None,
            custom_storage: None,
        }
    }
}

impl RateLimitConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn default_limit(mut self, window: Duration, max_requests: impl Into<f64>) -> Self {
        self.default = EndpointRateLimit {
            window: window.as_secs_f64(),
            max_requests: max_requests.into(),
        };
        self
    }

    pub fn endpoint(
        self,
        path: impl Into<String>,
        window: Duration,
        max_requests: impl Into<f64>,
    ) -> Self {
        self.rule(
            path,
            EndpointRateLimit {
                window: window.as_secs_f64(),
                max_requests: max_requests.into(),
            },
        )
    }

    pub fn rule(mut self, path: impl Into<String>, rule: impl Into<CustomRateLimitRule>) -> Self {
        let _ = self.custom_rules.insert(path.into(), rule.into());
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn storage(mut self, storage: RateLimitStorageKind) -> Self {
        self.storage = Some(storage);
        self
    }

    pub fn custom_storage(mut self, storage: Arc<dyn RateLimitStorage>) -> Self {
        self.custom_storage = Some(storage);
        self
    }
}
