use super::Middleware;
use crate::error::AuthResult;
use crate::types::{AuthRequest, AuthResponse};
use async_trait::async_trait;

/// Configuration for body size limit middleware.
#[derive(Debug, Clone)]
pub struct BodyLimitConfig {
    /// Maximum body size in bytes. Defaults to 1 MB.
    pub max_bytes: usize,

    /// Whether the middleware is enabled.
    pub enabled: bool,
}

impl Default for BodyLimitConfig {
    fn default() -> Self {
        Self {
            max_bytes: 1_048_576, // 1 MB
            enabled: true,
        }
    }
}

impl BodyLimitConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn max_bytes(mut self, max: usize) -> Self {
        self.max_bytes = max;
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Body size limit middleware.
///
/// Rejects requests whose body exceeds the configured maximum size.
pub struct BodyLimitMiddleware {
    config: BodyLimitConfig,
}

impl BodyLimitMiddleware {
    pub fn new(config: BodyLimitConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Middleware for BodyLimitMiddleware {
    fn name(&self) -> &'static str {
        "body-limit"
    }

    async fn before_request(&self, req: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        if !self.config.enabled {
            return Ok(None);
        }

        if let Some(body) = &req.body
            && body.len() > self.config.max_bytes
        {
            return Ok(Some(AuthResponse::json(
                413,
                &serde_json::json!({
                    "code": "BODY_TOO_LARGE",
                    "message": format!(
                        "Request body exceeds maximum size of {} bytes",
                        self.config.max_bytes
                    ),
                }),
            )?));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HttpMethod;
    use std::collections::HashMap;

    fn make_request_with_body(body_size: usize) -> AuthRequest {
        AuthRequest {
            method: HttpMethod::Post,
            path: "/sign-up/email".to_string(),
            headers: HashMap::new(),
            body: Some(vec![0u8; body_size]),
            query: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_body_limit_allows_within_limit() {
        let mw = BodyLimitMiddleware::new(BodyLimitConfig::new().max_bytes(1024));
        let req = make_request_with_body(512);
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_body_limit_allows_exact_limit() {
        let mw = BodyLimitMiddleware::new(BodyLimitConfig::new().max_bytes(1024));
        let req = make_request_with_body(1024);
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_body_limit_rejects_over_limit() {
        let mw = BodyLimitMiddleware::new(BodyLimitConfig::new().max_bytes(1024));
        let req = make_request_with_body(2048);
        let resp = mw.before_request(&req).await.unwrap();
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status, 413);
    }

    #[tokio::test]
    async fn test_body_limit_allows_no_body() {
        let mw = BodyLimitMiddleware::new(BodyLimitConfig::new().max_bytes(1024));
        let req = AuthRequest {
            method: HttpMethod::Get,
            path: "/get-session".to_string(),
            headers: HashMap::new(),
            body: None,
            query: HashMap::new(),
        };
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_body_limit_disabled() {
        let config = BodyLimitConfig::new().max_bytes(10).enabled(false);
        let mw = BodyLimitMiddleware::new(config);
        let req = make_request_with_body(1000);
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }
}
