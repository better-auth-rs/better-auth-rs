use super::Middleware;
use crate::config::{AuthConfig, extract_origin};
use crate::error::AuthResult;
use crate::types::{AuthRequest, AuthResponse, HttpMethod};
use async_trait::async_trait;
use std::sync::Arc;

/// Configuration for CSRF protection middleware.
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// Whether CSRF protection is enabled. Defaults to `true`.
    pub enabled: bool,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl CsrfConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// CSRF protection middleware.
///
/// Validates `Origin` / `Referer` headers on state-changing requests
/// (POST, PUT, DELETE, PATCH) against the configured trusted origins
/// and the service's own base URL.
///
/// Origin checking is delegated to [`AuthConfig::is_origin_trusted`] so
/// that all origin-validation logic lives in a single place.
pub struct CsrfMiddleware {
    config: CsrfConfig,
    /// Shared auth configuration used for origin trust checks.
    auth_config: Arc<AuthConfig>,
}

impl CsrfMiddleware {
    /// Create a new CSRF middleware.
    ///
    /// Origin trust decisions are delegated to `auth_config`.
    pub fn new(config: CsrfConfig, auth_config: Arc<AuthConfig>) -> Self {
        Self {
            config,
            auth_config,
        }
    }

    fn is_state_changing(method: &HttpMethod) -> bool {
        matches!(
            method,
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Delete | HttpMethod::Patch
        )
    }
}

#[async_trait]
impl Middleware for CsrfMiddleware {
    fn name(&self) -> &'static str {
        "csrf"
    }

    async fn before_request(&self, req: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        if !self.config.enabled {
            return Ok(None);
        }

        // Only check state-changing methods
        if !Self::is_state_changing(&req.method) {
            return Ok(None);
        }

        // Check Origin header first, then Referer
        let request_origin = req
            .headers
            .get("origin")
            .cloned()
            .or_else(|| req.headers.get("referer").and_then(|r| extract_origin(r)));

        match request_origin {
            Some(origin) if self.auth_config.is_origin_trusted(&origin) => Ok(None),
            Some(_origin) => Ok(Some(AuthResponse::json(
                403,
                &crate::types::CodeMessageResponse {
                    code: "CSRF_ERROR",
                    message: "Cross-site request blocked".to_string(),
                },
            )?)),
            // If no Origin/Referer header is present, allow the request.
            // This handles same-origin requests from older browsers and
            // non-browser clients (curl, SDKs, etc.).
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::extract_origin;
    use std::collections::HashMap;

    fn make_post(origin: Option<&str>) -> AuthRequest {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        if let Some(o) = origin {
            headers.insert("origin".to_string(), o.to_string());
        }
        AuthRequest {
            method: HttpMethod::Post,
            path: "/sign-in/email".to_string(),
            headers,
            body: None,
            query: HashMap::new(),
            virtual_user_id: None,
        }
    }

    fn test_auth_config(trusted_origins: Vec<String>) -> Arc<AuthConfig> {
        Arc::new(
            AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
                .base_url("http://localhost:3000")
                .trusted_origins(trusted_origins),
        )
    }

    #[tokio::test]
    async fn test_csrf_allows_same_origin() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let req = make_post(Some("http://localhost:3000"));
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_csrf_blocks_cross_origin() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let req = make_post(Some("http://evil.com"));
        let resp = mw.before_request(&req).await.unwrap();
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status, 403);
    }

    #[tokio::test]
    async fn test_csrf_allows_trusted_origin() {
        let mw = CsrfMiddleware::new(
            CsrfConfig::new(),
            test_auth_config(vec!["https://myapp.com".to_string()]),
        );
        let req = make_post(Some("https://myapp.com"));
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_csrf_allows_glob_trusted_origin() {
        let mw = CsrfMiddleware::new(
            CsrfConfig::new(),
            test_auth_config(vec!["https://*.example.com".to_string()]),
        );
        let req = make_post(Some("https://app.example.com"));
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_csrf_skips_get_requests() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let req = AuthRequest {
            method: HttpMethod::Get,
            path: "/get-session".to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert("origin".to_string(), "http://evil.com".to_string());
                h
            },
            body: None,
            query: HashMap::new(),
            virtual_user_id: None,
        };
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_csrf_allows_no_origin_header() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let req = make_post(None);
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_csrf_disabled() {
        let config = CsrfConfig::new().enabled(false);
        let mw = CsrfMiddleware::new(config, test_auth_config(vec![]));
        let req = make_post(Some("http://evil.com"));
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[test]
    fn test_extract_origin() {
        assert_eq!(
            extract_origin("https://example.com/path"),
            Some("https://example.com".to_string())
        );
        assert_eq!(
            extract_origin("http://localhost:3000"),
            Some("http://localhost:3000".to_string())
        );
        assert_eq!(extract_origin("not-a-url"), None);
    }
}
