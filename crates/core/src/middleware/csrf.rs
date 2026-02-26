use super::Middleware;
use crate::config::glob_match;
use crate::error::AuthResult;
use crate::types::{AuthRequest, AuthResponse, HttpMethod};
use async_trait::async_trait;

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
/// Trusted origins are sourced from the top-level
/// [`AuthConfig::trusted_origins`](crate::config::AuthConfig::trusted_origins)
/// and support glob-pattern matching (e.g. `"https://*.example.com"`).
pub struct CsrfMiddleware {
    config: CsrfConfig,
    /// Base URL of the service (extracted from AuthConfig at construction).
    base_origin: String,
    /// Trusted origins from the top-level AuthConfig.
    trusted_origins: Vec<String>,
}

impl CsrfMiddleware {
    /// Create a new CSRF middleware.
    ///
    /// `trusted_origins` should come from
    /// [`AuthConfig::trusted_origins`](crate::config::AuthConfig::trusted_origins).
    pub fn new(config: CsrfConfig, base_url: &str, trusted_origins: Vec<String>) -> Self {
        let base_origin = extract_origin(base_url).unwrap_or_default();
        Self {
            config,
            base_origin,
            trusted_origins,
        }
    }

    fn is_state_changing(method: &HttpMethod) -> bool {
        matches!(
            method,
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Delete | HttpMethod::Patch
        )
    }

    fn is_origin_trusted(&self, origin: &str) -> bool {
        if origin == self.base_origin {
            return true;
        }
        self.trusted_origins.iter().any(|trusted| {
            let trusted_origin = extract_origin(trusted).unwrap_or_default();
            glob_match(&trusted_origin, origin)
        })
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
            Some(origin) if self.is_origin_trusted(&origin) => Ok(None),
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

/// Extract the origin (scheme + host + port) from a URL string.
fn extract_origin(url: &str) -> Option<String> {
    // Simple parser: find "://" then take up to the next "/"
    let scheme_end = url.find("://")?;
    let rest = &url[scheme_end + 3..];
    let host_end = rest.find('/').unwrap_or(rest.len());
    let origin = format!("{}{}", &url[..scheme_end + 3], &rest[..host_end]);
    Some(origin)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        }
    }

    #[tokio::test]
    async fn test_csrf_allows_same_origin() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), "http://localhost:3000", vec![]);
        let req = make_post(Some("http://localhost:3000"));
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_csrf_blocks_cross_origin() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), "http://localhost:3000", vec![]);
        let req = make_post(Some("http://evil.com"));
        let resp = mw.before_request(&req).await.unwrap();
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status, 403);
    }

    #[tokio::test]
    async fn test_csrf_allows_trusted_origin() {
        let mw = CsrfMiddleware::new(
            CsrfConfig::new(),
            "http://localhost:3000",
            vec!["https://myapp.com".to_string()],
        );
        let req = make_post(Some("https://myapp.com"));
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_csrf_allows_glob_trusted_origin() {
        let mw = CsrfMiddleware::new(
            CsrfConfig::new(),
            "http://localhost:3000",
            vec!["https://*.example.com".to_string()],
        );
        let req = make_post(Some("https://app.example.com"));
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_csrf_skips_get_requests() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), "http://localhost:3000", vec![]);
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
        };
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_csrf_allows_no_origin_header() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), "http://localhost:3000", vec![]);
        let req = make_post(None);
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_csrf_disabled() {
        let config = CsrfConfig::new().enabled(false);
        let mw = CsrfMiddleware::new(config, "http://localhost:3000", vec![]);
        let req = make_post(Some("http://evil.com"));
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }
}
