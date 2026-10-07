use super::Middleware;
use crate::config::{AuthConfig, extract_origin};
use crate::error::{AuthError, AuthResult};
use crate::types::{AuthRequest, AuthResponse, HttpMethod};
use async_trait::async_trait;
use serde_json::{Map, Value};
#[cfg(test)]
use std::collections::HashMap;
use std::sync::Arc;

const CROSS_SITE_NAVIGATION_LOGIN_BLOCKED: &str =
    "Cross-site navigation login blocked. This request appears to be a CSRF attack.";
const INVALID_CALLBACK_URL: &str = "Invalid callbackURL";
const INVALID_ERROR_CALLBACK_URL: &str = "Invalid errorCallbackURL";
const INVALID_NEW_USER_CALLBACK_URL: &str = "Invalid newUserCallbackURL";
const INVALID_REDIRECT_URL: &str = "Invalid redirectURL";
const INVALID_ORIGIN: &str = "Invalid origin";
const MISSING_OR_NULL_ORIGIN: &str = "Missing or null Origin";

/// Configuration for Better Auth request-origin and CSRF protection.
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// Whether the request protection middleware is enabled. Defaults to `true`.
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

/// Better Auth request protection middleware.
///
/// This mirrors the upstream TypeScript behavior:
/// - mutating requests with cookies require a trusted `Origin` / `Referer`
/// - first-login `POST /sign-up/email` and `POST /sign-in/email` also use
///   Fetch Metadata headers to block cross-site navigation attacks
/// - callback / redirect targets are validated against trusted origins unless
///   `advanced.disable_origin_check` is set
pub struct CsrfMiddleware {
    config: CsrfConfig,
    auth_config: Arc<AuthConfig>,
    trusted_origins: Option<Vec<String>>,
}

impl CsrfMiddleware {
    pub fn new(config: CsrfConfig, auth_config: Arc<AuthConfig>) -> Self {
        Self {
            config,
            auth_config,
            trusted_origins: None,
        }
    }

    pub fn from_context<S: crate::AuthSchema>(
        config: CsrfConfig,
        context: &crate::AuthContext<S>,
    ) -> Self {
        Self {
            config,
            auth_config: context.config.clone(),
            trusted_origins: Some(context.trusted_origins().to_vec()),
        }
    }

    fn is_origin_trusted(&self, origin: &str) -> bool {
        match &self.trusted_origins {
            Some(values) => values.iter().any(|pattern| {
                glob_match::glob_match(&extract_origin(pattern).unwrap_or_default(), origin)
            }),
            None => self.auth_config.is_origin_trusted(origin),
        }
    }

    fn is_state_changing(method: &HttpMethod) -> bool {
        matches!(
            method,
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Delete | HttpMethod::Patch
        )
    }

    fn header<'a>(req: &'a AuthRequest, name: &str) -> Option<&'a str> {
        req.headers
            .iter()
            .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
    }

    fn has_cookies(req: &AuthRequest) -> bool {
        Self::header(req, "cookie").is_some()
    }

    fn has_fetch_metadata(req: &AuthRequest) -> bool {
        ["sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"]
            .into_iter()
            .any(|name| Self::header(req, name).is_some_and(|value| !value.trim().is_empty()))
    }

    async fn validate_origin(
        &self,
        req: &AuthRequest,
        force_validate: bool,
    ) -> Result<(), AuthError> {
        if self.auth_config.advanced.csrf_check_disabled()
            || self.auth_config.advanced.disable_origin_check
        {
            return Ok(());
        }

        if !force_validate && !Self::has_cookies(req) {
            return Ok(());
        }

        let inferred_origin = (Self::header(req, "origin") == Some("null")
            && Self::header(req, "sec-fetch-site") == Some("same-origin"))
        .then(|| req.url().map(|url| url.origin().ascii_serialization()))
        .flatten();
        let origin = inferred_origin
            .or_else(|| {
                Self::header(req, "origin")
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .or_else(|| Self::header(req, "referer").and_then(extract_origin))
            })
            .filter(|value| value != "null")
            .ok_or_else(|| AuthError::forbidden(MISSING_OR_NULL_ORIGIN))?;

        let trusted = if self.auth_config.trusted_origin_values().is_dynamic() {
            let mut origins = self.trusted_origins.clone().unwrap_or_default();
            origins.extend(
                self.auth_config
                    .trusted_origin_values()
                    .resolve(Some(req))
                    .await?,
            );
            origins.iter().any(|pattern| {
                glob_match::glob_match(&extract_origin(pattern).unwrap_or_default(), &origin)
            })
        } else {
            self.is_origin_trusted(&origin)
        };
        if trusted {
            Ok(())
        } else {
            Err(AuthError::forbidden(INVALID_ORIGIN))
        }
    }

    /// Validate a login form after the endpoint's input schema has passed.
    pub async fn validate_form_request(&self, req: &AuthRequest) -> Result<(), AuthError> {
        if !self.config.enabled || self.auth_config.advanced.csrf_check_disabled() {
            return Ok(());
        }

        if Self::has_cookies(req) {
            return self.validate_origin(req, false).await;
        }

        if Self::has_fetch_metadata(req) {
            let is_cross_site_navigation = matches!(
                (
                    Self::header(req, "sec-fetch-site"),
                    Self::header(req, "sec-fetch-mode"),
                ),
                (Some("cross-site"), Some("navigate"))
            );

            if is_cross_site_navigation {
                return Err(AuthError::forbidden(CROSS_SITE_NAVIGATION_LOGIN_BLOCKED));
            }

            return self.validate_origin(req, true).await;
        }

        if ["origin", "referer"]
            .into_iter()
            .any(|name| Self::header(req, name).is_some_and(|value| !value.is_empty()))
        {
            return self.validate_origin(req, true).await;
        }

        Ok(())
    }

    fn validate_redirect_targets(&self, req: &AuthRequest) -> Result<(), AuthError> {
        if self.auth_config.advanced.disable_origin_check {
            return Ok(());
        }

        let body = Self::request_body_map(req).unwrap_or_default();
        let query_callback = req
            .query
            .as_ref()
            .and_then(|query| query.get("callbackURL"))
            .cloned();
        let callback = body
            .get("callbackURL")
            .filter(|value| Self::is_truthy(value))
            .or(query_callback.as_ref());
        for (name, value) in [
            ("callbackURL", callback),
            ("redirectTo", body.get("redirectTo")),
            ("errorCallbackURL", body.get("errorCallbackURL")),
            ("newUserCallbackURL", body.get("newUserCallbackURL")),
        ] {
            let Some(value) = value.filter(|value| Self::is_truthy(value)) else {
                continue;
            };
            let value = value.as_str().ok_or_else(|| {
                AuthError::bad_request(format!(
                    "{}: expected a string",
                    Self::target_error_message(name)
                ))
            })?;
            if !crate::config::is_safe_relative_path(value)
                && !extract_origin(value).is_some_and(|origin| self.is_origin_trusted(&origin))
            {
                return Err(AuthError::forbidden(Self::target_error_message(name)));
            }
        }

        Ok(())
    }

    fn is_truthy(value: &Value) -> bool {
        match value {
            Value::Null => false,
            Value::Bool(value) => *value,
            Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
            Value::String(value) => !value.is_empty(),
            Value::Array(_) | Value::Object(_) => true,
        }
    }

    fn request_body_map(req: &AuthRequest) -> Option<Map<String, Value>> {
        if let Some(body) = req.parsed_http_body() {
            return body.as_object().cloned();
        }
        let content_type = Self::header(req, "content-type").unwrap_or_default();

        if content_type.contains("application/x-www-form-urlencoded") {
            let body = req.body.as_ref()?;
            return Some(
                url::form_urlencoded::parse(body)
                    .map(|(key, value)| (key.into_owned(), Value::String(value.into_owned())))
                    .collect(),
            );
        }

        req.body_as_json().ok()
    }

    fn target_error_message(name: &str) -> &'static str {
        match name {
            "callbackURL" => INVALID_CALLBACK_URL,
            "redirectTo" => INVALID_REDIRECT_URL,
            "errorCallbackURL" => INVALID_ERROR_CALLBACK_URL,
            "newUserCallbackURL" => INVALID_NEW_USER_CALLBACK_URL,
            _ => INVALID_ORIGIN,
        }
    }

    fn reject(error: AuthError) -> AuthResponse {
        error.to_auth_response()
    }
}

#[async_trait]
impl Middleware for CsrfMiddleware {
    fn name(&self) -> &'static str {
        "csrf"
    }

    async fn before_request(&self, req: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        if !self.config.enabled || !Self::is_state_changing(req.method()) {
            return Ok(None);
        }

        let csrf_result = self.validate_origin(req, false).await;

        if let Err(error) = csrf_result {
            return Ok(Some(Self::reject(error)));
        }

        if let Err(error) = self.validate_redirect_targets(req) {
            return Ok(Some(Self::reject(error)));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(
        path: &str,
        origin: Option<&str>,
        cookie: bool,
        extra_headers: &[(&str, &str)],
    ) -> AuthRequest {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        if let Some(origin) = origin {
            headers.insert("origin".to_string(), origin.to_string());
        }
        if cookie {
            headers.insert(
                "cookie".to_string(),
                "better-auth.session_token=test-token".to_string(),
            );
        }
        for (name, value) in extra_headers {
            headers.insert((*name).to_string(), (*value).to_string());
        }
        AuthRequest::from_parts(HttpMethod::Post, path.to_string(), headers, None, None)
    }

    fn test_auth_config(trusted_origins: Vec<String>) -> Arc<AuthConfig> {
        Arc::new(
            AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
                .base_url("http://localhost:3000")
                .trusted_origins(trusted_origins),
        )
    }

    async fn forbidden_message(response: Option<AuthResponse>) -> String {
        let response = response.expect("expected rejection response");
        assert_eq!(response.status, 403);
        let body =
            serde_json::from_slice::<serde_json::Value>(&response.body.bytes().unwrap()).unwrap();
        body["message"].as_str().unwrap().to_string()
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn cookie_backed_requests_require_a_trusted_origin() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let req = make_request("/sign-out", Some("http://evil.com"), true, &[]);
        let message = forbidden_message(mw.before_request(&req).await.unwrap()).await;
        assert_eq!(message, INVALID_ORIGIN);
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn cookie_backed_requests_require_origin_or_referer() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let req = make_request("/sign-out", None, true, &[]);
        let message = forbidden_message(mw.before_request(&req).await.unwrap()).await;
        assert_eq!(message, MISSING_OR_NULL_ORIGIN);
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn sign_in_allows_same_origin_fetch_metadata_requests() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let req = make_request(
            "/sign-in/email",
            Some("http://localhost:3000"),
            false,
            &[
                ("sec-fetch-site", "same-origin"),
                ("sec-fetch-mode", "cors"),
            ],
        );
        assert!(
            mw.validate_form_request(&req)
                .await
                .err()
                .map(|error| error.to_auth_response())
                .is_none()
        );
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn sign_in_blocks_cross_site_navigation_login_attempts() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let req = make_request(
            "/sign-in/email",
            Some("http://evil.com"),
            false,
            &[
                ("sec-fetch-site", "cross-site"),
                ("sec-fetch-mode", "navigate"),
            ],
        );
        let message = forbidden_message(
            mw.validate_form_request(&req)
                .await
                .err()
                .map(|error| error.to_auth_response()),
        )
        .await;
        assert_eq!(message, CROSS_SITE_NAVIGATION_LOGIN_BLOCKED);
    }

    #[tokio::test]
    async fn first_login_checks_origin_and_referer_without_fetch_metadata() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        for path in ["/sign-up/email", "/sign-in/email"] {
            for headers in [
                vec![("origin", "http://evil.com")],
                vec![("referer", "http://evil.com/login")],
                vec![("origin", ""), ("referer", "http://evil.com/login")],
            ] {
                let req = make_request(path, None, false, &headers);
                let message = forbidden_message(
                    mw.validate_form_request(&req)
                        .await
                        .err()
                        .map(|error| error.to_auth_response()),
                )
                .await;
                assert_eq!(message, INVALID_ORIGIN);
            }
            for headers in [
                vec![],
                vec![("origin", "http://localhost:3000")],
                vec![("referer", "http://localhost:3000/login")],
            ] {
                let req = make_request(path, None, false, &headers);
                assert!(
                    mw.validate_form_request(&req)
                        .await
                        .err()
                        .map(|error| error.to_auth_response())
                        .is_none()
                );
            }
        }
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn callback_targets_must_be_relative_or_trusted() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let mut req = make_request("/sign-in/social", None, false, &[]);
        req.body = Some(
            serde_json::json!({
                "provider": "google",
                "callbackURL": "http://evil.com/dashboard"
            })
            .to_string()
            .into_bytes(),
        );

        let message = forbidden_message(mw.before_request(&req).await.unwrap()).await;
        assert_eq!(message, INVALID_CALLBACK_URL);
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn csrf_can_be_disabled_explicitly() {
        let mw = CsrfMiddleware::new(CsrfConfig::new().enabled(false), test_auth_config(vec![]));
        let req = make_request("/sign-out", Some("http://evil.com"), true, &[]);
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn advanced_disable_origin_check_skips_callback_url_validation() {
        let mut config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
            .base_url("http://localhost:3000")
            .disable_origin_check(true);
        config.trusted_origins = Some(vec![].into());
        let mw = CsrfMiddleware::new(CsrfConfig::new(), Arc::new(config));
        let mut req = make_request("/sign-in/social", None, false, &[]);
        req.body = Some(
            serde_json::json!({
                "provider": "google",
                "callbackURL": "http://evil.com/dashboard"
            })
            .to_string()
            .into_bytes(),
        );

        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[test]
    fn extract_origin_still_handles_paths() {
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
