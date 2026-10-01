use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Index;
use validator::Validate;

use crate::utils::email::normalize_user_email;

// Re-export organization types
pub use super::types_org::{
    CreateInvitation, CreateMember, CreateOrganization, Invitation, InvitationStatus, Member,
    Organization, UpdateOrganization,
};
pub use super::types_plugin::{
    ApiKey, CreateApiKey, CreateDeviceCode, CreatePasskey, CreateTwoFactor, DeviceCode, Passkey,
    TwoFactor, UpdateApiKey, UpdateDeviceCode, UpdatePasskey, UpdatePasskeyAuthentication,
    UpdateTwoFactor,
};

/// HTTP method enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Options,
    Head,
}

/// Authentication request wrapper
#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub method: HttpMethod,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub query: HashMap<String, String>,
    /// Session authenticated by a trusted plugin hook for the current request.
    pub(crate) virtual_session: Option<crate::wire::SessionView>,
    /// Cookie updates from session middleware, shared by normalized request clones.
    response_headers: std::sync::Arc<std::sync::Mutex<Headers>>,
}

/// Metadata extracted from an incoming request for session creation.
///
/// Centralizes extraction of IP address and user-agent so that core
/// functions do not need the full [`AuthRequest`].
#[derive(Debug, Clone, Default)]
pub struct RequestMeta {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl RequestMeta {
    /// Extract metadata from an [`AuthRequest`]'s headers.
    ///
    /// IP address is read from `x-forwarded-for` (preferred), falling back
    /// to `x-real-ip`. User-agent is read from the `user-agent` header.
    pub fn from_request(req: &AuthRequest) -> Self {
        Self {
            ip_address: req
                .headers
                .get("x-forwarded-for")
                .or_else(|| req.headers.get("x-real-ip"))
                .cloned()
                .filter(|value| !value.is_empty()),
            user_agent: req.headers.get("user-agent").cloned(),
        }
    }
}

/// Authentication response wrapper
#[derive(Debug, Clone)]
pub struct AuthResponse {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
}

/// Response headers preserving repeated header names such as `Set-Cookie`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    /// Create an empty header collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a header, replacing any existing values for the same name.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) -> Option<String> {
        let name = name.into();
        let value = value.into();
        let mut previous = None;

        self.0.retain(|(existing_name, existing_value)| {
            if existing_name.eq_ignore_ascii_case(&name) {
                previous = Some(existing_value.clone());
                false
            } else {
                true
            }
        });

        self.0.push((name, value));
        previous
    }

    /// Append a header without removing existing values of the same name.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0.push((name.into(), value.into()));
    }

    /// Get the last value stored for a header name.
    pub fn get(&self, name: &str) -> Option<&String> {
        self.0.iter().rev().find_map(|(existing_name, value)| {
            existing_name.eq_ignore_ascii_case(name).then_some(value)
        })
    }

    /// Iterate over all values stored for a header name.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a String> + 'a {
        self.0.iter().filter_map(move |(existing_name, value)| {
            existing_name.eq_ignore_ascii_case(name).then_some(value)
        })
    }

    /// Check whether a header name exists.
    pub fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Return whether the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over stored header pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter().map(|(name, value)| (name, value))
    }

    /// Remove all values of a header.
    pub fn remove(&mut self, name: &str) {
        self.0.retain(|(key, _)| !key.eq_ignore_ascii_case(name));
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = (&'a String, &'a String);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, (String, String)>,
        fn(&(String, String)) -> (&String, &String),
    >;

    fn into_iter(self) -> Self::IntoIter {
        fn map_pair((name, value): &(String, String)) -> (&String, &String) {
            (name, value)
        }

        self.0.iter().map(map_pair)
    }
}

impl IntoIterator for Headers {
    type Item = (String, String);
    type IntoIter = std::vec::IntoIter<(String, String)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Index<&str> for Headers {
    type Output = String;

    #[expect(
        clippy::expect_used,
        reason = "Index must panic on missing headers to satisfy the trait contract"
    )]
    fn index(&self, index: &str) -> &Self::Output {
        self.get(index).expect("header not found")
    }
}

/// User creation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUser {
    pub id: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub role: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// User update data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateUser {
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTime<Utc>>,
    pub two_factor_enabled: Option<bool>,
    pub metadata: Option<serde_json::Value>,
}

/// Session creation data
#[derive(Debug, Clone)]
pub struct CreateSession {
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub impersonated_by: Option<String>,
    pub active_organization_id: Option<String>,
}

/// Account creation data
#[derive(Debug, Clone)]
pub struct CreateAccount {
    pub user_id: String,
    pub account_id: String,
    pub provider_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub password: Option<String>,
}

/// Account update data (for refreshing OAuth tokens)
#[derive(Debug, Clone, Default)]
pub struct UpdateAccount {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub password: Option<String>,
}

/// Verification token creation data
#[derive(Debug, Clone)]
pub struct CreateVerification {
    pub identifier: String,
    pub value: String,
    pub expires_at: DateTime<Utc>,
}

impl CreateUser {
    pub fn new() -> Self {
        Self {
            id: None,
            email: None,
            name: None,
            image: None,
            email_verified: None,
            username: None,
            display_username: None,
            role: None,
            metadata: None,
        }
    }

    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(normalize_user_email(&email.into()));
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_email_verified(mut self, verified: bool) -> Self {
        self.email_verified = Some(verified);
        self
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

impl Default for CreateUser {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthRequest {
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: HashMap::new(),
            body: None,
            query: HashMap::new(),
            virtual_session: None,
            response_headers: Default::default(),
        }
    }

    /// Construct a request from all public parts.
    ///
    /// Prefer [`AuthRequest::new`] when you only need method + path.
    pub fn from_parts(
        method: HttpMethod,
        path: String,
        headers: HashMap<String, String>,
        body: Option<Vec<u8>>,
        query: HashMap<String, String>,
    ) -> Self {
        Self {
            method,
            path,
            headers,
            body,
            query,
            virtual_session: None,
            response_headers: Default::default(),
        }
    }

    pub fn method(&self) -> &HttpMethod {
        &self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn header(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }

    /// Return the user ID authenticated by a trusted plugin hook.
    pub fn virtual_user_id(&self) -> Option<&str> {
        self.virtual_session
            .as_ref()
            .map(|session| session.user_id.as_str())
    }

    /// Return the session authenticated by a trusted plugin hook.
    pub fn virtual_session(&self) -> Option<&crate::wire::SessionView> {
        self.virtual_session.as_ref()
    }

    /// Attach a session authenticated by a trusted plugin hook.
    ///
    /// Call this method only from the request pipeline after a plugin returns
    /// `BeforeRequestAction::InjectSession`. Never populate the session from client input.
    pub fn set_virtual_session(&mut self, session: crate::wire::SessionView) {
        self.virtual_session = Some(session);
    }

    /// Queue a response header from request-scoped authentication middleware.
    pub fn append_response_header(&self, name: &str, value: String) -> crate::AuthResult<()> {
        self.response_headers
            .lock()
            .map_err(|_| crate::AuthError::internal("Session response headers lock poisoned"))?
            .append(name, value);
        Ok(())
    }

    /// Drain response headers queued by authentication middleware.
    pub fn take_response_headers(&self) -> crate::AuthResult<Headers> {
        let mut headers = self
            .response_headers
            .lock()
            .map_err(|_| crate::AuthError::internal("Session response headers lock poisoned"))?;
        Ok(std::mem::take(&mut *headers))
    }

    pub fn body_as_json<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        if let Some(body) = &self.body {
            serde_json::from_slice(body)
        } else {
            serde_json::from_str("{}")
        }
    }
}

impl AuthResponse {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    pub fn json<T: Serialize>(status: u16, data: &T) -> Result<Self, serde_json::Error> {
        let body = serde_json::to_vec(data)?;
        let mut headers = Headers::new();
        _ = headers.insert("content-type".to_string(), "application/json".to_string());

        Ok(Self {
            status,
            headers,
            body,
        })
    }

    pub fn text(status: u16, text: impl Into<String>) -> Self {
        let body = text.into().into_bytes();
        let mut headers = Headers::new();
        _ = headers.insert("content-type".to_string(), "text/plain".to_string());

        Self {
            status,
            headers,
            body,
        }
    }

    pub fn html(status: u16, html: impl Into<String>) -> Self {
        let body = html.into().into_bytes();
        let mut headers = Headers::new();
        _ = headers.insert(
            "content-type".to_string(),
            "text/html; charset=utf-8".to_string(),
        );

        Self {
            status,
            headers,
            body,
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        _ = self.headers.insert(name.into(), value.into());
        self
    }

    pub fn with_appended_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.headers.append(name.into(), value.into());
        self
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    #[validate(email(message = "Invalid email address"))]
    pub email: Option<String>,
    pub image: Option<String>,
    pub username: Option<String>,
    #[serde(rename = "displayUsername")]
    pub display_username: Option<String>,
    pub role: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

impl UpdateUserRequest {
    /// Wire keys upstream core marks `input: false`.
    ///
    /// Rejected on every request; stripped before deserialization so they can
    /// never reach the store.
    pub const NON_WRITABLE_CORE_FIELDS: [&'static str; 1] = ["emailVerified"];

    /// Wire keys the Admin plugin's user schema marks `input: false`.
    pub const NON_WRITABLE_ADMIN_FIELDS: [&'static str; 4] =
        ["role", "banned", "banReason", "banExpires"];

    /// Wire keys the Two-Factor plugin's user schema marks `input: false`.
    pub const NON_WRITABLE_TWO_FACTOR_FIELDS: [&'static str; 1] = ["twoFactorEnabled"];

    /// Every plugin-contributed non-writable key, regardless of which plugin
    /// owns it. Stripped before deserialization, exactly like upstream's
    /// silent ignore when the owning plugin is absent.
    pub fn is_plugin_non_writable(key: &str) -> bool {
        Self::NON_WRITABLE_ADMIN_FIELDS.contains(&key)
            || Self::NON_WRITABLE_TWO_FACTOR_FIELDS.contains(&key)
    }

    /// Whether `key` must be rejected on this request. Upstream only knows a
    /// plugin-contributed `input: false` field when that plugin's schema is
    /// installed, so each key is gated on its own plugin — not on either one.
    pub fn is_denied_by_plugin(
        key: &str,
        admin_installed: bool,
        two_factor_installed: bool,
    ) -> bool {
        (admin_installed && Self::NON_WRITABLE_ADMIN_FIELDS.contains(&key))
            || (two_factor_installed && Self::NON_WRITABLE_TWO_FACTOR_FIELDS.contains(&key))
    }

    /// JS truthiness, mirroring upstream's `if (data[key])` gate in
    /// `parseInputData`: `null`/`false`/`0`/`""` are skipped, not rejected.
    pub fn is_js_truthy(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Null => false,
            serde_json::Value::Bool(b) => *b,
            serde_json::Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
            serde_json::Value::String(s) => !s.is_empty(),
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => true,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UpdateUserResponse<U: Serialize> {
    pub user: U,
}

/// Generic `{ ok: bool }` response used by `/ok` and `/error` endpoints.
#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

/// Generic `{ status: bool }` response.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: bool,
}

/// `{ status: bool, message: String }` response (e.g. change-email).
#[derive(Debug, Serialize)]
pub struct StatusMessageResponse {
    pub status: bool,
    pub message: String,
}

/// Generic `{ success: bool }` response (e.g. sign-out).
///
/// Use for endpoints where the upstream spec defines `success` rather than `status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessResponse {
    pub success: bool,
}

/// `{ success: bool, message: String }` response (e.g. delete-user).
///
/// Use for endpoints where the upstream spec defines `success` rather than `status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessMessageResponse {
    pub success: bool,
    pub message: String,
}

/// Health-check response for `/health`.
#[derive(Debug, Serialize)]
pub struct HealthCheckResponse {
    pub status: &'static str,
    pub service: &'static str,
}

/// Error body `{ message: String }`.
#[derive(Debug, Serialize)]
pub struct ErrorMessageResponse {
    pub message: String,
}

/// Error body `{ code: String, message: String }` matching the TS better-auth
/// error response shape.
#[derive(Debug, Serialize)]
pub struct ErrorCodeMessageResponse {
    /// Omitted when upstream has no explicit code for this error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
}

/// Middleware error response `{ code: String, message: String }`.
#[derive(Debug, Serialize)]
pub struct CodeMessageResponse {
    pub code: &'static str,
    pub message: String,
}

/// Rate-limit error response with `retryAfter` field.
#[derive(Debug, Serialize)]
pub struct RateLimitErrorResponse {
    pub code: &'static str,
    pub message: &'static str,
    #[serde(rename = "retryAfter")]
    pub retry_after: u64,
}

/// Validation error response `{ code, message, errors }`.
#[derive(Debug, Serialize)]
pub struct ValidationErrorResponse<'a> {
    pub code: &'static str,
    pub message: &'static str,
    pub errors: std::collections::HashMap<std::borrow::Cow<'a, str>, Vec<String>>,
}

/// Parameters for listing users (admin endpoint).
#[derive(Debug, Clone, Default)]
pub struct ListUsersParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub search_field: Option<String>,
    pub search_value: Option<String>,
    pub search_operator: Option<String>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
    pub filter_field: Option<String>,
    pub filter_value: Option<String>,
    pub filter_operator: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── AuthRequest ─────────────────────────────────────────────────────

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_request_new_defaults() {
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        assert_eq!(req.method(), &HttpMethod::Get);
        assert_eq!(req.path(), "/test");
        assert!(req.headers.is_empty());
        assert!(req.body.is_none());
        assert!(req.virtual_user_id().is_none());
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_request_from_parts() {
        let mut headers = HashMap::new();
        let _ = headers.insert("host".to_string(), "localhost".to_string());
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/login".into(),
            headers,
            Some(b"{}".to_vec()),
            HashMap::new(),
        );
        assert_eq!(req.method(), &HttpMethod::Post);
        assert_eq!(req.header("host"), Some(&"localhost".to_string()));
        assert!(req.body.is_some());
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_request_body_as_json_with_body() {
        let req = AuthRequest {
            method: HttpMethod::Post,
            path: "/test".into(),
            headers: HashMap::new(),
            body: Some(br#"{"name":"test"}"#.to_vec()),
            query: HashMap::new(),
            virtual_session: None,
            response_headers: Default::default(),
        };
        let val: serde_json::Value = req.body_as_json().expect("parse");
        assert_eq!(val["name"], "test");
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_request_body_as_json_without_body() {
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        let val: serde_json::Value = req.body_as_json().expect("parse empty");
        assert!(val.is_object());
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_request_virtual_user_id() {
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        assert!(req.virtual_user_id().is_none());
        let now = Utc::now();
        req.set_virtual_session(crate::wire::SessionView {
            id: "key-123".into(),
            token: "key-token".into(),
            user_id: "user-123".into(),
            created_at: now,
            updated_at: now,
            expires_at: now,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active: true,
            additional_fields: Default::default(),
        });
        assert_eq!(req.virtual_user_id(), Some("user-123"));
    }

    // ── AuthResponse ────────────────────────────────────────────────────

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_response_new() {
        let resp = AuthResponse::new(200);
        assert_eq!(resp.status, 200);
        assert!(resp.body.is_empty());
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_response_json() {
        let resp = AuthResponse::json(200, &OkResponse { ok: true }).expect("json");
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["ok"], true);
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_response_text() {
        let resp = AuthResponse::text(404, "Not found");
        assert_eq!(resp.status, 404);
        assert_eq!(resp.headers.get("content-type").unwrap(), "text/plain");
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "Not found");
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_response_html() {
        let resp = AuthResponse::html(200, "<h1>Hi</h1>");
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_response_with_header() {
        let resp = AuthResponse::new(200).with_header("x-custom", "val");
        assert_eq!(resp.headers.get("x-custom").unwrap(), "val");
    }

    // ── RequestMeta ─────────────────────────────────────────────────────

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn request_meta_extracts_from_headers() {
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req
            .headers
            .insert("x-forwarded-for".into(), "1.2.3.4".into());
        let _ = req.headers.insert("user-agent".into(), "TestAgent".into());
        let meta = RequestMeta::from_request(&req);
        assert_eq!(meta.ip_address.as_deref(), Some("1.2.3.4"));
        assert_eq!(meta.user_agent.as_deref(), Some("TestAgent"));
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn request_meta_falls_back_to_real_ip() {
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req.headers.insert("x-real-ip".into(), "5.6.7.8".into());
        let meta = RequestMeta::from_request(&req);
        assert_eq!(meta.ip_address.as_deref(), Some("5.6.7.8"));
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn request_meta_none_when_no_headers() {
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        let meta = RequestMeta::from_request(&req);
        assert!(meta.ip_address.is_none());
        assert!(meta.user_agent.is_none());
    }

    // ── CreateUser builder ──────────────────────────────────────────────

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn create_user_builder() {
        let cu = CreateUser::new()
            .with_email("Test@Example.COM")
            .with_name("Test")
            .with_email_verified(true)
            .with_username("testuser")
            .with_role("admin")
            .with_metadata(serde_json::json!({"key": "val"}));

        assert!(cu.id.is_none()); // ID generation is delegated to the model/store path
        assert_eq!(cu.email.as_deref(), Some("test@example.com"));
        assert_eq!(cu.name.as_deref(), Some("Test"));
        assert_eq!(cu.email_verified, Some(true));
        assert_eq!(cu.username.as_deref(), Some("testuser"));
        assert_eq!(cu.role.as_deref(), Some("admin"));
        assert!(cu.metadata.is_some());
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn create_user_default() {
        let cu = CreateUser::default();
        assert!(cu.id.is_none());
        assert!(cu.email.is_none());
    }

    // ── is_false helper ─────────────────────────────────────────────────
}
