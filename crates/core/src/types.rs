use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Index;
use uuid::Uuid;
use validator::Validate;

/// Helper for `#[serde(skip_serializing_if = "is_false")]`
fn is_false(v: &bool) -> bool {
    !(*v)
}

// Re-export organization types
pub use super::types_org::{
    CreateInvitation, CreateMember, CreateOrganization, FullOrganization, Invitation,
    InvitationStatus, Member, MemberUser, MemberWithUser, Organization, UpdateOrganization,
};

/// Core user type - matches OpenAPI schema
///
/// Plugin-added fields (username, role, banned, twoFactorEnabled, etc.) are
/// omitted from serialization when at their default values, matching TS
/// behavior where these fields only appear when the corresponding plugin is
/// enabled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
    pub image: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
    // Plugin-added fields — skip when at default values to match TS core behavior
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "displayUsername", skip_serializing_if = "Option::is_none")]
    pub display_username: Option<String>,
    #[serde(rename = "twoFactorEnabled", skip_serializing_if = "is_false", default)]
    pub two_factor_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "is_false", default)]
    pub banned: bool,
    #[serde(rename = "banReason", skip_serializing_if = "Option::is_none")]
    pub ban_reason: Option<String>,
    #[serde(rename = "banExpires", skip_serializing_if = "Option::is_none")]
    pub ban_expires: Option<DateTime<Utc>>,
    // Keep metadata for internal use but don't serialize
    #[serde(skip)]
    pub metadata: serde_json::Value,
}

/// Session information - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    pub token: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
    #[serde(rename = "ipAddress")]
    pub ip_address: Option<String>,
    #[serde(rename = "userAgent")]
    pub user_agent: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: String,
    // Plugin-added fields — skip when at default values to match TS core behavior
    #[serde(rename = "impersonatedBy", skip_serializing_if = "Option::is_none")]
    pub impersonated_by: Option<String>,
    #[serde(
        rename = "activeOrganizationId",
        skip_serializing_if = "Option::is_none"
    )]
    pub active_organization_id: Option<String>,
    // Keep active field for internal use but don't serialize
    #[serde(skip)]
    pub active: bool,
}

/// Account linking (for OAuth providers) - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "idToken")]
    pub id_token: Option<String>,
    #[serde(rename = "accessTokenExpiresAt")]
    pub access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(rename = "refreshTokenExpiresAt")]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub password: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

/// Verification token - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    pub id: String,
    pub identifier: String,
    pub value: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

/// Two-factor authentication - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactor {
    pub id: String,
    pub secret: String,
    #[serde(rename = "backupCodes")]
    pub backup_codes: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

/// Passkey authentication - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey {
    pub id: String,
    pub name: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    pub counter: u64,
    #[serde(rename = "deviceType")]
    pub device_type: String,
    #[serde(rename = "backedUp")]
    pub backed_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new passkey
#[derive(Debug, Clone)]
pub struct CreatePasskey {
    pub user_id: String,
    pub name: String,
    pub credential_id: String,
    pub public_key: String,
    pub counter: u64,
    pub device_type: String,
    pub backed_up: bool,
    pub transports: Option<String>,
}

/// Input for updating a passkey
#[derive(Debug, Clone)]
pub struct UpdatePasskey {
    pub name: Option<String>,
}

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
    /// Virtual user ID injected by a `BeforeRequestAction::InjectSession`.
    ///
    /// When set, downstream handlers treat the request as authenticated for
    /// this user **without** a real database session.  This mirrors the
    /// TypeScript `ctx.context.session` virtual-session approach.
    ///
    /// # Security
    ///
    /// This field **must only** be set by the internal request pipeline
    /// (via [`set_virtual_user_id`](AuthRequest::set_virtual_user_id)) after
    /// a plugin's `before_request` hook returns
    /// `BeforeRequestAction::InjectSession`.  Application code constructing
    /// an `AuthRequest` should always leave this as `None`; setting it to
    /// `Some(…)` externally bypasses normal authentication.
    ///
    /// **`pub(crate)`** — external crates must use [`AuthRequest::from_parts`]
    /// or [`AuthRequest::new`] (which initialise this to `None`) and then
    /// [`set_virtual_user_id`](AuthRequest::set_virtual_user_id) only from
    /// the trusted request pipeline.
    pub(crate) virtual_user_id: Option<String>,
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
    pub password: Option<String>,
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

/// Two-factor authentication creation data
#[derive(Debug, Clone)]
pub struct CreateTwoFactor {
    pub user_id: String,
    pub secret: String,
    pub backup_codes: Option<String>,
}

/// API key - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: Option<String>,
    pub start: Option<String>,
    pub prefix: Option<String>,
    /// SHA-256 hash of the key (column name: `key` in SQL)
    #[serde(rename = "key")]
    pub key_hash: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "refillInterval")]
    pub refill_interval: Option<i64>,
    #[serde(rename = "refillAmount")]
    pub refill_amount: Option<i64>,
    #[serde(rename = "lastRefillAt")]
    pub last_refill_at: Option<String>,
    pub enabled: bool,
    #[serde(rename = "rateLimitEnabled")]
    pub rate_limit_enabled: bool,
    #[serde(rename = "rateLimitTimeWindow")]
    pub rate_limit_time_window: Option<i64>,
    #[serde(rename = "rateLimitMax")]
    pub rate_limit_max: Option<i64>,
    #[serde(rename = "requestCount")]
    pub request_count: Option<i64>,
    pub remaining: Option<i64>,
    #[serde(rename = "lastRequest")]
    pub last_request: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
}

/// API key creation data
#[derive(Debug, Clone)]
pub struct CreateApiKey {
    pub user_id: String,
    pub name: Option<String>,
    pub prefix: Option<String>,
    pub key_hash: String,
    pub start: Option<String>,
    pub expires_at: Option<String>,
    pub remaining: Option<i64>,
    pub rate_limit_enabled: bool,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    pub refill_interval: Option<i64>,
    pub refill_amount: Option<i64>,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
    pub enabled: bool,
}

/// API key update data
#[derive(Debug, Clone, Default)]
pub struct UpdateApiKey {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub remaining: Option<i64>,
    pub rate_limit_enabled: Option<bool>,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    pub refill_interval: Option<i64>,
    pub refill_amount: Option<i64>,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
    /// Update the expiration time. `Some(Some("..."))` sets a new value,
    /// `Some(None)` clears it, `None` leaves it unchanged.
    pub expires_at: Option<Option<String>>,
    /// Last request timestamp (updated during verify).
    pub last_request: Option<Option<String>>,
    /// Request count within the current rate-limit window.
    pub request_count: Option<i64>,
    /// Last refill timestamp (updated during verify).
    pub last_refill_at: Option<Option<String>>,
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
            id: Some(Uuid::new_v4().to_string()),
            email: None,
            name: None,
            image: None,
            email_verified: None,
            password: None,
            username: None,
            display_username: None,
            role: None,
            metadata: None,
        }
    }

    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
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

    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
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
            virtual_user_id: None,
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
            virtual_user_id: None,
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

    /// Returns the virtual user ID injected by a `before_request` hook, if any.
    pub fn virtual_user_id(&self) -> Option<&str> {
        self.virtual_user_id.as_deref()
    }

    /// Set the virtual user ID on this request.
    ///
    /// # Safety contract
    ///
    /// This **must only** be called from the internal request pipeline
    /// (i.e. `handle_request_inner`) after a plugin's `before_request` hook
    /// returns `BeforeRequestAction::InjectSession`.  Calling it from
    /// application code would bypass normal authentication.
    pub fn set_virtual_user_id(&mut self, user_id: String) {
        self.virtual_user_id = Some(user_id);
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
    pub code: String,
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
    pub errors: std::collections::HashMap<&'a str, Vec<String>>,
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

    // ── User serialization ──────────────────────────────────────────────

    #[test]
    fn user_serializes_camel_case() {
        let user = User {
            id: "u1".into(),
            name: Some("Test".into()),
            email: Some("test@test.com".into()),
            email_verified: true,
            image: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            username: None,
            display_username: None,
            two_factor_enabled: false,
            role: None,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            metadata: serde_json::Value::Null,
        };
        let json = serde_json::to_string(&user).expect("serialize");
        assert!(json.contains("\"emailVerified\""));
        assert!(json.contains("\"createdAt\""));
        assert!(json.contains("\"updatedAt\""));
        // Plugin fields at default should be omitted
        assert!(!json.contains("\"twoFactorEnabled\""));
        assert!(!json.contains("\"banned\""));
        assert!(!json.contains("\"role\""));
        assert!(!json.contains("\"username\""));
    }

    #[test]
    fn user_serializes_plugin_fields_when_set() {
        let user = User {
            id: "u1".into(),
            name: None,
            email: None,
            email_verified: false,
            image: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            username: Some("testuser".into()),
            display_username: None,
            two_factor_enabled: true,
            role: Some("admin".into()),
            banned: true,
            ban_reason: Some("spam".into()),
            ban_expires: None,
            metadata: serde_json::Value::Null,
        };
        let json = serde_json::to_string(&user).expect("serialize");
        assert!(json.contains("\"twoFactorEnabled\":true"));
        assert!(json.contains("\"banned\":true"));
        assert!(json.contains("\"role\":\"admin\""));
        assert!(json.contains("\"username\":\"testuser\""));
        assert!(json.contains("\"banReason\":\"spam\""));
    }

    #[test]
    fn user_deserializes_camel_case() {
        let json = r#"{
            "id": "u1",
            "name": "Test",
            "email": "test@test.com",
            "emailVerified": true,
            "image": null,
            "createdAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z"
        }"#;
        let user: User = serde_json::from_str(json).expect("deserialize");
        assert_eq!(user.id, "u1");
        assert!(user.email_verified);
        assert!(!user.two_factor_enabled); // default
        assert!(!user.banned); // default
    }

    // ── Session serialization ───────────────────────────────────────────

    #[test]
    fn session_serializes_camel_case() {
        let session = Session {
            id: "s1".into(),
            expires_at: Utc::now(),
            token: "tok".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ip_address: Some("1.2.3.4".into()),
            user_agent: Some("test".into()),
            user_id: "u1".into(),
            impersonated_by: None,
            active_organization_id: None,
            active: true,
        };
        let json = serde_json::to_string(&session).expect("serialize");
        assert!(json.contains("\"expiresAt\""));
        assert!(json.contains("\"userId\""));
        assert!(json.contains("\"ipAddress\""));
        assert!(json.contains("\"userAgent\""));
        // active is #[serde(skip)] — should not appear
        assert!(!json.contains("\"active\""));
        // Plugin fields at None should be omitted
        assert!(!json.contains("\"impersonatedBy\""));
        assert!(!json.contains("\"activeOrganizationId\""));
    }

    // ── AuthRequest ─────────────────────────────────────────────────────

    #[test]
    fn auth_request_new_defaults() {
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        assert_eq!(req.method(), &HttpMethod::Get);
        assert_eq!(req.path(), "/test");
        assert!(req.headers.is_empty());
        assert!(req.body.is_none());
        assert!(req.virtual_user_id().is_none());
    }

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

    #[test]
    fn auth_request_body_as_json_with_body() {
        let req = AuthRequest {
            method: HttpMethod::Post,
            path: "/test".into(),
            headers: HashMap::new(),
            body: Some(br#"{"name":"test"}"#.to_vec()),
            query: HashMap::new(),
            virtual_user_id: None,
        };
        let val: serde_json::Value = req.body_as_json().expect("parse");
        assert_eq!(val["name"], "test");
    }

    #[test]
    fn auth_request_body_as_json_without_body() {
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        let val: serde_json::Value = req.body_as_json().expect("parse empty");
        assert!(val.is_object());
    }

    #[test]
    fn auth_request_virtual_user_id() {
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        assert!(req.virtual_user_id().is_none());
        req.set_virtual_user_id("user-123".into());
        assert_eq!(req.virtual_user_id(), Some("user-123"));
    }

    // ── AuthResponse ────────────────────────────────────────────────────

    #[test]
    fn auth_response_new() {
        let resp = AuthResponse::new(200);
        assert_eq!(resp.status, 200);
        assert!(resp.body.is_empty());
    }

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

    #[test]
    fn auth_response_text() {
        let resp = AuthResponse::text(404, "Not found");
        assert_eq!(resp.status, 404);
        assert_eq!(resp.headers.get("content-type").unwrap(), "text/plain");
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "Not found");
    }

    #[test]
    fn auth_response_html() {
        let resp = AuthResponse::html(200, "<h1>Hi</h1>");
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn auth_response_with_header() {
        let resp = AuthResponse::new(200).with_header("x-custom", "val");
        assert_eq!(resp.headers.get("x-custom").unwrap(), "val");
    }

    // ── RequestMeta ─────────────────────────────────────────────────────

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

    #[test]
    fn request_meta_falls_back_to_real_ip() {
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req.headers.insert("x-real-ip".into(), "5.6.7.8".into());
        let meta = RequestMeta::from_request(&req);
        assert_eq!(meta.ip_address.as_deref(), Some("5.6.7.8"));
    }

    #[test]
    fn request_meta_none_when_no_headers() {
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        let meta = RequestMeta::from_request(&req);
        assert!(meta.ip_address.is_none());
        assert!(meta.user_agent.is_none());
    }

    // ── CreateUser builder ──────────────────────────────────────────────

    #[test]
    fn create_user_builder() {
        let cu = CreateUser::new()
            .with_email("test@test.com")
            .with_name("Test")
            .with_password("pass123")
            .with_email_verified(true)
            .with_username("testuser")
            .with_role("admin")
            .with_metadata(serde_json::json!({"key": "val"}));

        assert!(cu.id.is_some()); // auto-generated UUID
        assert_eq!(cu.email.as_deref(), Some("test@test.com"));
        assert_eq!(cu.name.as_deref(), Some("Test"));
        assert_eq!(cu.password.as_deref(), Some("pass123"));
        assert_eq!(cu.email_verified, Some(true));
        assert_eq!(cu.username.as_deref(), Some("testuser"));
        assert_eq!(cu.role.as_deref(), Some("admin"));
        assert!(cu.metadata.is_some());
    }

    #[test]
    fn create_user_default() {
        let cu = CreateUser::default();
        assert!(cu.id.is_some());
        assert!(cu.email.is_none());
    }

    // ── is_false helper ─────────────────────────────────────────────────

    #[test]
    fn is_false_helper() {
        assert!(is_false(&false));
        assert!(!is_false(&true));
    }
}
