pub use crate::types_account::{CreateAccount, CreateVerification, UpdateAccount};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Index;
use validator::Validate;

use crate::utils::email::normalize_user_email;

pub use crate::types_team::{
    CreateOrganizationRole, CreateTeam, OrganizationRole, Team, TeamMember, UpdateOrganizationRole,
    UpdateTeam,
};

// Re-export organization types
pub use super::types_org::{
    CreateInvitation, CreateMember, CreateOrganization, Invitation, InvitationStatus, Member,
    Organization, UpdateOrganization,
};
pub use super::types_plugin::{
    ApiKey, CreateApiKey, CreateDeviceCode, CreatePasskey, CreateTwoFactor, CreateWalletAddress,
    DeviceCode, DeviceCodeOwnership, DeviceCodeWhere, Passkey, PasskeyCredentialState,
    PasskeyStorage, TwoFactor, TwoFactorStorage, UpdateApiKey, UpdateDeviceCode, UpdatePasskey,
    UpdatePasskeyAuthentication, UpdateTwoFactor, WalletAddress, WhereMode, WhereOperator,
};

/// HTTP method enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// Raw endpoint query. Native omission remains distinct from null and an empty object.
    pub query: Option<serde_json::Value>,
    url: Option<url::Url>,
    base_relative_path: bool,
    original_request: Option<std::sync::Arc<AuthRequest>>,
    pub(crate) parsed_http_body: Option<crate::http_body::ParsedHttpBody>,
    pub(crate) endpoint_body: Option<crate::endpoint_input::EndpointBody>,
    /// Session authenticated by a trusted plugin hook for the current request.
    pub(crate) virtual_session: Option<crate::wire::SessionView>,
    /// Cookie updates from session middleware, shared by normalized request clones.
    response_headers: std::sync::Arc<std::sync::Mutex<Headers>>,
    server_only: bool,
    server_context: std::sync::Arc<std::sync::Mutex<crate::FieldMap>>,
    headers_present: bool,
    new_session: std::sync::Arc<std::sync::Mutex<Option<crate::session::SessionData>>>,
    session_snapshot: std::sync::Arc<std::sync::Mutex<Option<crate::session::SessionData>>>,
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
    /// Extract metadata with the default forwarded-address policy.
    pub fn from_request(req: &AuthRequest) -> Self {
        Self::from_request_with_config(req, &crate::config::IpAddressConfig::default())
    }

    /// Extract session metadata with the application's trusted-proxy policy.
    pub fn from_request_with_config(
        req: &AuthRequest,
        config: &crate::config::IpAddressConfig,
    ) -> Self {
        Self {
            ip_address: config.resolve(req),
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
    api_error: bool,
    error_headers: Option<Headers>,
    captured_headers: Option<Headers>,
}

/// Response headers preserving repeated header names such as `Set-Cookie`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    /// Merge endpoint headers. Cookies accumulate; other headers replace earlier values.
    pub fn merge(&mut self, headers: Self) {
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("set-cookie") {
                self.append(name, value);
            } else {
                let _ = self.insert(name, value);
            }
        }
    }

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

    pub(crate) fn has_set_cookie(&self, name: &str) -> bool {
        let exact = format!("{name}=");
        let chunk = format!("{name}.");
        self.get_all("set-cookie")
            .any(|value| value.starts_with(&exact) || value.starts_with(&chunk))
    }

    pub(crate) fn remove_set_cookie(&mut self, name: &str) {
        let exact = format!("{name}=");
        let chunk = format!("{name}.");
        self.0.retain(|(header, value)| {
            !header.eq_ignore_ascii_case("set-cookie")
                || !(value.starts_with(&exact) || value.starts_with(&chunk))
        });
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
    /// Seeded creation time; omission uses the adapter creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "crate::field_value::serde::optional_date")]
    pub created_at: Option<crate::FieldDate>,
    /// Seeded update time; omission uses the adapter creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "crate::field_value::serde::optional_date")]
    pub updated_at: Option<crate::FieldDate>,
    /// Application user fields keyed by their public schema names.
    #[serde(with = "crate::field_value::serde::map", default)]
    pub additional_fields: crate::FieldMap,
    pub id: Option<String>,
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "crate::SchemaValue::is_undefined")]
    pub name: crate::SchemaValue<Option<String>>,
    #[serde(default, skip_serializing_if = "crate::SchemaValue::is_undefined")]
    pub image: crate::SchemaValue<Option<String>>,
    pub email_verified: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_nullable_update"
    )]
    pub username: Option<Option<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_nullable_update"
    )]
    pub display_username: Option<Option<String>>,
    pub is_anonymous: Option<bool>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub ban_reason: Option<String>,
    #[serde(with = "crate::field_value::serde::optional_date", default)]
    pub ban_expires: Option<crate::FieldDate>,
    #[serde(with = "crate::field_value::serde::optional_value", default)]
    pub metadata: Option<crate::FieldValue>,
}

/// User update data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateUser {
    /// Application user fields keyed by their public schema names.
    #[serde(with = "crate::field_value::serde::map", default)]
    pub additional_fields: crate::FieldMap,
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "crate::SchemaValue::is_undefined")]
    pub name: crate::SchemaValue<Option<String>>,
    #[serde(default, skip_serializing_if = "crate::SchemaValue::is_undefined")]
    pub image: crate::SchemaValue<Option<String>>,
    pub email_verified: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_nullable_update"
    )]
    pub username: Option<Option<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_nullable_update"
    )]
    pub display_username: Option<Option<String>>,
    pub is_anonymous: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_nullable_update"
    )]
    pub phone_number: Option<Option<String>>,
    pub phone_number_verified: Option<bool>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    /// Omission preserves the reason; an explicit null clears it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_nullable_update"
    )]
    pub ban_reason: Option<Option<String>>,
    /// Omission preserves expiration; an explicit null clears it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::field_value::serde::date_update"
    )]
    pub ban_expires: Option<Option<crate::FieldDate>>,
    pub two_factor_enabled: Option<bool>,
    #[serde(with = "crate::field_value::serde::optional_value", default)]
    pub metadata: Option<crate::FieldValue>,
}

fn deserialize_nullable_update<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    <Option<T> as serde::Deserialize>::deserialize(deserializer).map(Some)
}

/// Session creation data
#[derive(Debug, Clone)]
pub struct CreateSession {
    /// Trusted application fields written with the initial session record.
    pub additional_fields: crate::FieldMap,
    pub user_id: crate::SchemaValue<String>,
    pub expires_at: crate::FieldDate,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub impersonated_by: Option<String>,
    pub active_organization_id: Option<String>,
}

impl CreateUser {
    pub fn new() -> Self {
        Self {
            created_at: None,
            updated_at: None,
            additional_fields: Default::default(),
            id: None,
            email: None,
            name: Default::default(),
            image: Default::default(),
            email_verified: None,
            username: Default::default(),
            display_username: Default::default(),
            is_anonymous: None,
            phone_number: None,
            phone_number_verified: None,
            role: None,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            metadata: None,
        }
    }

    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(normalize_user_email(&email.into()));
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into()).into();
        self
    }

    pub fn with_email_verified(mut self, verified: bool) -> Self {
        self.email_verified = Some(verified);
        self
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(Some(username.into()));
        self
    }

    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    pub fn with_metadata(mut self, metadata: crate::FieldValue) -> Self {
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
            query: None,
            url: None,
            base_relative_path: false,
            original_request: None,
            parsed_http_body: None,
            endpoint_body: None,
            virtual_session: None,
            response_headers: Default::default(),
            server_only: false,
            server_context: Default::default(),
            headers_present: true,
            new_session: Default::default(),
            session_snapshot: Default::default(),
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
        query: Option<serde_json::Value>,
    ) -> Self {
        Self {
            method,
            path,
            headers,
            body,
            query,
            url: None,
            base_relative_path: false,
            original_request: None,
            parsed_http_body: None,
            endpoint_body: None,
            virtual_session: None,
            response_headers: Default::default(),
            server_only: false,
            server_context: Default::default(),
            headers_present: true,
            new_session: Default::default(),
            session_snapshot: Default::default(),
        }
    }

    /// Read a scalar query field without collapsing arrays or null into omission.
    pub fn query_string(&self, name: &str) -> Result<Option<&str>, AuthResponse> {
        crate::query::string_field(self.query.as_ref(), name)
    }

    pub fn method(&self) -> &HttpMethod {
        &self.method
    }

    /// Supply native endpoint headers with lowercase names, preserving omission separately from an empty set.
    pub fn with_optional_headers(mut self, headers: Option<HashMap<String, String>>) -> Self {
        self.headers_present = headers.is_some();
        self.headers = headers
            .unwrap_or_default()
            .into_iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value))
            .collect();
        self
    }

    /// Headers supplied to the endpoint, including an explicitly empty set.
    pub fn endpoint_headers(&self) -> Option<&HashMap<String, String>> {
        self.headers_present.then_some(&self.headers)
    }

    /// The endpoint's session snapshot, including an expired record retained by get-session.
    /// This snapshot is not an authentication decision. Use the session manager to authenticate.
    pub fn session_snapshot(&self) -> crate::AuthResult<Option<crate::session::SessionData>> {
        Ok(self
            .session_snapshot
            .lock()
            .map_err(|_| crate::AuthError::internal("Session snapshot lock poisoned"))?
            .clone())
    }

    pub(crate) fn set_session_snapshot(
        &self,
        data: Option<crate::session::SessionData>,
    ) -> crate::AuthResult<()> {
        *self
            .session_snapshot
            .lock()
            .map_err(|_| crate::AuthError::internal("Session snapshot lock poisoned"))? = data;
        Ok(())
    }

    /// The exact identity last passed to the session-cookie writer during this endpoint call.
    pub fn new_session(&self) -> crate::AuthResult<Option<crate::session::SessionData>> {
        Ok(self
            .new_session
            .lock()
            .map_err(|_| crate::AuthError::internal("Session snapshot lock poisoned"))?
            .clone())
    }

    /// Clear the issuance snapshot after a session is removed during an endpoint hook.
    pub fn clear_new_session(&self) -> crate::AuthResult<()> {
        *self
            .new_session
            .lock()
            .map_err(|_| crate::AuthError::internal("Session snapshot lock poisoned"))? = None;
        Ok(())
    }

    pub(crate) fn set_new_session(
        &self,
        data: crate::session::SessionData,
    ) -> crate::AuthResult<()> {
        *self
            .new_session
            .lock()
            .map_err(|_| crate::AuthError::internal("Session snapshot lock poisoned"))? =
            Some(data);
        Ok(())
    }

    /// Preserve an explicit native Request independently of endpoint headers and HTTP transport.
    pub fn with_original_request(mut self, request: AuthRequest) -> Self {
        self.original_request = Some(std::sync::Arc::new(request));
        self
    }

    pub fn original_request(&self) -> Option<&AuthRequest> {
        self.original_request.as_deref()
    }

    /// Attach the original URL supplied by the server transport.
    ///
    /// Route normalization preserves this URL. Do not derive the URL from client
    /// forwarding headers unless the application has authenticated the proxy.
    pub fn with_url(mut self, url: url::Url) -> Self {
        self.url = Some(url);
        self
    }

    /// Mark the current path as relative to a server router mount.
    /// The integration must remove the mount prefix before calling this method.
    pub fn with_base_relative_path(mut self) -> Self {
        self.base_relative_path = true;
        self
    }

    /// Return the path supplied by a mounted server router.
    pub fn base_relative_path(&self) -> Option<&str> {
        self.base_relative_path.then_some(self.path())
    }

    /// Return the original transport URL, if the integration supplied one.
    pub fn url(&self) -> Option<&url::Url> {
        self.url.as_ref()
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
            .and_then(|session| session.user_id.as_str())
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

    pub(crate) fn set_server_only(&mut self) {
        self.server_only = true;
    }

    /// Whether this invocation belongs to a native-only endpoint.
    pub fn is_server_only(&self) -> bool {
        self.server_only
    }

    /// Attach trusted server state for request hooks. Never populate this state from request body fields.
    pub fn set_server_context(
        &self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> crate::AuthResult<()> {
        let _ = self
            .server_context
            .lock()
            .map_err(|_| crate::AuthError::internal("Request server context lock poisoned"))?
            .insert(key.into(), value);
        Ok(())
    }

    /// Read server state attached by an authenticated flow.
    pub fn server_context(&self, key: &str) -> crate::AuthResult<Option<serde_json::Value>> {
        Ok(self
            .server_context
            .lock()
            .map_err(|_| crate::AuthError::internal("Request server context lock poisoned"))?
            .get(key)
            .cloned())
    }

    /// Queue a response header from request-scoped authentication middleware.
    pub fn set_response_header(
        &self,
        name: &str,
        value: impl Into<String>,
    ) -> crate::AuthResult<()> {
        let _ = self
            .response_headers
            .lock()
            .map_err(|_| crate::AuthError::internal("Session response headers lock poisoned"))?
            .insert(name, value.into());
        Ok(())
    }

    /// Append a response header without replacing earlier values.
    pub fn append_response_header(&self, name: &str, value: String) -> crate::AuthResult<()> {
        self.response_headers
            .lock()
            .map_err(|_| crate::AuthError::internal("Session response headers lock poisoned"))?
            .append(name, value);
        Ok(())
    }

    pub(crate) fn has_response_cookie(&self, name: &str) -> crate::AuthResult<bool> {
        Ok(self
            .response_headers
            .lock()
            .map_err(|_| crate::AuthError::internal("Session response headers lock poisoned"))?
            .has_set_cookie(name))
    }

    pub(crate) fn remove_response_cookie(&self, name: &str) -> crate::AuthResult<()> {
        self.response_headers
            .lock()
            .map_err(|_| crate::AuthError::internal("Session response headers lock poisoned"))?
            .remove_set_cookie(name);
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
        if let Some(body) = self.projected_body() {
            serde_json::from_value(body.clone().unwrap_or_else(|| serde_json::json!({})))
        } else if let Some(body) = self.parsed_http_body() {
            serde_json::from_value(body.clone())
        } else if let Some(body) = &self.body {
            serde_json::from_slice(body)
        } else {
            serde_json::from_str("{}")
        }
    }
}

impl AuthResponse {
    /// Whether the returned value represents an API error rather than an ordinary response.
    pub fn is_api_error(&self) -> bool {
        self.api_error
    }

    pub(crate) fn into_api_error(mut self) -> Self {
        self.api_error = true;
        if self.error_headers.is_none() {
            self.error_headers = Some(self.headers.clone());
        }
        self
    }

    /// Explicit headers supplied by the API error before dispatch merged response headers.
    pub fn api_error_headers(&self) -> Option<&Headers> {
        self.error_headers.as_ref()
    }

    /// Endpoint headers captured on a thrown native API error.
    pub fn captured_headers(&self) -> Option<&Headers> {
        self.captured_headers.as_ref()
    }

    /// Attach the endpoint header accumulator without changing the error's HTTP headers.
    pub fn capture_error_headers(&mut self, headers: Headers) {
        self.captured_headers = Some(headers);
    }

    /// Replace the returned JSON value while preserving response status and accumulated headers.
    pub fn replace_json<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), serde_json::Error> {
        self.body = serde_json::to_vec(value)?;
        self.api_error = false;
        self.error_headers = None;
        self.captured_headers = None;
        Ok(())
    }

    /// Replace the endpoint's returned value while retaining accumulated response headers.
    pub fn replace_returned(&mut self, mut returned: Self) {
        let mut headers = std::mem::take(&mut self.headers);
        headers.merge(std::mem::take(&mut returned.headers));
        returned.headers = headers;
        *self = returned;
    }

    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: Vec::new(),
            api_error: false,
            error_headers: None,
            captured_headers: None,
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
            api_error: false,
            error_headers: None,
            captured_headers: None,
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
            api_error: false,
            error_headers: None,
            captured_headers: None,
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
            api_error: false,
            error_headers: None,
            captured_headers: None,
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
    #[serde(default, skip_serializing_if = "crate::SchemaValue::is_undefined")]
    pub name: crate::SchemaValue<Option<String>>,
    #[validate(email(message = "Invalid email address"))]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "crate::SchemaValue::is_undefined")]
    pub image: crate::SchemaValue<Option<String>>,
    pub role: Option<String>,
    pub metadata: Option<crate::FieldValue>,
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
    pub limit: Option<f64>,
    pub offset: Option<f64>,
    pub search_field: Option<String>,
    pub search_value: Option<String>,
    pub search_operator: Option<String>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
    pub filter_field: Option<String>,
    pub filter_value: Option<crate::FieldValue>,
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
            None,
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
            query: None,
            url: None,
            base_relative_path: false,
            original_request: None,
            parsed_http_body: None,
            endpoint_body: None,
            virtual_session: None,
            response_headers: Default::default(),
            server_only: false,
            server_context: Default::default(),
            headers_present: true,
            new_session: Default::default(),
            session_snapshot: Default::default(),
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
            visible_fields: None,
            id: "key-123".into(),
            token: "key-token".into(),
            user_id: "user-123".into(),
            created_at: now.into(),
            updated_at: now.into(),
            expires_at: now.into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
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
    fn request_meta_supports_configured_real_ip_header() {
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req.headers.insert("x-real-ip".into(), "5.6.7.8".into());
        let config = crate::config::IpAddressConfig {
            headers: Some(vec!["x-real-ip".into()]),
            ..Default::default()
        };
        let meta = RequestMeta::from_request_with_config(&req, &config);
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
            .with_metadata(
                crate::FieldValue::from_json(serde_json::json!({"key": "val"})).unwrap(),
            );

        assert!(cu.id.is_none()); // ID generation is delegated to the model/store path
        assert_eq!(cu.email.as_deref(), Some("test@example.com"));
        assert_eq!(cu.name.typed().unwrap().as_deref(), Some("Test"));
        assert_eq!(cu.email_verified, Some(true));
        assert_eq!(
            cu.username.as_ref().and_then(Option::as_deref),
            Some("testuser")
        );
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

    #[test]
    fn nullable_user_updates_preserve_omission_null_and_values() {
        let cases = [
            serde_json::json!({}),
            serde_json::json!({
                "phone_number": null,
                "ban_reason": null,
                "ban_expires": null,
            }),
            serde_json::json!({
                "phone_number": "+12025550123",
                "ban_reason": "review",
                "ban_expires": "2030-01-01T00:00:00Z",
            }),
        ];
        for input in cases {
            let patch: UpdateUser = serde_json::from_value(input.clone()).unwrap();
            let output = serde_json::to_value(&patch).unwrap();
            for field in ["phone_number", "ban_reason", "ban_expires"] {
                assert_eq!(output.get(field), input.get(field));
            }
            let restored: UpdateUser = serde_json::from_value(output).unwrap();
            assert_eq!(restored.phone_number, patch.phone_number);
            assert_eq!(restored.ban_reason, patch.ban_reason);
            assert_eq!(restored.ban_expires, patch.ban_expires);
        }
    }

    // ── is_false helper ─────────────────────────────────────────────────
}
