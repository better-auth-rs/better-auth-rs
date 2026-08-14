//! Shared dual-server comparison infrastructure and test-control helpers.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::Duration;

use better_auth::BetterAuth;
use better_auth::prelude::{CreateAccount, CreateVerification};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex as TokioMutex;

use super::helpers::{
    ResetSenderMode, TestAuthOptions, create_test_auth, create_test_auth_with_options,
    get_with_auth, post_json, take_reset_password_token, unique_email,
};

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
type TestAuth = BetterAuth<TestSchema>;

pub const REFERENCE_PORT: u16 = 3100;
pub const REFERENCE_BASE: &str = "http://localhost:3100/api/auth";

fn env_flag_set(name: &str) -> bool {
    std::env::var(name)
        .map(|value| !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

fn reference_server_required() -> bool {
    env_flag_set("CI") || env_flag_set("BETTER_AUTH_REQUIRE_REFERENCE_SERVER")
}

async fn reference_server_available() -> bool {
    let client = localhost_client();
    client
        .get(format!("http://127.0.0.1:{REFERENCE_PORT}/__health"))
        .send()
        .await
        .map(|response| response.status().is_success())
        .unwrap_or(false)
}

fn try_start_reference_server() -> Result<std::process::Child, String> {
    let server_dir = std::path::Path::new("compat-tests/reference-server");
    if !server_dir.join("node_modules").exists() {
        return Err(format!(
            "node_modules not found in {}. Run:\n  cd {} && bun install",
            server_dir.display(),
            server_dir.display()
        ));
    }

    std::process::Command::new("bun")
        .args(["run", "server.ts"])
        .current_dir(server_dir)
        .env("PORT", REFERENCE_PORT.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| {
            format!(
                "failed to start reference server in {}: {error}",
                server_dir.display()
            )
        })
}

static SERIAL: TokioMutex<()> = TokioMutex::const_new(());
static REF_SERVER: Mutex<Option<std::process::Child>> = Mutex::new(None);

pub async fn serial_lock() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL.lock().await
}

async fn ensure_reference_server() -> Result<(), String> {
    if reference_server_available().await {
        return Ok(());
    }

    {
        let mut slot = REF_SERVER.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(try_start_reference_server()?);
        }
    }

    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if reference_server_available().await {
            return Ok(());
        }
    }

    Err("reference server did not become ready within 15 seconds".to_string())
}

pub async fn ensure_reference_server_or_skip() -> bool {
    match ensure_reference_server().await {
        Ok(()) => true,
        Err(reason) => {
            if reference_server_required() {
                panic!("[dual-server] reference server is required: {reason}");
            }
            eprintln!("[dual-server] SKIPPED locally: {reason}");
            eprintln!(
                "[dual-server] Set CI=1 or BETTER_AUTH_REQUIRE_REFERENCE_SERVER=1 to make this a hard failure."
            );
            false
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CookieAttrs {
    _value: String,
    path: Option<String>,
    http_only: bool,
    secure: bool,
    same_site: Option<String>,
    max_age: Option<String>,
}

fn parse_set_cookie(header_value: &str) -> (String, CookieAttrs) {
    let parts: Vec<&str> = header_value.split(';').collect();
    let name_value = parts.first().unwrap_or(&"");
    let (name, value) = name_value.split_once('=').unwrap_or((name_value, ""));

    let mut attrs = CookieAttrs {
        _value: value.to_string(),
        ..Default::default()
    };

    for part in parts.iter().skip(1) {
        let trimmed = part.trim();
        let lower = trimmed.to_lowercase();
        if lower == "httponly" {
            attrs.http_only = true;
        } else if lower == "secure" {
            attrs.secure = true;
        } else if let Some(v) = lower.strip_prefix("path=") {
            attrs.path = Some(v.to_string());
        } else if let Some(v) = lower.strip_prefix("samesite=") {
            attrs.same_site = Some(v.to_string());
        } else if let Some(v) = lower.strip_prefix("max-age=") {
            attrs.max_age = Some(v.to_string());
        }
    }

    (name.to_string(), attrs)
}

#[derive(Debug)]
pub struct FullResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub cookies: BTreeMap<String, CookieAttrs>,
    pub body: Value,
}

pub fn ref_error_response(error: String) -> FullResponse {
    eprintln!("[dual-server] ref request failed: {}", error);
    FullResponse {
        status: 0,
        headers: BTreeMap::new(),
        cookies: BTreeMap::new(),
        body: Value::String(format!("error: {}", error)),
    }
}

pub struct RefClient {
    client: reqwest::Client,
    pub session_cookie: Option<String>,
}

impl RefClient {
    pub fn new() -> Self {
        Self {
            client: localhost_client(),
            session_cookie: None,
        }
    }

    fn apply_headers(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req = req.header("origin", format!("http://localhost:{}", REFERENCE_PORT));
        if let Some(ref cookie) = self.session_cookie {
            req = req.header("cookie", format!("better-auth.session_token={cookie}"));
        }
        req
    }

    fn capture_cookie_from_response(&mut self, resp: &reqwest::Response) {
        for value in resp.headers().get_all("set-cookie") {
            if let Ok(s) = value.to_str()
                && let Some(rest) = s.strip_prefix("better-auth.session_token=")
            {
                let token = rest.split(';').next().unwrap_or(rest);
                self.session_cookie = (!token.is_empty()).then(|| token.to_string());
                return;
            }
        }
    }

    fn extract_full_response(
        resp: &reqwest::Response,
    ) -> (BTreeMap<String, String>, BTreeMap<String, CookieAttrs>) {
        let mut headers = BTreeMap::new();
        let mut cookies = BTreeMap::new();

        for (name, value) in resp.headers() {
            let name_lower = name.as_str().to_lowercase();
            if name_lower == "set-cookie" {
                if let Ok(v) = value.to_str() {
                    let (cookie_name, attrs) = parse_set_cookie(v);
                    let _ = cookies.insert(cookie_name, attrs);
                }
            } else if let Ok(v) = value.to_str() {
                let _ = headers.insert(name_lower, v.to_string());
            }
        }

        (headers, cookies)
    }

    pub async fn post_full(&mut self, path: &str, body: &Value) -> Result<FullResponse, String> {
        let url = format!("{}{}", REFERENCE_BASE, path);
        let req = self.apply_headers(
            self.client
                .post(&url)
                .json(body)
                .header("content-type", "application/json"),
        );
        let resp = req
            .send()
            .await
            .map_err(|error| format!("POST {url}: {error}"))?;

        self.capture_cookie_from_response(&resp);
        let status = resp.status().as_u16();
        let (headers, cookies) = Self::extract_full_response(&resp);
        let json: Value = resp
            .json()
            .await
            .unwrap_or_else(|_| Value::String("non-json".into()));

        Ok(FullResponse {
            status,
            headers,
            cookies,
            body: json,
        })
    }

    pub async fn get_full(&mut self, path: &str) -> Result<FullResponse, String> {
        let url = format!("{}{}", REFERENCE_BASE, path);
        let req = self.apply_headers(self.client.get(&url));
        let resp = req
            .send()
            .await
            .map_err(|error| format!("GET {url}: {error}"))?;

        self.capture_cookie_from_response(&resp);
        let status = resp.status().as_u16();
        let (headers, cookies) = Self::extract_full_response(&resp);
        let json: Value = resp
            .json()
            .await
            .unwrap_or_else(|_| Value::String("non-json".into()));

        Ok(FullResponse {
            status,
            headers,
            cookies,
            body: json,
        })
    }
}

pub fn localhost_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlMode {
    Capture,
    Fail,
    Success,
    Error,
}

impl ControlMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Fail => "throw",
            Self::Success => "success",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OAuthSeed {
    pub email: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "idToken")]
    pub id_token: Option<String>,
    #[serde(rename = "accessTokenExpiresAt")]
    pub access_token_expires_at: Option<String>,
    #[serde(rename = "refreshTokenExpiresAt")]
    pub refresh_token_expires_at: Option<String>,
    pub scope: Option<String>,
}

impl OAuthSeed {
    pub fn expired(email: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            provider_id: "mock".to_string(),
            account_id: "mock-account-id".to_string(),
            access_token: Some("stale-access-token".to_string()),
            refresh_token: Some("seed-refresh-token".to_string()),
            id_token: Some("seed-id-token".to_string()),
            access_token_expires_at: Some("2000-01-01T00:00:00Z".to_string()),
            refresh_token_expires_at: Some("2099-01-01T00:00:00Z".to_string()),
            scope: Some("openid,email,profile".to_string()),
        }
    }

    pub fn valid(email: impl Into<String>) -> Self {
        Self {
            access_token_expires_at: Some("2099-01-01T00:00:00Z".to_string()),
            ..Self::expired(email)
        }
    }
}

pub async fn reset_reference_state() -> Result<(), String> {
    post_control_json(
        "http://127.0.0.1:3100/__test/reset-state",
        &serde_json::json!({}),
    )
    .await
}

pub async fn set_reference_reset_password_mode(mode: ControlMode) -> Result<(), String> {
    post_control_json(
        "http://127.0.0.1:3100/__test/set-reset-password-mode",
        &serde_json::json!({ "mode": mode.as_str() }),
    )
    .await
}

pub async fn seed_reference_reset_password_token(
    email: &str,
    token: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), String> {
    post_control_json(
        "http://127.0.0.1:3100/__test/seed-reset-password-token",
        &serde_json::json!({
            "email": email,
            "token": token,
            "expiresAt": expires_at.to_rfc3339(),
        }),
    )
    .await
}

pub async fn set_reference_oauth_refresh_mode(mode: ControlMode) -> Result<(), String> {
    post_control_json(
        "http://127.0.0.1:3100/__test/set-oauth-refresh-mode",
        &serde_json::json!({ "mode": mode.as_str() }),
    )
    .await
}

pub async fn ref_reset_password_token(email: &str) -> Result<String, String> {
    let client = localhost_client();
    let response = client
        .get(format!(
            "http://127.0.0.1:{REFERENCE_PORT}/__test/reset-password-token"
        ))
        .query(&[("email", email)])
        .send()
        .await
        .map_err(|error| format!("reset token fetch failed: {error}"))?;

    if !response.status().is_success() {
        return Err(format!("reset token fetch returned {}", response.status()));
    }

    let body: Value = response
        .json()
        .await
        .map_err(|error| format!("reset token JSON parse failed: {error}"))?;
    body.get("token")
        .and_then(|token| token.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("reset token missing in response: {body}"))
}

pub async fn ref_seed_oauth_account(seed: &OAuthSeed) -> Result<(), String> {
    post_control_json(
        "http://127.0.0.1:3100/__test/seed-oauth-account",
        &serde_json::to_value(seed).unwrap_or_else(|error| {
            panic!("oauth seed should serialize: {error}");
        }),
    )
    .await
}

async fn post_control_json(url: &str, body: &Value) -> Result<(), String> {
    let client = localhost_client();
    let response = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|error| format!("POST {url} failed: {error}"))?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("POST {url} returned {}", response.status()))
    }
}

pub async fn create_default_test_auth() -> TestAuth {
    create_test_auth().await
}

pub async fn create_test_auth_with_reset_sender(mode: ResetSenderMode) -> TestAuth {
    create_test_auth_with_options(TestAuthOptions {
        reset_sender_mode: mode,
        ..Default::default()
    })
    .await
}

pub async fn seed_rust_reset_password_token(
    auth: &TestAuth,
    email: &str,
    token: &str,
    expires_at: DateTime<Utc>,
) {
    let user_id = auth
        .store()
        .get_user_by_email(email)
        .await
        .unwrap_or_else(|error| panic!("user lookup should succeed: {error}"))
        .unwrap_or_else(|| panic!("expected user for email {email}"))
        .id
        .to_string();

    let _ = auth
        .store()
        .create_verification(CreateVerification {
            identifier: format!("reset-password:{token}"),
            value: user_id,
            expires_at,
        })
        .await
        .unwrap_or_else(|error| panic!("reset-password verification should be created: {error}"));
}

pub async fn seed_rust_oauth_account(auth: &TestAuth, user_id: &str, seed: &OAuthSeed) {
    let access_token_expires_at = seed
        .access_token_expires_at
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .unwrap_or_else(|error| panic!("access token expiry should parse: {error}"));
    let refresh_token_expires_at = seed
        .refresh_token_expires_at
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .unwrap_or_else(|error| panic!("refresh token expiry should parse: {error}"));

    let _ = auth
        .store()
        .create_account(CreateAccount {
            user_id: user_id.to_string(),
            account_id: seed.account_id.clone(),
            provider_id: seed.provider_id.clone(),
            access_token: seed.access_token.clone(),
            refresh_token: seed.refresh_token.clone(),
            id_token: seed.id_token.clone(),
            access_token_expires_at,
            refresh_token_expires_at,
            scope: seed.scope.clone(),
            password: None,
        })
        .await
        .unwrap_or_else(|error| panic!("oauth account should be created: {error}"));
}

fn parse_rfc3339(value: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(value).map(|value| value.with_timezone(&Utc))
}

pub async fn signup_on_both(
    auth: &TestAuth,
    ref_client: &mut RefClient,
    prefix: &str,
) -> (String, String, String) {
    let email = unique_email(prefix);
    let body = serde_json::json!({
        "name": format!("{prefix} user"),
        "email": email,
        "password": "password123",
    });

    let rust_signup = rust_send(auth, post_json("/sign-up/email", body.clone())).await;
    let _ = ref_client
        .post_full("/sign-up/email", &body)
        .await
        .unwrap_or_else(ref_error_response);

    let rust_token = rust_signup
        .body
        .get("token")
        .and_then(|token| token.as_str())
        .unwrap_or("")
        .to_string();
    let rust_user_id = rust_signup
        .body
        .get("user")
        .and_then(|user| user.get("id"))
        .and_then(|id| id.as_str())
        .unwrap_or("")
        .to_string();

    (email, rust_token, rust_user_id)
}

pub async fn request_reset_on_both(
    auth: &TestAuth,
    ref_client: &mut RefClient,
    email: &str,
) -> (String, String) {
    let body = serde_json::json!({
        "email": email,
        "redirectTo": "/reset",
    });
    let _ = rust_send(auth, post_json("/request-password-reset", body.clone())).await;
    let _ = ref_client
        .post_full("/request-password-reset", &body)
        .await
        .unwrap_or_else(ref_error_response);

    let rust_token = take_reset_password_token(email)
        .unwrap_or_else(|| panic!("rust reset token missing for {email}"));
    let reference_token = ref_reset_password_token(email)
        .await
        .unwrap_or_else(|error| panic!("reference reset token missing: {error}"));
    (rust_token, reference_token)
}

pub async fn rust_send(auth: &TestAuth, req: better_auth::prelude::AuthRequest) -> FullResponse {
    let resp = auth
        .handle_request(req)
        .await
        .unwrap_or_else(|error| panic!("Rust request should not panic: {error}"));

    let status = resp.status;
    let mut headers = BTreeMap::new();
    let mut cookies = BTreeMap::new();

    for (name, value) in &resp.headers {
        let name_lower = name.to_lowercase();
        if name_lower == "set-cookie" {
            let (cookie_name, attrs) = parse_set_cookie(value);
            let _ = cookies.insert(cookie_name, attrs);
        } else {
            let _ = headers.insert(name_lower, value.clone());
        }
    }

    let body: Value = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&resp.body).to_string()));

    FullResponse {
        status,
        headers,
        cookies,
        body,
    }
}

fn json_shape(value: &Value) -> Value {
    match value {
        Value::Null => Value::String("null".into()),
        Value::Bool(_) => Value::String("boolean".into()),
        Value::Number(_) => Value::String("number".into()),
        Value::String(_) => Value::String("string".into()),
        Value::Array(arr) => {
            if let Some(first) = arr.first() {
                Value::Array(vec![json_shape(first)])
            } else {
                Value::Array(vec![])
            }
        }
        Value::Object(map) => {
            let shaped: serde_json::Map<String, Value> = map
                .iter()
                .map(|(key, value)| (key.clone(), json_shape(value)))
                .collect();
            Value::Object(shaped)
        }
    }
}

fn compare_shapes(rust_shape: &Value, ref_shape: &Value, path: &str) -> Vec<String> {
    let mut diffs = Vec::new();

    match (rust_shape, ref_shape) {
        (Value::Object(rust_obj), Value::Object(ref_obj)) => {
            let rust_keys: BTreeSet<_> = rust_obj.keys().collect();
            let ref_keys: BTreeSet<_> = ref_obj.keys().collect();

            for key in rust_keys.difference(&ref_keys) {
                diffs.push(format!(
                    "{}.{}: present in Rust, missing in reference",
                    path, key
                ));
            }
            for key in ref_keys.difference(&rust_keys) {
                diffs.push(format!(
                    "{}.{}: missing in Rust, present in reference",
                    path, key
                ));
            }
            for key in rust_keys.intersection(&ref_keys) {
                let child_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{}.{}", path, key)
                };
                if let (Some(rust_value), Some(ref_value)) = (rust_obj.get(*key), ref_obj.get(*key))
                {
                    diffs.extend(compare_shapes(rust_value, ref_value, &child_path));
                }
            }
        }
        (Value::Array(rust_arr), Value::Array(ref_arr)) => {
            if let (Some(rust_first), Some(ref_first)) = (rust_arr.first(), ref_arr.first()) {
                diffs.extend(compare_shapes(rust_first, ref_first, &format!("{path}[]")));
            }
        }
        (Value::String(rust_value), Value::String(ref_value)) if rust_value != ref_value => {
            diffs.push(format!("{path}: Rust={rust_value}, reference={ref_value}"));
        }
        _ => {}
    }

    diffs
}

const KNOWN_EXTRA_RUST_USER_FIELDS: &[&str] = &[
    "banned",
    "banReason",
    "banExpires",
    "role",
    "twoFactorEnabled",
    "username",
    "displayUsername",
];

const KNOWN_EXTRA_RUST_SESSION_FIELDS: &[&str] = &["activeOrganizationId", "impersonatedBy"];

fn filter_known_diffs(diffs: &[String]) -> Vec<String> {
    diffs
        .iter()
        .filter(|diff| {
            for field in KNOWN_EXTRA_RUST_USER_FIELDS {
                if diff.contains(&format!(".{}: present in Rust", field)) {
                    return false;
                }
            }
            for field in KNOWN_EXTRA_RUST_SESSION_FIELDS {
                if diff.contains(&format!(".{}: present in Rust", field)) {
                    return false;
                }
            }
            if diff.contains(".url: present in Rust") {
                return false;
            }
            if (diff.contains("ipAddress:") || diff.contains("userAgent:"))
                && diff.contains("Rust=null")
                && diff.contains("reference=string")
            {
                return false;
            }
            true
        })
        .cloned()
        .collect()
}

pub struct EndpointReport {
    name: String,
    status_match: bool,
    rust_status: u16,
    ref_status: u16,
    shape_diffs: Vec<String>,
    unexpected_shape_diffs: Vec<String>,
    cookie_diffs: Vec<String>,
    header_diffs: Vec<String>,
}

impl EndpointReport {
    fn is_pass(&self) -> bool {
        self.status_match
            && self.unexpected_shape_diffs.is_empty()
            && self.cookie_diffs.is_empty()
            && self.header_diffs.is_empty()
    }
}

fn compare_cookies(
    rust_cookies: &BTreeMap<String, CookieAttrs>,
    ref_cookies: &BTreeMap<String, CookieAttrs>,
) -> Vec<String> {
    let mut diffs = Vec::new();

    for (name, ref_attrs) in ref_cookies {
        match rust_cookies.get(name) {
            None => diffs.push(format!("cookie '{name}': missing in Rust")),
            Some(rust_attrs) => {
                if rust_attrs.path != ref_attrs.path {
                    diffs.push(format!(
                        "cookie '{name}' Path: Rust={:?}, Ref={:?}",
                        rust_attrs.path, ref_attrs.path
                    ));
                }
                if rust_attrs.http_only != ref_attrs.http_only {
                    diffs.push(format!(
                        "cookie '{name}' HttpOnly: Rust={}, Ref={}",
                        rust_attrs.http_only, ref_attrs.http_only
                    ));
                }
                if rust_attrs.same_site != ref_attrs.same_site {
                    diffs.push(format!(
                        "cookie '{name}' SameSite: Rust={:?}, Ref={:?}",
                        rust_attrs.same_site, ref_attrs.same_site
                    ));
                }
                if rust_attrs.secure != ref_attrs.secure {
                    diffs.push(format!(
                        "cookie '{name}' Secure: Rust={}, Ref={}",
                        rust_attrs.secure, ref_attrs.secure
                    ));
                }
            }
        }
    }

    for name in rust_cookies.keys() {
        if !ref_cookies.contains_key(name) {
            diffs.push(format!("cookie '{name}': present in Rust, missing in Ref"));
        }
    }

    diffs
}

fn compare_headers(
    rust_headers: &BTreeMap<String, String>,
    ref_headers: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut diffs = Vec::new();
    let compare_keys = ["content-type"];

    for key in &compare_keys {
        let rust_val = rust_headers.get(*key);
        let ref_val = ref_headers.get(*key);
        match (rust_val, ref_val) {
            (Some(rust_value), Some(ref_value)) => {
                let rust_type = rust_value.split(';').next().unwrap_or(rust_value).trim();
                let ref_type = ref_value.split(';').next().unwrap_or(ref_value).trim();
                if rust_type != ref_type {
                    diffs.push(format!(
                        "header '{key}': Rust='{rust_type}', Ref='{ref_type}'"
                    ));
                }
            }
            (None, Some(ref_value)) => {
                diffs.push(format!(
                    "header '{key}': missing in Rust, Ref='{ref_value}'"
                ));
            }
            (Some(rust_value), None) => {
                diffs.push(format!(
                    "header '{key}': Rust='{rust_value}', missing in Ref"
                ));
            }
            (None, None) => {}
        }
    }

    diffs
}

pub fn compare_full(name: &str, rust: &FullResponse, reference: &FullResponse) -> EndpointReport {
    let status_match = rust.status == reference.status;
    let shape_diffs = compare_shapes(&json_shape(&rust.body), &json_shape(&reference.body), "");
    let unexpected_shape_diffs = filter_known_diffs(&shape_diffs);
    let cookie_diffs = compare_cookies(&rust.cookies, &reference.cookies);
    let header_diffs = compare_headers(&rust.headers, &reference.headers);

    EndpointReport {
        name: name.to_string(),
        status_match,
        rust_status: rust.status,
        ref_status: reference.status,
        shape_diffs,
        unexpected_shape_diffs,
        cookie_diffs,
        header_diffs,
    }
}

pub fn print_report(title: &str, reports: &[EndpointReport]) {
    eprintln!("\n╔══════════════════════════════════════════════════════╗");
    eprintln!(
        "║ {:<52} ║",
        format!("Dual-Server Alignment Report ({title})")
    );
    eprintln!("╚══════════════════════════════════════════════════════╝\n");

    let mut total_pass = 0;
    let mut total_fail = 0;

    for report in reports {
        let icon = if report.is_pass() { "PASS" } else { "FAIL" };
        if report.is_pass() {
            total_pass += 1;
        } else {
            total_fail += 1;
        }

        eprintln!(
            "[{}] {} (status: Rust={} Ref={})",
            icon, report.name, report.rust_status, report.ref_status
        );

        if !report.status_match {
            eprintln!(
                "      STATUS MISMATCH: Rust={}, Ref={}",
                report.rust_status, report.ref_status
            );
        }

        if !report.shape_diffs.is_empty() {
            for diff in &report.shape_diffs {
                let is_known = !report.unexpected_shape_diffs.contains(diff);
                let marker = if is_known { "known" } else { "UNEXPECTED" };
                eprintln!("      [{marker}] shape: {diff}");
            }
        }

        for diff in &report.cookie_diffs {
            eprintln!("      [COOKIE] {diff}");
        }
        for diff in &report.header_diffs {
            eprintln!("      [HEADER] {diff}");
        }
    }

    eprintln!();
    eprintln!(
        "Summary: {} passed, {} failed out of {} endpoints",
        total_pass,
        total_fail,
        reports.len()
    );
    eprintln!("─────────────────────────────────────────────────────\n");
}

pub fn log_alignment_gaps(reports: &[EndpointReport]) {
    let gaps: Vec<_> = reports.iter().filter(|report| !report.is_pass()).collect();
    if gaps.is_empty() {
        return;
    }
    eprintln!(
        "[alignment] {} endpoint(s) have alignment gaps:",
        gaps.len()
    );
    for report in &gaps {
        if !report.status_match {
            eprintln!(
                "  - {}: status Rust={} Ref={}",
                report.name, report.rust_status, report.ref_status
            );
        }
        for diff in &report.unexpected_shape_diffs {
            eprintln!("  - {}: shape: {}", report.name, diff);
        }
        for diff in &report.cookie_diffs {
            eprintln!("  - {}: cookie: {}", report.name, diff);
        }
        for diff in &report.header_diffs {
            eprintln!("  - {}: header: {}", report.name, diff);
        }
    }
}

pub fn assert_report_pass(report: EndpointReport) {
    if !report.is_pass() {
        print_report("unexpected diff", std::slice::from_ref(&report));
    }
    assert!(report.is_pass(), "{} should match exactly", report.name);
}

pub fn expect_status(response: &FullResponse, status: StatusCode, context: &str) {
    assert_eq!(
        response.status,
        status.as_u16(),
        "{} expected status {}, got {} with body {}",
        context,
        status,
        response.status,
        response.body
    );
}

pub async fn get_session_status(auth: &TestAuth, token: &str) -> u16 {
    rust_send(auth, get_with_auth("/get-session", token))
        .await
        .status
}

pub fn expired_at(minutes_ago: i64) -> DateTime<Utc> {
    Utc::now() - ChronoDuration::minutes(minutes_ago)
}

pub fn future_at(hours_from_now: i64) -> DateTime<Utc> {
    Utc::now() + ChronoDuration::hours(hours_from_now)
}
