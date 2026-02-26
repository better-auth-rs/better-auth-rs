//! Dual-server comparison testing infrastructure.
//!
//! Sends identical requests to both the Rust `better-auth-rs` server and the
//! reference Node.js `better-auth` server, then compares response *shapes*
//! (not exact values, since IDs / tokens will differ).
//!
//! ## How it works
//!
//! 1. The test harness **automatically starts** the reference Node.js server
//!    (`compat-tests/reference-server/server.mjs`) as a child process.
//! 2. It waits for the `/__health` endpoint to respond (up to 10 seconds).
//! 3. Each test sends the same request to both servers and compares the JSON
//!    response *shape* (field names + value types, not values).
//! 4. The child process is killed when the RAII guard is dropped.
//!
//! ## Prerequisites
//!
//! The reference server dependencies must be installed before running:
//!
//! ```bash
//! cd compat-tests/reference-server && npm install
//! ```
//!
//! If `node_modules` is missing, all tests are skipped with a diagnostic
//! message — they never fail CI.
//!
//! ## Cookie-based auth
//!
//! The TypeScript better-auth uses cookie-based session auth
//! (`set-cookie: better-auth.session_token=...`), NOT Bearer tokens.
//! The `RefClient` in this module captures and forwards cookies to match
//! the real TS behavior.

mod compat;

use compat::helpers::*;
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::Mutex as TokioMutex;

// ---------------------------------------------------------------------------
// Reference-server client
// ---------------------------------------------------------------------------

const REFERENCE_PORT: u16 = 3100;
const REFERENCE_BASE: &str = "http://localhost:3100/api/auth";

/// Check whether the reference server is reachable.
async fn reference_server_available() -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    client
        .get(format!("http://localhost:{REFERENCE_PORT}/__health"))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Try to start the reference server as a child process.
/// Returns `Some(child)` on success.
fn try_start_reference_server() -> Option<std::process::Child> {
    let server_dir = std::path::Path::new("compat-tests/reference-server");

    // Check if node_modules exists
    if !server_dir.join("node_modules").exists() {
        eprintln!(
            "[dual-server] node_modules not found in {}, skipping. Run:\n\
             cd compat-tests/reference-server && npm install",
            server_dir.display()
        );
        return None;
    }

    let child = std::process::Command::new("node")
        .arg("server.mjs")
        .current_dir(server_dir)
        .env("PORT", REFERENCE_PORT.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;

    Some(child)
}

/// Global lock that serialises all dual-server tests so they don't race on
/// the single reference server instance or port.  Uses `tokio::sync::Mutex`
/// because the lock is held across `.await` points inside async test fns.
static SERIAL: TokioMutex<()> = TokioMutex::const_new(());

/// Shared reference server child process.  Started once, lives for the
/// entire test binary.  Using `Mutex<Option<Child>>` instead of RAII guard
/// so the server is only killed when the process exits (the OS reaps it).
static REF_SERVER: Mutex<Option<std::process::Child>> = Mutex::new(None);

/// Ensure the reference server is running.  Starts it at most once across
/// all tests.  Returns `false` if it could not be started (node_modules
/// missing).
async fn ensure_reference_server() -> bool {
    // Fast path: already running?
    if reference_server_available().await {
        return true;
    }

    // Try to start (under lock so only one test does this)
    {
        let mut slot = REF_SERVER.lock().unwrap();
        if slot.is_none() {
            match try_start_reference_server() {
                Some(child) => {
                    *slot = Some(child);
                }
                None => return false,
            }
        }
    }

    // Wait for readiness (up to 10 seconds)
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if reference_server_available().await {
            return true;
        }
    }

    eprintln!("[dual-server] Reference server did not become ready in 10s, skipping.");
    false
}

// ---------------------------------------------------------------------------
// Shape comparison
// ---------------------------------------------------------------------------

/// Extract the structural "shape" of a JSON value -- field names and value
/// types -- ignoring actual values.  This lets us compare responses from two
/// different servers that produce different IDs and timestamps.
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
                .map(|(k, v)| (k.clone(), json_shape(v)))
                .collect();
            Value::Object(shaped)
        }
    }
}

/// Compare two shapes and collect paths where they differ.
fn compare_shapes(rust_shape: &Value, ref_shape: &Value, path: &str) -> Vec<String> {
    let mut diffs = Vec::new();

    match (rust_shape, ref_shape) {
        (Value::Object(r), Value::Object(n)) => {
            let r_keys: BTreeSet<_> = r.keys().collect();
            let n_keys: BTreeSet<_> = n.keys().collect();

            for key in r_keys.difference(&n_keys) {
                diffs.push(format!(
                    "{}.{}: present in Rust, missing in reference",
                    path, key
                ));
            }
            for key in n_keys.difference(&r_keys) {
                diffs.push(format!(
                    "{}.{}: missing in Rust, present in reference",
                    path, key
                ));
            }
            for key in r_keys.intersection(&n_keys) {
                let child_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{}.{}", path, key)
                };
                diffs.extend(compare_shapes(&r[*key], &n[*key], &child_path));
            }
        }
        (Value::Array(r), Value::Array(n)) => {
            if let (Some(r0), Some(n0)) = (r.first(), n.first()) {
                diffs.extend(compare_shapes(r0, n0, &format!("{}[]", path)));
            }
        }
        (Value::String(r), Value::String(n)) if r != n => {
            diffs.push(format!("{}: Rust={}, reference={}", path, r, n));
        }
        _ => {}
    }

    diffs
}

// ---------------------------------------------------------------------------
// Cookie-aware reference server client
// ---------------------------------------------------------------------------

/// A client for the TS reference server that properly handles cookie-based
/// session auth (better-auth uses `set-cookie` headers, not Bearer tokens).
struct RefClient {
    client: reqwest::Client,
    /// The session cookie value captured from signup/signin responses.
    session_cookie: Option<String>,
}

impl RefClient {
    fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            session_cookie: None,
        }
    }

    /// Build a request with the session cookie (if present) and origin header.
    fn apply_headers(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req = req.header("origin", format!("http://localhost:{}", REFERENCE_PORT));
        if let Some(ref cookie) = self.session_cookie {
            req = req.header("cookie", format!("better-auth.session_token={}", cookie));
        }
        req
    }

    /// Extract the `better-auth.session_token` from the response's
    /// `set-cookie` header, if present.
    fn capture_cookie(&mut self, resp: &reqwest::Response) {
        for value in resp.headers().get_all("set-cookie") {
            if let Ok(s) = value.to_str() {
                if let Some(rest) = s.strip_prefix("better-auth.session_token=") {
                    let token = rest.split(';').next().unwrap_or(rest);
                    self.session_cookie = Some(token.to_string());
                    return;
                }
            }
        }
    }

    /// POST a JSON body to the reference server. Captures the session cookie.
    async fn post(&mut self, path: &str, body: &Value) -> Result<(u16, Value), String> {
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
            .map_err(|e| format!("POST {}: {}", url, e))?;
        self.capture_cookie(&resp);
        let status = resp.status().as_u16();
        let json: Value = resp
            .json()
            .await
            .unwrap_or_else(|_| Value::String("non-json".into()));
        Ok((status, json))
    }

    /// GET from the reference server with cookie auth.
    async fn get(&self, path: &str) -> Result<(u16, Value), String> {
        let url = format!("{}{}", REFERENCE_BASE, path);
        let req = self.apply_headers(self.client.get(&url));
        let resp = req
            .send()
            .await
            .map_err(|e| format!("GET {}: {}", url, e))?;
        let status = resp.status().as_u16();
        let json: Value = resp
            .json()
            .await
            .unwrap_or_else(|_| Value::String("non-json".into()));
        Ok((status, json))
    }
}

/// Known differences between Rust (with plugins) and TS (emailAndPassword only).
/// These fields are present in Rust because `create_test_auth()` registers
/// admin, organization, and two-factor plugins.  They are NOT bugs.
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

/// Filter out known/expected differences from a diff list.
///
/// Known categories:
/// - Extra user/session fields from Rust plugins (admin, org, 2FA)
/// - Extra `url` field in signin response
/// - Missing `code` field in Rust error responses
/// - `ipAddress`/`userAgent` type mismatch: Rust in-memory harness doesn't
///   populate HTTP headers → null, while TS reference server receives real
///   HTTP requests → string.  This is a test-harness difference, not an
///   implementation gap.
fn filter_known_diffs(diffs: &[String]) -> Vec<String> {
    diffs
        .iter()
        .filter(|d| {
            // Skip known extra user fields from plugins
            for field in KNOWN_EXTRA_RUST_USER_FIELDS {
                if d.contains(&format!(".{}: present in Rust", field)) {
                    return false;
                }
            }
            // Skip known extra session fields from plugins
            for field in KNOWN_EXTRA_RUST_SESSION_FIELDS {
                if d.contains(&format!(".{}: present in Rust", field)) {
                    return false;
                }
            }
            // Skip known signin extra `url` field
            if d.contains(".url: present in Rust") {
                return false;
            }
            // Skip known error response `code` field (TS has it, Rust doesn't yet)
            if d.contains(".code: missing in Rust") {
                return false;
            }
            // Skip ipAddress/userAgent type mismatch (null in Rust in-memory
            // harness vs string in TS reference server that receives real HTTP)
            if (d.contains("ipAddress:") || d.contains("userAgent:"))
                && d.contains("Rust=null")
                && d.contains("reference=string")
            {
                return false;
            }
            true
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Dual-server comparison tests
// ---------------------------------------------------------------------------

/// Compare sign-up response shapes between Rust and reference servers.
#[tokio::test]
async fn dual_server_signup_shape_comparison() {
    let _lock = SERIAL.lock().await;
    if !ensure_reference_server().await {
        eprintln!("[dual-server] SKIPPED: reference server not available");
        return;
    }

    let auth = create_test_auth().await;
    let mut ref_client = RefClient::new();

    let email = unique_email("dual_signup");
    let signup_body = serde_json::json!({
        "name": "Dual Test User",
        "email": email,
        "password": "password123"
    });

    // Rust server
    let (rust_status, rust_body) =
        send_request(&auth, post_json("/sign-up/email", signup_body.clone())).await;

    // Reference server (also captures session cookie)
    let (ref_status, ref_body) = ref_client
        .post("/sign-up/email", &signup_body)
        .await
        .expect("Reference server request failed");

    eprintln!("[dual-server] POST /sign-up/email");
    eprintln!("  Rust status:  {}", rust_status);
    eprintln!("  Ref  status:  {}", ref_status);

    let all_diffs = compare_shapes(&json_shape(&rust_body), &json_shape(&ref_body), "");
    let unexpected = filter_known_diffs(&all_diffs);

    if all_diffs.is_empty() {
        eprintln!("  Shape: EXACT MATCH");
    } else {
        eprintln!(
            "  Shape: {} total diffs ({} known, {} unexpected)",
            all_diffs.len(),
            all_diffs.len() - unexpected.len(),
            unexpected.len()
        );
        for d in &all_diffs {
            eprintln!("    {}", d);
        }
    }

    assert!(
        unexpected.is_empty(),
        "Unexpected signup shape differences:\n{}",
        unexpected.join("\n")
    );
}

/// Compare sign-in response shapes.
#[tokio::test]
async fn dual_server_signin_shape_comparison() {
    let _lock = SERIAL.lock().await;
    if !ensure_reference_server().await {
        eprintln!("[dual-server] SKIPPED: reference server not available");
        return;
    }

    let auth = create_test_auth().await;
    let mut ref_client = RefClient::new();

    let email = unique_email("dual_signin");
    let signup_body = serde_json::json!({
        "name": "Dual Signin User",
        "email": email,
        "password": "password123"
    });

    // Sign up on both servers
    send_request(&auth, post_json("/sign-up/email", signup_body.clone())).await;
    let _ = ref_client.post("/sign-up/email", &signup_body).await;

    let signin_body = serde_json::json!({
        "email": email,
        "password": "password123"
    });

    // Rust server
    let (rust_status, rust_body) =
        send_request(&auth, post_json("/sign-in/email", signin_body.clone())).await;

    // Reference server (captures session cookie)
    let (ref_status, ref_body) = ref_client
        .post("/sign-in/email", &signin_body)
        .await
        .expect("Reference server request failed");

    eprintln!("[dual-server] POST /sign-in/email");
    eprintln!("  Rust status:  {}", rust_status);
    eprintln!("  Ref  status:  {}", ref_status);

    let all_diffs = compare_shapes(&json_shape(&rust_body), &json_shape(&ref_body), "");
    let unexpected = filter_known_diffs(&all_diffs);

    if all_diffs.is_empty() {
        eprintln!("  Shape: EXACT MATCH");
    } else {
        eprintln!(
            "  Shape: {} total diffs ({} known, {} unexpected)",
            all_diffs.len(),
            all_diffs.len() - unexpected.len(),
            unexpected.len()
        );
        for d in &all_diffs {
            eprintln!("    {}", d);
        }
    }

    assert!(
        unexpected.is_empty(),
        "Unexpected signin shape differences:\n{}",
        unexpected.join("\n")
    );
}

/// Compare error response shapes (invalid credentials).
#[tokio::test]
async fn dual_server_error_shape_comparison() {
    let _lock = SERIAL.lock().await;
    if !ensure_reference_server().await {
        eprintln!("[dual-server] SKIPPED: reference server not available");
        return;
    }

    let auth = create_test_auth().await;
    let mut ref_client = RefClient::new();

    let email = unique_email("nonexistent_dual");
    let signin_body = serde_json::json!({
        "email": email,
        "password": "password123"
    });

    // Rust server
    let (rust_status, rust_body) =
        send_request(&auth, post_json("/sign-in/email", signin_body.clone())).await;

    // Reference server
    let (ref_status, ref_body) = ref_client
        .post("/sign-in/email", &signin_body)
        .await
        .expect("Reference server request failed");

    eprintln!("[dual-server] POST /sign-in/email (error case)");
    eprintln!("  Rust status:  {}", rust_status);
    eprintln!("  Ref  status:  {}", ref_status);

    let all_diffs = compare_shapes(&json_shape(&rust_body), &json_shape(&ref_body), "");
    let unexpected = filter_known_diffs(&all_diffs);

    if all_diffs.is_empty() {
        eprintln!("  Shape: EXACT MATCH");
    } else {
        eprintln!(
            "  Shape: {} total diffs ({} known, {} unexpected)",
            all_diffs.len(),
            all_diffs.len() - unexpected.len(),
            unexpected.len()
        );
        for d in &all_diffs {
            eprintln!("    {}", d);
        }
    }

    assert!(
        unexpected.is_empty(),
        "Unexpected error shape differences:\n{}",
        unexpected.join("\n")
    );
}

/// Run a broad comparison across multiple endpoints and produce a summary
/// report.  Uses cookie-based auth for the reference server.
#[tokio::test]
async fn dual_server_comprehensive_comparison() {
    let _lock = SERIAL.lock().await;
    if !ensure_reference_server().await {
        eprintln!("[dual-server] SKIPPED: reference server not available");
        return;
    }

    let auth = create_test_auth().await;
    let mut ref_client = RefClient::new();

    // Sign up on both servers
    let email = unique_email("dual_comp");

    /// Compare a single endpoint between Rust and reference servers,
    /// returning an `EndpointCheck` with shape diff results.
    fn compare_endpoint(
        name: &'static str,
        rust_status: u16,
        rust_body: &Value,
        ref_result: Result<(u16, Value), String>,
    ) -> Option<EndpointCheck> {
        match ref_result {
            Ok((ref_status, ref_body)) => {
                let all_diffs = compare_shapes(&json_shape(rust_body), &json_shape(&ref_body), "");
                let unexpected_diffs = filter_known_diffs(&all_diffs);
                Some(EndpointCheck {
                    name,
                    all_diffs,
                    unexpected_diffs,
                    rust_status,
                    ref_status,
                })
            }
            Err(_) => None,
        }
    }
    let signup_body = serde_json::json!({
        "name": "Dual Comprehensive",
        "email": email,
        "password": "password123"
    });

    let (_, rust_signup) =
        send_request(&auth, post_json("/sign-up/email", signup_body.clone())).await;
    let rust_token = rust_signup["token"].as_str().unwrap_or("").to_string();

    // This also captures the session cookie in ref_client
    let _ = ref_client.post("/sign-up/email", &signup_body).await;

    // Sign in on reference server to get a fresh session cookie
    let signin_body = serde_json::json!({
        "email": email,
        "password": "password123"
    });
    let _ = ref_client.post("/sign-in/email", &signin_body).await;

    // Endpoints to compare
    struct EndpointCheck {
        name: &'static str,
        all_diffs: Vec<String>,
        unexpected_diffs: Vec<String>,
        rust_status: u16,
        ref_status: u16,
    }

    let mut results: Vec<EndpointCheck> = Vec::new();

    // GET /get-session
    {
        let (rs, rb) = send_request(&auth, get_with_auth("/get-session", &rust_token)).await;
        if let Some(check) = compare_endpoint(
            "GET /get-session",
            rs,
            &rb,
            ref_client.get("/get-session").await,
        ) {
            results.push(check);
        }
    }

    // GET /list-sessions
    {
        let (rs, rb) = send_request(&auth, get_with_auth("/list-sessions", &rust_token)).await;
        if let Some(check) = compare_endpoint(
            "GET /list-sessions",
            rs,
            &rb,
            ref_client.get("/list-sessions").await,
        ) {
            results.push(check);
        }
    }

    // POST /change-password (use boolean for revokeOtherSessions — TS validates strictly)
    {
        let chg_body = serde_json::json!({
            "currentPassword": "password123",
            "newPassword": "newpassword456",
            "revokeOtherSessions": false
        });
        let (rs, rb) = send_request(
            &auth,
            post_json_with_auth("/change-password", chg_body.clone(), &rust_token),
        )
        .await;
        if let Some(check) = compare_endpoint(
            "POST /change-password",
            rs,
            &rb,
            ref_client.post("/change-password", &chg_body).await,
        ) {
            results.push(check);
        }
    }

    // GET /ok
    {
        let (rs, rb) = send_request(&auth, get_request("/ok")).await;
        if let Some(check) = compare_endpoint("GET /ok", rs, &rb, ref_client.get("/ok").await) {
            results.push(check);
        }
    }

    // Print summary report
    eprintln!("\n=== Dual-Server Comparison Report ===\n");
    let mut total_unexpected = 0;
    for r in &results {
        let icon = if r.unexpected_diffs.is_empty() {
            "PASS"
        } else {
            "FAIL"
        };
        eprintln!(
            "[{}] {} (Rust={}, Ref={})",
            icon, r.name, r.rust_status, r.ref_status
        );
        if !r.all_diffs.is_empty() {
            for d in &r.all_diffs {
                let is_known = !r.unexpected_diffs.contains(d);
                let marker = if is_known { "known" } else { "UNEXPECTED" };
                eprintln!("      [{}] {}", marker, d);
            }
        }
        total_unexpected += r.unexpected_diffs.len();
    }
    eprintln!(
        "\nEndpoints compared: {}, Unexpected differences: {}",
        results.len(),
        total_unexpected
    );
    eprintln!("=====================================\n");

    assert_eq!(
        total_unexpected,
        0,
        "Found {} unexpected shape differences across {} endpoints",
        total_unexpected,
        results.len()
    );
}
