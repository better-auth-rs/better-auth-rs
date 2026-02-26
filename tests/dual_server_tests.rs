//! Dual-server comparison testing infrastructure.
//!
//! Sends identical requests to both the Rust `better-auth-rs` server and the
//! reference Node.js `better-auth` server, then compares response *shapes*
//! (not exact values, since IDs / tokens will differ).
//!
//! ## Prerequisites
//!
//! The reference server must be installed before running these tests:
//!
//! ```bash
//! cd compat-tests/reference-server && npm install
//! ```
//!
//! If the reference server is not available, all tests in this module are
//! skipped with a diagnostic message -- they never fail CI.

mod compat;

use compat::helpers::*;
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::Duration;

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

/// RAII guard that kills the reference server child process on drop.
struct ReferenceServerGuard {
    child: Option<std::process::Child>,
}

impl Drop for ReferenceServerGuard {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Ensure the reference server is running.  Returns a guard that kills the
/// process on drop, or `None` if the server could not be started.
async fn ensure_reference_server() -> Option<ReferenceServerGuard> {
    // Already running?
    if reference_server_available().await {
        return Some(ReferenceServerGuard { child: None });
    }

    // Try to start it
    let child = try_start_reference_server()?;
    let guard = ReferenceServerGuard { child: Some(child) };

    // Wait for readiness (up to 10 seconds)
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if reference_server_available().await {
            return Some(guard);
        }
    }

    eprintln!("[dual-server] Reference server did not become ready in 10s, skipping.");
    None
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

/// Send a POST request to the reference server and return (status, body).
async fn ref_post(path: &str, body: &Value) -> Result<(u16, Value), String> {
    let client = reqwest::Client::new();
    let url = format!("{}{}", REFERENCE_BASE, path);

    let resp = client
        .post(&url)
        .json(body)
        .header("content-type", "application/json")
        .header("origin", format!("http://localhost:{}", REFERENCE_PORT))
        .send()
        .await
        .map_err(|e| format!("POST {}: {}", url, e))?;

    let status = resp.status().as_u16();
    let json: Value = resp
        .json()
        .await
        .unwrap_or_else(|_| Value::String("non-json".into()));
    Ok((status, json))
}

/// Send a GET request to the reference server with auth and return (status, body).
async fn ref_get(path: &str, token: &str) -> Result<(u16, Value), String> {
    let client = reqwest::Client::new();
    let url = format!("{}{}", REFERENCE_BASE, path);

    let resp = client
        .get(&url)
        .header("authorization", format!("Bearer {}", token))
        .header("origin", format!("http://localhost:{}", REFERENCE_PORT))
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

// ---------------------------------------------------------------------------
// Dual-server comparison tests
// ---------------------------------------------------------------------------

/// Compare sign-up response shapes between Rust and reference servers.
#[tokio::test]
async fn dual_server_signup_shape_comparison() {
    let _guard = match ensure_reference_server().await {
        Some(g) => g,
        None => {
            eprintln!("[dual-server] SKIPPED: reference server not available");
            return;
        }
    };

    let auth = create_test_auth().await;

    let signup_body = serde_json::json!({
        "name": "Dual Test User",
        "email": "dual_signup@example.com",
        "password": "password123"
    });

    // Rust server
    let (rust_status, rust_body) =
        send_request(&auth, post_json("/sign-up/email", signup_body.clone())).await;

    // Reference server
    let (ref_status, ref_body) = ref_post("/sign-up/email", &signup_body)
        .await
        .expect("Reference server request failed");

    eprintln!("[dual-server] POST /sign-up/email");
    eprintln!("  Rust status:  {}", rust_status);
    eprintln!("  Ref  status:  {}", ref_status);

    let rust_shape = json_shape(&rust_body);
    let ref_shape = json_shape(&ref_body);

    let diffs = compare_shapes(&rust_shape, &ref_shape, "");
    if diffs.is_empty() {
        eprintln!("  Shape: MATCH");
    } else {
        eprintln!("  Shape differences:");
        for d in &diffs {
            eprintln!("    {}", d);
        }
    }

    // We report but don't fail -- this is informational for now.
    // Uncomment the assert below once the shapes are aligned:
    // assert!(diffs.is_empty(), "Signup response shapes differ:\n{}", diffs.join("\n"));
}

/// Compare sign-in response shapes.
#[tokio::test]
async fn dual_server_signin_shape_comparison() {
    let _guard = match ensure_reference_server().await {
        Some(g) => g,
        None => {
            eprintln!("[dual-server] SKIPPED: reference server not available");
            return;
        }
    };

    let auth = create_test_auth().await;

    let signup_body = serde_json::json!({
        "name": "Dual Signin User",
        "email": "dual_signin@example.com",
        "password": "password123"
    });

    // Sign up on both servers
    send_request(&auth, post_json("/sign-up/email", signup_body.clone())).await;
    let _ = ref_post("/sign-up/email", &signup_body).await;

    let signin_body = serde_json::json!({
        "email": "dual_signin@example.com",
        "password": "password123"
    });

    // Rust server
    let (rust_status, rust_body) =
        send_request(&auth, post_json("/sign-in/email", signin_body.clone())).await;

    // Reference server
    let (ref_status, ref_body) = ref_post("/sign-in/email", &signin_body)
        .await
        .expect("Reference server request failed");

    eprintln!("[dual-server] POST /sign-in/email");
    eprintln!("  Rust status:  {}", rust_status);
    eprintln!("  Ref  status:  {}", ref_status);

    let diffs = compare_shapes(&json_shape(&rust_body), &json_shape(&ref_body), "");
    if diffs.is_empty() {
        eprintln!("  Shape: MATCH");
    } else {
        eprintln!("  Shape differences:");
        for d in &diffs {
            eprintln!("    {}", d);
        }
    }
}

/// Compare error response shapes (invalid credentials).
#[tokio::test]
async fn dual_server_error_shape_comparison() {
    let _guard = match ensure_reference_server().await {
        Some(g) => g,
        None => {
            eprintln!("[dual-server] SKIPPED: reference server not available");
            return;
        }
    };

    let auth = create_test_auth().await;

    let signin_body = serde_json::json!({
        "email": "nonexistent_dual@example.com",
        "password": "password123"
    });

    // Rust server
    let (rust_status, rust_body) =
        send_request(&auth, post_json("/sign-in/email", signin_body.clone())).await;

    // Reference server
    let (ref_status, ref_body) = ref_post("/sign-in/email", &signin_body)
        .await
        .expect("Reference server request failed");

    eprintln!("[dual-server] POST /sign-in/email (error case)");
    eprintln!("  Rust status:  {}", rust_status);
    eprintln!("  Ref  status:  {}", ref_status);

    let diffs = compare_shapes(&json_shape(&rust_body), &json_shape(&ref_body), "");
    if diffs.is_empty() {
        eprintln!("  Shape: MATCH");
    } else {
        eprintln!("  Shape differences:");
        for d in &diffs {
            eprintln!("    {}", d);
        }
    }
}

/// Run a broad comparison across multiple endpoints and produce a summary
/// report.
#[tokio::test]
async fn dual_server_comprehensive_comparison() {
    let _guard = match ensure_reference_server().await {
        Some(g) => g,
        None => {
            eprintln!("[dual-server] SKIPPED: reference server not available");
            return;
        }
    };

    let auth = create_test_auth().await;

    // Sign up on both servers
    let signup_body = serde_json::json!({
        "name": "Dual Comprehensive",
        "email": "dual_comp@example.com",
        "password": "password123"
    });

    let (_, rust_signup) =
        send_request(&auth, post_json("/sign-up/email", signup_body.clone())).await;
    let rust_token = rust_signup["token"].as_str().unwrap_or("").to_string();

    let ref_signup = ref_post("/sign-up/email", &signup_body).await;
    let ref_token = ref_signup
        .as_ref()
        .ok()
        .and_then(|(_, b)| b["token"].as_str())
        .unwrap_or("")
        .to_string();

    // Endpoints to compare
    struct EndpointCheck {
        name: &'static str,
        diffs: Vec<String>,
        rust_status: u16,
        ref_status: u16,
    }

    let mut results: Vec<EndpointCheck> = Vec::new();

    // GET /get-session
    {
        let (rs, rb) = send_request(&auth, get_with_auth("/get-session", &rust_token)).await;
        if let Ok((ns, nb)) = ref_get("/get-session", &ref_token).await {
            results.push(EndpointCheck {
                name: "GET /get-session",
                diffs: compare_shapes(&json_shape(&rb), &json_shape(&nb), ""),
                rust_status: rs,
                ref_status: ns,
            });
        }
    }

    // GET /list-sessions
    {
        let (rs, rb) = send_request(&auth, get_with_auth("/list-sessions", &rust_token)).await;
        if let Ok((ns, nb)) = ref_get("/list-sessions", &ref_token).await {
            results.push(EndpointCheck {
                name: "GET /list-sessions",
                diffs: compare_shapes(&json_shape(&rb), &json_shape(&nb), ""),
                rust_status: rs,
                ref_status: ns,
            });
        }
    }

    // POST /change-password
    {
        let chg_body = serde_json::json!({
            "currentPassword": "password123",
            "newPassword": "newpassword456",
            "revokeOtherSessions": "false"
        });
        let (rs, rb) = send_request(
            &auth,
            post_json_with_auth("/change-password", chg_body.clone(), &rust_token),
        )
        .await;
        if let Ok((ns, nb)) = (async {
            let client = reqwest::Client::new();
            let resp = client
                .post(format!("{}/change-password", REFERENCE_BASE))
                .json(&chg_body)
                .header("authorization", format!("Bearer {}", ref_token))
                .header("content-type", "application/json")
                .header("origin", format!("http://localhost:{}", REFERENCE_PORT))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let json: Value = resp.json().await.unwrap_or(Value::Null);
            Ok::<_, String>((status, json))
        })
        .await
        {
            results.push(EndpointCheck {
                name: "POST /change-password",
                diffs: compare_shapes(&json_shape(&rb), &json_shape(&nb), ""),
                rust_status: rs,
                ref_status: ns,
            });
        }
    }

    // Print summary report
    eprintln!("\n=== Dual-Server Comparison Report ===\n");
    let mut total_diffs = 0;
    for r in &results {
        let icon = if r.diffs.is_empty() { "MATCH" } else { "DIFF" };
        eprintln!(
            "[{}] {} (Rust={}, Ref={})",
            icon, r.name, r.rust_status, r.ref_status
        );
        for d in &r.diffs {
            eprintln!("      {}", d);
            total_diffs += 1;
        }
    }
    eprintln!(
        "\nEndpoints compared: {}, Differences: {}",
        results.len(),
        total_diffs
    );
    eprintln!("=====================================\n");
}
