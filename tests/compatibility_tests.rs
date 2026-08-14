//! Compatibility tests that compare our implementation against the
//! generated upstream OpenAPI contract from the pinned Better Auth package.
//!
//! These tests ensure route coverage and response shape alignment with
//! the canonical Better-Auth TypeScript implementation.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "compatibility tests intentionally use panic-on-failure assertions and direct JSON indexing for contract checks"
)]

mod compat;

use std::collections::{BTreeMap, HashSet};

use better_auth::{
    AuthBuilder, AuthConfig, BetterAuth,
    plugins::EmailPasswordPlugin,
    prelude::{AuthRequest, HttpMethod},
};
use better_auth_seaorm::{Database, DatabaseConnection, SeaOrmStore};
use serde_json::Value;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse the generated upstream OpenAPI and return a map of path → set of HTTP methods.
fn load_reference_spec() -> BTreeMap<String, HashSet<String>> {
    let spec =
        compat::schema::load_openapi_spec_with_profile(compat::schema::OpenApiProfile::AllIn);
    let paths = spec.paths.as_ref().expect("generated spec must have paths");

    let mut result = BTreeMap::new();
    for (path, methods) in paths {
        let mut method_set = HashSet::new();
        if methods.get.is_some() {
            let _ = method_set.insert("get".to_string());
        }
        if methods.post.is_some() {
            let _ = method_set.insert("post".to_string());
        }
        if methods.put.is_some() {
            let _ = method_set.insert("put".to_string());
        }
        if methods.delete.is_some() {
            let _ = method_set.insert("delete".to_string());
        }
        if methods.patch.is_some() {
            let _ = method_set.insert("patch".to_string());
        }
        if methods.options.is_some() {
            let _ = method_set.insert("options".to_string());
        }
        if methods.head.is_some() {
            let _ = method_set.insert("head".to_string());
        }
        let _ = result.insert(path.clone(), method_set);
    }
    result
}

fn completed_phase_reference_surface(
    reference: &BTreeMap<String, HashSet<String>>,
) -> BTreeMap<String, HashSet<String>> {
    let mut surface: BTreeMap<String, HashSet<String>> = [
        "/ok",
        "/error",
        "/sign-up/email",
        "/sign-in/email",
        "/get-session",
        "/sign-out",
        "/list-sessions",
        "/revoke-session",
        "/revoke-sessions",
        "/revoke-other-sessions",
        "/refresh-token",
        "/get-access-token",
        "/request-password-reset",
        "/reset-password",
        "/reset-password/{token}",
        "/change-password",
        "/verify-password",
        "/update-user",
        "/delete-user",
        "/delete-user/callback",
        "/change-email",
        "/send-verification-email",
        "/verify-email",
        "/sign-in/social",
        "/link-social",
        "/list-accounts",
        "/unlink-account",
        "/account-info",
        "/device/code",
        "/device/token",
        "/device",
        "/device/approve",
        "/device/deny",
        "/api-key/create",
        "/api-key/get",
        "/api-key/list",
        "/api-key/update",
        "/api-key/delete",
    ]
    .into_iter()
    .map(|path| {
        (
            path.to_string(),
            reference
                .get(path)
                .unwrap_or_else(|| panic!("reference spec missing completed-phase path {}", path))
                .clone(),
        )
    })
    .collect();

    // The pinned TS runtime exposes `/callback/{provider}` publicly, but the
    // generated OpenAPI profile omits it. Treat it as a completed-phase
    // runtime route and assert it explicitly until the structural profile
    // catches up.
    let _ = surface.insert(
        "/callback/{provider}".to_string(),
        HashSet::from(["get".to_string(), "post".to_string()]),
    );
    // The pinned TS runtime exposes `/sign-in/username` and
    // `/is-username-available` publicly when the username plugin is enabled,
    // but the generated OpenAPI profile omits them.
    let _ = surface.insert(
        "/sign-in/username".to_string(),
        HashSet::from(["post".to_string()]),
    );
    let _ = surface.insert(
        "/is-username-available".to_string(),
        HashSet::from(["post".to_string()]),
    );

    surface
}

/// Create a test auth instance with all currently implemented plugins.
async fn test_database() -> DatabaseConnection {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    database
}

async fn create_full_auth() -> BetterAuth<TestSchema> {
    let config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000")
        .password_min_length(8);

    let store = SeaOrmStore::<TestSchema>::new(config.clone(), test_database().await);

    AuthBuilder::<TestSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(better_auth::plugins::SessionManagementPlugin::new())
        .plugin(better_auth::plugins::PasswordManagementPlugin::new())
        .plugin(better_auth::plugins::EmailVerificationPlugin::new())
        .plugin(
            better_auth::plugins::UserManagementPlugin::new()
                .change_email_enabled(true)
                .delete_user_enabled(true)
                .require_delete_verification(false),
        )
        .plugin(better_auth::plugins::AccountManagementPlugin::new())
        .plugin(better_auth::plugins::OAuthPlugin::new())
        .plugin(better_auth::plugins::DeviceAuthorizationPlugin::new())
        .plugin(better_auth::plugins::TwoFactorPlugin::new())
        .plugin(better_auth::plugins::ApiKeyPlugin::builder().build())
        .build()
        .await
        .expect("Failed to create test auth instance")
}

/// Collect all routes our implementation exposes (core + plugin).
fn collect_implemented_routes(auth: &BetterAuth<TestSchema>) -> BTreeMap<String, HashSet<String>> {
    let mut routes: BTreeMap<String, HashSet<String>> = BTreeMap::new();

    // Core routes (from handle_core_request)
    let core = vec![("/ok", "get"), ("/error", "get"), ("/update-user", "post")];
    for (path, method) in core {
        let _ = routes
            .entry(path.to_string())
            .or_default()
            .insert(method.to_string());
    }

    // Plugin routes
    for plugin in auth.plugins() {
        for route in plugin.routes() {
            let method_str = match route.method {
                HttpMethod::Get => "get",
                HttpMethod::Post => "post",
                HttpMethod::Put => "put",
                HttpMethod::Delete => "delete",
                HttpMethod::Patch => "patch",
                HttpMethod::Options => "options",
                HttpMethod::Head => "head",
            };
            let _ = routes
                .entry(route.path.clone())
                .or_default()
                .insert(method_str.to_string());
        }
    }

    routes
}

// ---------------------------------------------------------------------------
// Schema Diff Tests
// ---------------------------------------------------------------------------

/// Verify the reference spec can be parsed and has a reasonable number of endpoints.
#[test]
fn test_reference_spec_loads() {
    let spec = load_reference_spec();
    assert!(
        spec.len() >= 50,
        "Reference spec should have at least 50 paths, got {}",
        spec.len()
    );
}

/// Print a coverage report showing which reference endpoints are implemented.
/// This test always passes but prints useful diagnostics.
#[tokio::test]
async fn test_route_coverage_report() {
    let reference = load_reference_spec();
    let auth = create_full_auth().await;
    let implemented = collect_implemented_routes(&auth);

    let mut covered = 0;
    let mut missing = Vec::new();
    let mut extra = Vec::new();
    let total_ref_endpoints: usize = reference.values().map(|m| m.len()).sum();

    for (path, ref_methods) in &reference {
        if let Some(impl_methods) = implemented.get(path) {
            for method in ref_methods {
                if impl_methods.contains(method) {
                    covered += 1;
                } else {
                    missing.push(format!("{} {}", method.to_uppercase(), path));
                }
            }
        } else {
            for method in ref_methods {
                missing.push(format!("{} {}", method.to_uppercase(), path));
            }
        }
    }

    // Find routes we have that aren't in the reference
    for (path, impl_methods) in &implemented {
        if let Some(ref_methods) = reference.get(path) {
            for method in impl_methods {
                if !ref_methods.contains(method) {
                    extra.push(format!("{} {}", method.to_uppercase(), path));
                }
            }
        } else {
            for method in impl_methods {
                extra.push(format!("{} {}", method.to_uppercase(), path));
            }
        }
    }

    let coverage_pct = if total_ref_endpoints > 0 {
        (covered as f64 / total_ref_endpoints as f64) * 100.0
    } else {
        0.0
    };

    eprintln!("=== Route Coverage Report ===");
    eprintln!("Reference endpoints: {}", total_ref_endpoints);
    eprintln!("Implemented:         {}", covered);
    eprintln!("Missing:             {}", missing.len());
    eprintln!("Extra (non-ref):     {}", extra.len());
    eprintln!("Coverage:            {:.1}%", coverage_pct);
    eprintln!();

    if !missing.is_empty() {
        eprintln!("--- Missing endpoints ---");
        for m in &missing {
            eprintln!("  [ ] {}", m);
        }
    }
    if !extra.is_empty() {
        eprintln!("--- Extra endpoints (not in reference) ---");
        for e in &extra {
            eprintln!("  [+] {}", e);
        }
    }
    eprintln!("=============================");
}

#[tokio::test]
async fn test_completed_phase_surface_matches_reference_exactly() {
    let reference = load_reference_spec();
    let expected = completed_phase_reference_surface(&reference);
    let auth = create_full_auth().await;
    let implemented = collect_implemented_routes(&auth);

    let mut missing = Vec::new();
    let mut extra = Vec::new();

    for (path, expected_methods) in &expected {
        match implemented.get(path) {
            Some(actual_methods) => {
                for method in expected_methods {
                    if !actual_methods.contains(method) {
                        missing.push(format!("{} {}", method.to_uppercase(), path));
                    }
                }
                for method in actual_methods {
                    if !expected_methods.contains(method) {
                        extra.push(format!("{} {}", method.to_uppercase(), path));
                    }
                }
            }
            None => {
                for method in expected_methods {
                    missing.push(format!("{} {}", method.to_uppercase(), path));
                }
            }
        }
    }

    assert!(
        missing.is_empty() && extra.is_empty(),
        "completed phase route drift detected\nmissing:\n{}\nextra:\n{}",
        if missing.is_empty() {
            "<none>".to_string()
        } else {
            missing.join("\n")
        },
        if extra.is_empty() {
            "<none>".to_string()
        } else {
            extra.join("\n")
        }
    );
}

/// Verify that the completed pre-stage-8 endpoints covered by the main surface test exist at all.
#[tokio::test]
async fn test_completed_phase_endpoints_present() {
    let auth = create_full_auth().await;
    let implemented = collect_implemented_routes(&auth);

    let required = vec![
        ("get", "/ok"),
        ("get", "/error"),
        ("post", "/sign-up/email"),
        ("post", "/sign-in/email"),
        ("post", "/sign-in/username"),
        ("post", "/is-username-available"),
        ("get", "/get-session"),
        ("post", "/sign-out"),
        ("post", "/update-user"),
        ("post", "/delete-user"),
        ("post", "/request-password-reset"),
        ("post", "/reset-password"),
        ("post", "/change-password"),
        ("post", "/verify-password"),
        ("post", "/send-verification-email"),
        ("get", "/verify-email"),
        ("get", "/list-sessions"),
        ("post", "/revoke-session"),
        ("post", "/revoke-sessions"),
        ("post", "/revoke-other-sessions"),
        ("post", "/sign-in/social"),
        ("get", "/callback/{provider}"),
        ("post", "/callback/{provider}"),
        ("post", "/link-social"),
        ("get", "/list-accounts"),
        ("post", "/unlink-account"),
        ("get", "/account-info"),
        ("post", "/change-email"),
        ("get", "/delete-user/callback"),
        ("post", "/device/code"),
        ("post", "/device/token"),
        ("get", "/device"),
        ("post", "/device/approve"),
        ("post", "/device/deny"),
        ("post", "/api-key/create"),
        ("get", "/api-key/get"),
        ("get", "/api-key/list"),
        ("post", "/api-key/update"),
        ("post", "/api-key/delete"),
    ];

    let mut missing = Vec::new();
    for (method, path) in &required {
        let found = implemented
            .get(*path)
            .map(|methods| methods.contains(*method))
            .unwrap_or(false);
        if !found {
            missing.push(format!("{} {}", method.to_uppercase(), path));
        }
    }

    assert!(
        missing.is_empty(),
        "Missing required endpoints:\n{}",
        missing.join("\n")
    );
}

/// Verify our generated OpenAPI spec includes all core routes.
#[tokio::test]
async fn test_generated_openapi_has_core_routes() {
    let auth = create_full_auth().await;
    let spec = auth.openapi_spec();

    assert!(spec.paths.contains_key("/ok"), "OpenAPI spec missing /ok");
    assert!(
        spec.paths.contains_key("/error"),
        "OpenAPI spec missing /error"
    );
    assert!(
        spec.paths.contains_key("/update-user"),
        "OpenAPI spec missing /update-user"
    );
    assert!(
        spec.paths.contains_key("/delete-user"),
        "OpenAPI spec missing /delete-user"
    );
    assert!(
        spec.paths.contains_key("/sign-up/email"),
        "OpenAPI spec missing /sign-up/email"
    );
    assert!(
        spec.paths.contains_key("/sign-in/email"),
        "OpenAPI spec missing /sign-in/email"
    );
    assert!(
        spec.paths.contains_key("/verify-password"),
        "OpenAPI spec missing /verify-password"
    );
    assert!(
        spec.paths.contains_key("/account-info"),
        "OpenAPI spec missing /account-info"
    );
}

/// Verify the generated OpenAPI spec version and info fields.
#[tokio::test]
async fn test_generated_openapi_metadata() {
    let auth = create_full_auth().await;
    let spec = auth.openapi_spec();

    assert_eq!(spec.openapi, "3.1.0");
    assert_eq!(spec.info.title, "Better Auth");
    assert!(spec.info.description.is_some());
}

// ---------------------------------------------------------------------------
// Contract Tests — validate response shapes
// ---------------------------------------------------------------------------

/// Helper to send a request and parse the JSON response body.
async fn send_json_request(
    auth: &BetterAuth<TestSchema>,
    method: HttpMethod,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut req = AuthRequest::new(method, path);
    if let Some(b) = body {
        req.body = Some(b.to_string().into_bytes());
        let _ = req
            .headers
            .insert("content-type".to_string(), "application/json".to_string());
    }
    let resp = auth
        .handle_request(req)
        .await
        .expect("Request should not panic");
    let status = resp.status;
    let json: Value = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&resp.body).to_string()));
    (status, json)
}

/// GET /ok should return { "ok": true }
#[tokio::test]
async fn test_contract_ok_endpoint() {
    let auth = create_full_auth().await;
    let (status, body) = send_json_request(&auth, HttpMethod::Get, "/ok", None).await;
    assert_eq!(status, 200);
    assert_eq!(body["ok"], true);
}

/// GET /error should return the TS-compatible HTML error page.
#[tokio::test]
async fn test_contract_error_endpoint() {
    let auth = create_full_auth().await;
    let (status, body) = send_json_request(&auth, HttpMethod::Get, "/error", None).await;
    assert_eq!(status, 200);
    let html = body.as_str().expect("/error should return HTML text");
    // The HTML page uses inline-styled elements matching the TS template
    // (not plain `<h1>ERROR</h1>` — both TS and Rust use styled tags).
    assert!(
        html.contains("<title>Error</title>"),
        "error page should contain <title>Error</title>"
    );
    assert!(
        html.contains("ERROR"),
        "error page should contain ERROR heading"
    );
    assert!(
        html.contains("UNKNOWN"),
        "error page should contain the UNKNOWN error code"
    );
    assert!(
        html.contains("CODE:"),
        "error page should contain CODE: label"
    );
    assert!(
        html.contains("Ask AI"),
        "error page should contain Ask AI button"
    );
}

/// POST /sign-up/email should return { token, user: { id, email, name, ... } }
#[tokio::test]
async fn test_contract_signup_response_shape() {
    let auth = create_full_auth().await;
    let (status, body) = send_json_request(
        &auth,
        HttpMethod::Post,
        "/sign-up/email",
        Some(serde_json::json!({
            "email": "contract@example.com",
            "password": "password123",
            "name": "Contract Test"
        })),
    )
    .await;

    assert_eq!(status, 200);

    // Must have token
    assert!(
        body["token"].is_string(),
        "Response must contain 'token' string"
    );

    // Must have user object with required fields
    let user = &body["user"];
    assert!(user["id"].is_string(), "user.id must be a string");
    assert_eq!(user["email"], "contract@example.com");
    assert_eq!(user["name"], "Contract Test");
    assert!(
        user.get("createdAt").is_some() || user.get("created_at").is_some(),
        "user must have createdAt or created_at"
    );
}

/// POST /sign-in/email should return { token, user: { ... } }
#[tokio::test]
async fn test_contract_signin_response_shape() {
    let auth = create_full_auth().await;

    // Create user first
    let _ = send_json_request(
        &auth,
        HttpMethod::Post,
        "/sign-up/email",
        Some(serde_json::json!({
            "email": "signin-contract@example.com",
            "password": "password123",
            "name": "Signin Contract"
        })),
    )
    .await;

    // Sign in
    let (status, body) = send_json_request(
        &auth,
        HttpMethod::Post,
        "/sign-in/email",
        Some(serde_json::json!({
            "email": "signin-contract@example.com",
            "password": "password123"
        })),
    )
    .await;

    assert_eq!(status, 200);
    assert!(
        body["token"].is_string(),
        "Response must contain 'token' string"
    );
    assert!(body["user"]["id"].is_string(), "user.id must be a string");
    assert_eq!(body["user"]["email"], "signin-contract@example.com");
}

/// POST /sign-out should return { success: true }
#[tokio::test]
async fn test_contract_signout_response_shape() {
    let auth = create_full_auth().await;

    // Create user and get token
    let (_, signup_body) = send_json_request(
        &auth,
        HttpMethod::Post,
        "/sign-up/email",
        Some(serde_json::json!({
            "email": "signout-contract@example.com",
            "password": "password123",
            "name": "Signout Test"
        })),
    )
    .await;

    let token = signup_body["token"].as_str().unwrap();

    // Sign out
    let mut req = AuthRequest::new(HttpMethod::Post, "/sign-out");
    let _ = req
        .headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let resp = auth
        .handle_request(req)
        .await
        .expect("Sign-out should not panic");

    assert_eq!(resp.status, 200);
    let body: Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(body["success"], true);
}

/// Error responses must have { "message": "..." } shape
#[tokio::test]
async fn test_contract_error_response_shape() {
    let auth = create_full_auth().await;

    // Try to sign in with invalid credentials
    let (status, body) = send_json_request(
        &auth,
        HttpMethod::Post,
        "/sign-in/email",
        Some(serde_json::json!({
            "email": "nonexistent@example.com",
            "password": "password123"
        })),
    )
    .await;

    assert!(
        status >= 400,
        "Error should return 4xx status, got {}",
        status
    );
    assert!(
        body["message"].is_string(),
        "Error response must have 'message' field, got: {}",
        body
    );
}

/// Validation error responses must have { "message": "..." } and 4xx status
#[tokio::test]
async fn test_contract_validation_error_shape() {
    let auth = create_full_auth().await;

    // Missing required fields
    let (status, body) = send_json_request(
        &auth,
        HttpMethod::Post,
        "/sign-up/email",
        Some(serde_json::json!({})),
    )
    .await;

    assert!(
        (400..500).contains(&status),
        "Validation error should be 4xx, got {}",
        status
    );
    assert!(
        body["message"].is_string(),
        "Validation error must have 'message' field"
    );
}

/// GET /__test/openapi.json should return valid OpenAPI spec
#[tokio::test]
async fn test_contract_openapi_endpoint() {
    let auth = create_full_auth().await;
    let (status, body) =
        send_json_request(&auth, HttpMethod::Get, "/__test/openapi.json", None).await;

    assert_eq!(status, 200);
    assert!(
        body["openapi"].is_string(),
        "Must have 'openapi' version field"
    );
    assert!(body["info"]["title"].is_string(), "Must have info.title");
    assert!(body["paths"].is_object(), "Must have 'paths' object");
}

/// Unhandled routes should return 404 with { "message": "..." }
#[tokio::test]
async fn test_contract_not_found_response() {
    let auth = create_full_auth().await;
    let (status, body) =
        send_json_request(&auth, HttpMethod::Get, "/nonexistent-route", None).await;

    assert_eq!(status, 404);
    assert!(
        body["message"].is_string(),
        "404 response must have 'message' field"
    );
}
