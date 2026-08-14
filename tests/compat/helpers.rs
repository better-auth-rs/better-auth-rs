//! Auth setup, HTTP request builders, and signup/signin helpers.
//!
//! This is the **canonical** location for all shared test utilities.
//! All integration test files should use `use compat::helpers::*;`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Once, OnceLock};

use better_auth::{
    AuthBuilder, AuthConfig, BetterAuth,
    plugins::{
        AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, EmailPasswordPlugin,
        EmailVerificationPlugin, OAuthPlugin, OrganizationPlugin, PasskeyPlugin,
        PasswordManagementPlugin, SessionManagementPlugin, TwoFactorPlugin, UserManagementPlugin,
        oauth::{
            OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest,
            OAuthUserInfoResponse,
        },
        password_management::SendResetPassword,
    },
    prelude::{AuthRequest, HttpMethod},
};
use better_auth_seaorm::{Database, DatabaseConnection, SeaOrmStore};
use reqwest::Url;
use serde_json::Value;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
type TestAuth = BetterAuth<TestSchema>;

static LOCAL_PROXY_BYPASS: Once = Once::new();
static MOCK_OAUTH_SERVER: Once = Once::new();

const MOCK_OAUTH_BASE_URL: &str = "http://127.0.0.1:3110";

fn ensure_local_proxy_bypass() {
    LOCAL_PROXY_BYPASS.call_once(|| {
        // SAFETY: Test helpers set a single stable localhost proxy bypass
        // before issuing any mock OAuth localhost requests.
        unsafe { std::env::set_var("NO_PROXY", "localhost,127.0.0.1") };
        // SAFETY: Test helpers set a single stable localhost proxy bypass
        // before issuing any mock OAuth localhost requests.
        unsafe { std::env::set_var("no_proxy", "localhost,127.0.0.1") };
    });
}

fn ensure_mock_oauth_server() {
    ensure_local_proxy_bypass();
    MOCK_OAUTH_SERVER.call_once(|| {
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let listener = tokio::net::TcpListener::bind("127.0.0.1:3110")
                .await
                .expect("mock OAuth server should bind to 127.0.0.1:3110");

            loop {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("mock OAuth server should accept connections");
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let read_len = stream.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..read_len]);

                    let response = if request.starts_with("GET /__test/oauth/authorize") {
                        let path = request
                            .lines()
                            .next()
                            .and_then(|line| line.split_whitespace().nth(1))
                            .unwrap_or("/");
                        let url = Url::parse(&format!("{MOCK_OAUTH_BASE_URL}{path}"))
                            .expect("mock OAuth authorize URL should parse");
                        let redirect_uri = url
                            .query_pairs()
                            .find(|(key, _)| key == "redirect_uri")
                            .map(|(_, value)| value.into_owned())
                            .unwrap_or_else(|| "http://localhost:3000/callback".to_string());
                        let state = url
                            .query_pairs()
                            .find(|(key, _)| key == "state")
                            .map(|(_, value)| value.into_owned())
                            .unwrap_or_else(|| "missing-state".to_string());
                        let location =
                            format!("{redirect_uri}?code=compat-code&state={state}");
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    } else if request.starts_with("POST /__test/oauth/token") {
                        let body = serde_json::json!({
                            "access_token": "mock-access-token",
                            "refresh_token": "mock-refresh-token",
                            "token_type": "Bearer",
                            "expires_in": 3600,
                            "scope": "openid email profile"
                        })
                        .to_string();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    } else if request.starts_with("GET /__test/oauth/userinfo") {
                        let body = serde_json::json!({
                            "sub": "mock-user-id-123",
                            "email": "mock@example.com",
                            "name": "Mock OAuth User",
                            "email_verified": true
                        })
                        .to_string();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    } else {
                        let body = serde_json::json!({"error": "not found"}).to_string();
                        format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    };

                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
    });
    std::thread::sleep(std::time::Duration::from_millis(25));
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ResetSenderMode {
    #[default]
    Capture,
    Fail,
}

#[derive(Debug, Clone, Default)]
pub struct TestAuthOptions {
    pub reset_sender_mode: ResetSenderMode,
    pub creator_role: Option<String>,
}

struct TestResetSender {
    mode: ResetSenderMode,
}

static RESET_PASSWORD_OUTBOX: OnceLock<Mutex<std::collections::HashMap<String, String>>> =
    OnceLock::new();

fn reset_password_outbox() -> &'static Mutex<std::collections::HashMap<String, String>> {
    RESET_PASSWORD_OUTBOX.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[async_trait::async_trait]
impl SendResetPassword for TestResetSender {
    async fn send(
        &self,
        user: &serde_json::Value,
        _url: &str,
        token: &str,
    ) -> better_auth::AuthResult<()> {
        if self.mode == ResetSenderMode::Fail {
            return Err(better_auth::AuthError::internal(
                "test reset sender failure".to_string(),
            ));
        }
        if let Some(email) = user.get("email").and_then(|value| value.as_str()) {
            reset_password_outbox()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(email.to_string(), token.to_string());
        }
        Ok(())
    }
}

pub fn take_reset_password_token(email: &str) -> Option<String> {
    reset_password_outbox()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(email)
}

// ---------------------------------------------------------------------------
// Unique email generator
// ---------------------------------------------------------------------------

static EMAIL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique email address for testing, avoiding hard-coded collisions.
pub fn unique_email(prefix: &str) -> String {
    let n = EMAIL_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{n}_{}@test.com", std::process::id())
}

// ---------------------------------------------------------------------------
// Auth setup
// ---------------------------------------------------------------------------

/// Generate a deterministic test-only key (not a real secret).
pub fn test_secret() -> String {
    "t]e]s]t]-]o]n]l]y]-]k]e]y]-]n]o]t]-]a]-]r]e]a]l]-]s]e]c]r]e]t]-]3]2]c]h".replace(']', "")
}

pub fn test_config() -> AuthConfig {
    AuthConfig::new(test_secret())
        .base_url("http://localhost:3000")
        .password_min_length(8)
}

fn mock_oauth_plugin() -> OAuthPlugin {
    struct MockUserInfoHandler;

    #[async_trait::async_trait]
    impl OAuthUserInfoHandler for MockUserInfoHandler {
        async fn get_user_info(
            &self,
            _request: OAuthUserInfoRequest,
        ) -> Result<OAuthUserInfoResponse, String> {
            Ok(OAuthUserInfoResponse {
                user: OAuthUserInfo {
                    id: "mock-account-id".to_string(),
                    email: "mock@example.com".to_string(),
                    name: Some("Mock OAuth User".to_string()),
                    image: None,
                    email_verified: true,
                },
                data: serde_json::json!({
                    "id": "mock-account-id",
                    "email": "mock@example.com",
                    "name": "Mock OAuth User",
                    "image": null,
                    "emailVerified": true,
                }),
            })
        }
    }

    OAuthPlugin::new().add_provider(
        "mock",
        OAuthProvider {
            client_id: "mock-client-id".to_string(),
            client_secret: "mock-client-secret".to_string(),
            auth_url: format!("{MOCK_OAUTH_BASE_URL}/__test/oauth/authorize"),
            token_url: format!("{MOCK_OAUTH_BASE_URL}/__test/oauth/token"),
            user_info_url: Some(format!("{MOCK_OAUTH_BASE_URL}/__test/oauth/userinfo")),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            authorization_params: Vec::new(),
            map_user_info: Some(|_value| {
                Ok(OAuthUserInfo {
                    id: "mock-account-id".to_string(),
                    email: "mock@example.com".to_string(),
                    name: Some("Mock OAuth User".to_string()),
                    image: None,
                    email_verified: true,
                })
            }),
            get_user_info: Some(Arc::new(MockUserInfoHandler)),
            refresh_access_token: None,
            verify_id_token: None,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        },
    )
}

async fn test_database() -> DatabaseConnection {
    ensure_local_proxy_bypass();
    let database = Database::connect("sqlite::memory:")
        .await
        .unwrap_or_else(|e| panic!("sqlite test database should connect: {e}"));
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap_or_else(|e| panic!("sqlite test migrations should run: {e}"));
    database
}

async fn test_store(config: &AuthConfig) -> SeaOrmStore<TestSchema> {
    SeaOrmStore::<TestSchema>::new(config.clone(), test_database().await)
}

pub async fn create_test_auth() -> TestAuth {
    create_test_auth_with_options(TestAuthOptions::default()).await
}

pub async fn create_test_auth_with_options(options: TestAuthOptions) -> TestAuth {
    let config = test_config();
    let store = test_store(&config).await;
    let organization_plugin = if let Some(creator_role) = options.creator_role.clone() {
        OrganizationPlugin::new().creator_role(creator_role)
    } else {
        OrganizationPlugin::new()
    };

    AuthBuilder::<TestSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(
            PasswordManagementPlugin::new()
                .require_current_password(true)
                .send_reset_password(Arc::new(TestResetSender {
                    mode: options.reset_sender_mode,
                })),
        )
        .plugin(AccountManagementPlugin::new())
        .plugin(EmailVerificationPlugin::new())
        .plugin(
            UserManagementPlugin::new()
                .change_email_enabled(true)
                .delete_user_enabled(true)
                .require_delete_verification(false),
        )
        .plugin(ApiKeyPlugin::builder().build())
        .plugin(mock_oauth_plugin())
        .plugin(TwoFactorPlugin::new())
        .plugin(organization_plugin)
        .plugin(
            PasskeyPlugin::new()
                .rp_id("localhost")
                .rp_name("Better Auth Test")
                .origin("http://localhost:3000"),
        )
        .plugin(AdminPlugin::new())
        .build()
        .await
        .unwrap_or_else(|e| panic!("Failed to create test auth instance: {e}"))
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

pub fn post_json(path: &str, body: Value) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Post, path);
    req.body = Some(body.to_string().into_bytes());
    let _ = req
        .headers
        .insert("content-type".to_string(), "application/json".to_string());
    let _ = req
        .headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

pub fn get_request(path: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, path);
    let _ = req
        .headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

pub fn get_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, path);
    let _ = req
        .headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let _ = req
        .headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

pub fn get_with_auth_and_query(path: &str, token: &str, query: Vec<(&str, &str)>) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, path);
    let _ = req
        .headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let _ = req
        .headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    for (k, v) in query {
        let _ = req.query.insert(k.to_string(), v.to_string());
    }
    req
}

pub fn post_json_with_auth(path: &str, body: Value, token: &str) -> AuthRequest {
    let mut req = post_json(path, body);
    let _ = req
        .headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req
}

pub fn delete_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Delete, path);
    let _ = req
        .headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let _ = req
        .headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

/// Build an authenticated POST request with an empty `{}` body (no content-type).
///
/// Matches the pattern used by many integration tests for action endpoints
/// like `/sign-out`, `/revoke-sessions`, `/delete-user`, etc.
pub fn post_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Post, path);
    req.body = Some(b"{}".to_vec());
    let _ = req
        .headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    let _ = req
        .headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

// ---------------------------------------------------------------------------
// Send / signup / signin
// ---------------------------------------------------------------------------

pub async fn send_request(auth: &TestAuth, req: AuthRequest) -> (u16, Value) {
    let resp = auth
        .handle_request(req)
        .await
        .unwrap_or_else(|e| panic!("Request should not panic: {e}"));
    let status = resp.status;
    let json: Value = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&resp.body).to_string()));
    (status, json)
}

pub async fn signup_user(
    auth: &TestAuth,
    email: &str,
    password: &str,
    name: &str,
) -> (String, Value) {
    let req = post_json(
        "/sign-up/email",
        serde_json::json!({
            "name": name,
            "email": email,
            "password": password,
        }),
    );
    let (status, json) = send_request(auth, req).await;
    assert_eq!(
        status, 200,
        "signup should succeed, got status {}: {}",
        status, json
    );
    let token = json
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("signup response missing token"))
        .to_string();
    (token, json)
}

pub async fn signin_user(auth: &TestAuth, email: &str, password: &str) -> (String, Value) {
    let req = post_json(
        "/sign-in/email",
        serde_json::json!({
            "email": email,
            "password": password,
        }),
    );
    let (status, json) = send_request(auth, req).await;
    assert_eq!(
        status, 200,
        "signin should succeed, got status {}: {}",
        status, json
    );
    let token = json
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("signin response missing token"))
        .to_string();
    (token, json)
}

// ---------------------------------------------------------------------------
// TestHarness
// ---------------------------------------------------------------------------

/// Unified test harness wrapping `BetterAuth` with ergonomic helpers.
///
/// # Examples
///
/// ```rust,ignore
/// let h = TestHarness::new().await;
/// let (token, _) = h.signup("alice@test.com", "password123", "Alice").await;
/// let (status, body) = h.send(h.authed_get("/get-session", &token)).await;
/// assert_eq!(status, 200);
/// ```
pub struct TestHarness {
    auth: Arc<TestAuth>,
}

impl TestHarness {
    /// Create a harness with **all** plugins enabled (suitable for compat and
    /// comprehensive integration tests).
    pub async fn new() -> Self {
        let auth = create_test_auth().await;
        Self {
            auth: Arc::new(auth),
        }
    }

    /// Create a harness with configurable test auth behavior.
    pub async fn with_options(options: TestAuthOptions) -> Self {
        let auth = create_test_auth_with_options(options).await;
        Self {
            auth: Arc::new(auth),
        }
    }

    /// Create a harness with a **minimal** plugin set matching
    /// `integration_tests.rs` conventions (EmailPassword, SessionManagement,
    /// PasswordManagement, AccountManagement, ApiKey).
    pub async fn minimal() -> Self {
        let config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
            .base_url("http://localhost:3000")
            .password_min_length(6);
        let store = test_store(&config).await;
        let auth = AuthBuilder::<TestSchema>::new(config)
            .store(store)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(
                PasswordManagementPlugin::new().send_reset_password(Arc::new(TestResetSender {
                    mode: ResetSenderMode::Capture,
                })),
            )
            .plugin(AccountManagementPlugin::new())
            .plugin(EmailVerificationPlugin::new())
            .plugin(
                UserManagementPlugin::new()
                    .change_email_enabled(true)
                    .delete_user_enabled(true)
                    .require_delete_verification(false),
            )
            .plugin(ApiKeyPlugin::builder().build())
            .plugin(mock_oauth_plugin())
            .build()
            .await
            .unwrap_or_else(|e| panic!("Failed to create test auth instance: {e}"));
        Self {
            auth: Arc::new(auth),
        }
    }

    /// Wrap an existing `Arc<BetterAuth>` in a harness.
    pub fn from_arc(auth: Arc<TestAuth>) -> Self {
        Self { auth }
    }

    /// Access the inner `BetterAuth` reference.
    pub fn auth(&self) -> &TestAuth {
        &self.auth
    }

    /// Consume the harness and return the inner `Arc`.
    pub fn into_arc(self) -> Arc<TestAuth> {
        self.auth
    }

    // -------------------------------------------------------------------
    // Request builders (instance methods delegate to helpers that include
    // `origin` header for CSRF by default)
    // -------------------------------------------------------------------

    /// Build a GET request (with `origin` header).
    pub fn get(&self, path: &str) -> AuthRequest {
        get_request(path)
    }

    /// Build an authenticated GET request (with `origin` header).
    pub fn authed_get(&self, path: &str, token: &str) -> AuthRequest {
        get_with_auth(path, token)
    }

    /// Build a POST request with a JSON body (with `origin` header).
    pub fn post(&self, path: &str, body: Value) -> AuthRequest {
        post_json(path, body)
    }

    /// Build an authenticated POST request with a JSON body (with `origin`
    /// header).
    pub fn authed_post(&self, path: &str, body: Value, token: &str) -> AuthRequest {
        post_json_with_auth(path, body, token)
    }

    // -------------------------------------------------------------------
    // Send
    // -------------------------------------------------------------------

    /// Send a request and return `(status_code, parsed_json_body)`.
    pub async fn send(&self, req: AuthRequest) -> (u16, Value) {
        send_request(&self.auth, req).await
    }

    // -------------------------------------------------------------------
    // User lifecycle
    // -------------------------------------------------------------------

    /// Sign up a new user. Returns `(token, response_json)`.
    pub async fn signup(&self, email: &str, password: &str, name: &str) -> (String, Value) {
        let req = self.post(
            "/sign-up/email",
            serde_json::json!({ "name": name, "email": email, "password": password }),
        );
        let (status, json) = self.send(req).await;
        assert_eq!(
            status, 200,
            "signup should succeed, got status {}: {}",
            status, json
        );
        let token = json
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("signup response missing token"))
            .to_string();
        (token, json)
    }

    /// Sign in an existing user. Returns `(token, response_json)`.
    pub async fn signin(&self, email: &str, password: &str) -> (String, Value) {
        let req = self.post(
            "/sign-in/email",
            serde_json::json!({ "email": email, "password": password }),
        );
        let (status, json) = self.send(req).await;
        assert_eq!(
            status, 200,
            "signin should succeed, got status {}: {}",
            status, json
        );
        let token = json
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("signin response missing token"))
            .to_string();
        (token, json)
    }

    /// Create a test user with a unique email and return `(user_id, session_token)`.
    pub async fn create_user_with_session(&self) -> (String, String) {
        let email = unique_email("harness");
        let (token, json) = self.signup(&email, "password123", "Test User").await;
        let user_id = json
            .get("user")
            .and_then(|u| u.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("missing user id"))
            .to_string();
        (user_id, token)
    }
}
