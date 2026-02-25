use async_trait::async_trait;
use better_auth::adapters::{MemoryCacheAdapter, MemoryDatabaseAdapter, MemoryMailerAdapter};
use better_auth::core::{AuthContext, AuthPlugin, AuthRoute, PluginCapabilities};
use better_auth::error::AuthResult;
use better_auth::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::types::{AuthRequest, AuthResponse, HttpMethod};
use better_auth::{AuthConfig, BetterAuth};
use serde_json::json;
use std::sync::{Arc, Mutex};

struct NeedsCachePlugin;

#[async_trait]
impl AuthPlugin for NeedsCachePlugin {
    fn name(&self) -> &'static str {
        "needs-cache"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/needs-cache", "needs_cache")]
    }

    fn capabilities(&self) -> PluginCapabilities {
        PluginCapabilities {
            needs_cache: true,
            ..PluginCapabilities::default()
        }
    }

    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

struct RouteTestPlugin;

#[async_trait]
impl AuthPlugin for RouteTestPlugin {
    fn name(&self) -> &'static str {
        "route-test"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/route-test", "route_test"),
            AuthRoute::post("/route-test", "route_test_post"),
        ]
    }

    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

struct HookRecorder {
    events: Arc<Mutex<Vec<String>>>,
}

impl HookRecorder {
    fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self { events }
    }
}

#[async_trait]
impl AuthPlugin for HookRecorder {
    fn name(&self) -> &'static str {
        "hook-recorder"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    async fn on_user_created(
        &self,
        _user: &better_auth::types::User,
        _ctx: &AuthContext,
    ) -> AuthResult<()> {
        self.events.lock().unwrap().push("user_created".to_string());
        Ok(())
    }

    async fn on_session_created(
        &self,
        _session: &better_auth::types::Session,
        _ctx: &AuthContext,
    ) -> AuthResult<()> {
        self.events
            .lock()
            .unwrap()
            .push("session_created".to_string());
        Ok(())
    }

    async fn on_user_deleted(&self, _user_id: &str, _ctx: &AuthContext) -> AuthResult<()> {
        self.events.lock().unwrap().push("user_deleted".to_string());
        Ok(())
    }

    async fn on_session_deleted(&self, _session_token: &str, _ctx: &AuthContext) -> AuthResult<()> {
        self.events
            .lock()
            .unwrap()
            .push("session_deleted".to_string());
        Ok(())
    }
}

fn test_config() -> AuthConfig {
    AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000")
        .password_min_length(6)
}

#[tokio::test]
async fn test_missing_capability_blocks_build() {
    let result = BetterAuth::new(test_config())
        .database(MemoryDatabaseAdapter::new())
        .plugin(NeedsCachePlugin)
        .build()
        .await;

    let err = result.expect_err("Expected build to fail without cache capability");
    let message = err.to_string();
    assert!(message.contains("Missing capability"));
    assert!(message.contains("needs-cache"));
    assert!(message.contains("cache"));
}

#[tokio::test]
async fn test_routes_include_core_and_plugin_routes() {
    let auth = BetterAuth::new(test_config())
        .database(MemoryDatabaseAdapter::new())
        .plugin(RouteTestPlugin)
        .build()
        .await
        .expect("Failed to build auth instance");

    let routes = auth.routes();

    let has_update = routes
        .iter()
        .any(|route| route.method == HttpMethod::Post && route.path == "/update-user");
    let has_delete = routes
        .iter()
        .any(|route| route.method == HttpMethod::Delete && route.path == "/delete-user");
    let has_plugin_get = routes
        .iter()
        .any(|route| route.method == HttpMethod::Get && route.path == "/route-test");
    let has_plugin_post = routes
        .iter()
        .any(|route| route.method == HttpMethod::Post && route.path == "/route-test");

    assert!(has_update, "Expected core route /update-user");
    assert!(has_delete, "Expected core route /delete-user");
    assert!(has_plugin_get, "Expected plugin route /route-test (GET)");
    assert!(has_plugin_post, "Expected plugin route /route-test (POST)");
}

#[tokio::test]
async fn test_runtime_capabilities_from_config() {
    let auth = BetterAuth::new(test_config())
        .database(MemoryDatabaseAdapter::new())
        .cache(MemoryCacheAdapter::new())
        .mailer(MemoryMailerAdapter::new())
        .plugin(RouteTestPlugin)
        .build()
        .await;

    assert!(
        auth.is_ok(),
        "Expected build to succeed with cache and mailer configured"
    );
}

#[tokio::test]
async fn test_hook_lifecycle_events() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let recorder = HookRecorder::new(events.clone());

    let auth = BetterAuth::new(test_config())
        .database(MemoryDatabaseAdapter::new())
        .plugin(recorder)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await
        .expect("Failed to build auth instance");

    let signup_data = json!({
        "email": "hook@example.com",
        "password": "password123",
        "name": "Hook User"
    });

    let mut signup_request = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
    signup_request.body = Some(signup_data.to_string().into_bytes());
    signup_request
        .headers
        .insert("content-type".to_string(), "application/json".to_string());

    let signup_response = auth
        .handle_request(signup_request)
        .await
        .expect("Signup failed");
    assert_eq!(signup_response.status, 200);

    let response_json: serde_json::Value =
        serde_json::from_slice(&signup_response.body).expect("Failed to parse response JSON");
    let token = response_json["token"].as_str().unwrap().to_string();

    let mut delete_request = AuthRequest::new(HttpMethod::Delete, "/delete-user");
    delete_request
        .headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let delete_response = auth
        .handle_request(delete_request)
        .await
        .expect("Delete failed");
    assert_eq!(delete_response.status, 200);

    let events = events.lock().unwrap().clone();
    assert!(events.contains(&"user_created".to_string()));
    assert!(events.contains(&"session_created".to_string()));
    assert!(events.contains(&"session_deleted".to_string()));
    assert!(events.contains(&"user_deleted".to_string()));
}
