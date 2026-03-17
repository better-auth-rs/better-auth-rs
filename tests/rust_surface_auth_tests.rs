#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "surface tests intentionally use panic-on-failure assertions and direct JSON indexing for API shape checks"
)]

use async_trait::async_trait;
use better_auth::plugin::{AuthContext, AuthPlugin, AuthRoute};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::prelude::{AuthRequest, AuthResponse, HttpMethod};
use better_auth::store::sea_orm::{Database, DatabaseConnection};
use better_auth::{AuthBuilder, AuthConfig, AuthResult, BetterAuth, run_migrations};

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

fn test_config() -> AuthConfig {
    AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000")
        .password_min_length(8)
}

async fn test_database() -> DatabaseConnection {
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("sqlite test database should connect");
    run_migrations(&database)
        .await
        .expect("sqlite test migrations should run");
    database
}

async fn build_auth_with_route_plugin() -> BetterAuth {
    AuthBuilder::new(test_config())
        .database(test_database().await)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(RouteTestPlugin)
        .build()
        .await
        .expect("build should succeed")
}

// Rust-specific surface: `AuthBuilder::build` is the Rust entry point that
// validates configuration before producing a `BetterAuth` instance.
#[tokio::test]
async fn test_builder_rejects_invalid_config() {
    let result = BetterAuth::new(AuthConfig::default())
        .database(test_database().await)
        .build()
        .await;
    assert!(result.is_err());
}

// Rust-specific surface: `BetterAuth::plugin_names` and `BetterAuth::get_plugin`
// are public Rust introspection APIs with no TS analogue.
#[tokio::test]
async fn test_plugin_registry_accessors() {
    let auth = build_auth_with_route_plugin().await;

    let plugin_names = auth.plugin_names();
    assert!(plugin_names.contains(&"email-password"));
    assert!(plugin_names.contains(&"route-test"));
    assert!(auth.get_plugin("route-test").is_some());
    assert!(auth.get_plugin("missing-plugin").is_none());
}

// Rust-specific surface: `BetterAuth::routes` exposes only plugin-declared
// routes for embedding and router composition.
#[tokio::test]
async fn test_routes_lists_plugin_routes_only() {
    let auth = build_auth_with_route_plugin().await;

    let routes = auth.routes();
    assert!(routes.iter().any(|(path, _)| path == "/route-test"));
    assert!(!routes.iter().any(|(path, _)| path == "/update-user"));
}

// Rust-specific surface: `disabled_path` must affect direct `handle_request`
// callers, not only framework integrations.
#[tokio::test]
async fn test_disabled_path_blocks_direct_dispatch() {
    let auth = BetterAuth::new(test_config().disabled_path("/ok"))
        .database(test_database().await)
        .build()
        .await
        .expect("build should succeed");

    let response = auth
        .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/ok"))
        .await
        .expect("request should return a response");

    assert_eq!(response.status, 404);
}

// Rust-specific surface: `BetterAuth::openapi_spec` is a Rust API for embedded
// schema generation and should include both core and plugin routes.
#[tokio::test]
async fn test_openapi_spec_includes_core_and_plugin_routes() {
    let auth = build_auth_with_route_plugin().await;
    let spec = auth
        .openapi_spec()
        .to_value()
        .expect("OpenAPI spec should serialize to JSON");

    assert!(spec["paths"]["/ok"]["get"]["operationId"].is_string());
    assert_eq!(
        spec["paths"]["/route-test"]["get"]["operationId"],
        "route_test"
    );
    assert_eq!(
        spec["paths"]["/route-test"]["post"]["operationId"],
        "route_test_post"
    );
}
