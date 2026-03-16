use async_trait::async_trait;
use better_auth::plugins::{EmailPasswordPlugin, SessionManagementPlugin, UserManagementPlugin};
use better_auth::types::{AuthRequest, AuthResponse, HttpMethod};
use better_auth::{
    AuthBuilder, AuthConfig, AuthContext, AuthPlugin, AuthResult, AuthRoute, run_migrations,
    sea_orm::{Database, DatabaseConnection},
};
use serde_json::json;

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
        .password_min_length(6)
}

async fn test_database() -> DatabaseConnection {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    run_migrations(&database).await.unwrap();
    database
}

#[tokio::test]
async fn test_routes_include_plugin_routes() {
    let auth = AuthBuilder::new(test_config())
        .database(test_database().await)
        .plugin(RouteTestPlugin)
        .build()
        .await
        .expect("Failed to build auth instance");

    let routes = auth.routes();

    // routes() returns Vec<(String, &dyn AuthPlugin)> — tuples of (path, plugin_ref)
    // Core routes like /update-user are not included here; plugin-registered routes are.
    let has_plugin_route = routes.iter().any(|(path, _)| path == "/route-test");
    assert!(has_plugin_route, "Expected plugin route /route-test");

    // Verify the plugin is correctly registered
    let plugin_names = auth.plugin_names();
    assert!(
        plugin_names.contains(&"route-test"),
        "Expected route-test plugin to be registered"
    );
}

#[tokio::test]
async fn test_signup_and_delete_lifecycle() {
    let auth = AuthBuilder::new(test_config())
        .database(test_database().await)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(
            UserManagementPlugin::new()
                .delete_user_enabled(true)
                .require_delete_verification(false),
        )
        .build()
        .await
        .expect("Failed to build auth instance");

    // Sign up a user
    let signup_data = json!({
        "email": "lifecycle@example.com",
        "password": "password123",
        "name": "Lifecycle User"
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
    assert!(response_json["user"]["id"].is_string());
    assert_eq!(response_json["user"]["email"], "lifecycle@example.com");
    let token = response_json["token"].as_str().unwrap().to_string();

    // Delete the user using the session token
    let mut delete_request = AuthRequest::new(HttpMethod::Post, "/delete-user");
    delete_request
        .headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    delete_request.body = Some(b"{}".to_vec());

    let delete_response = auth
        .handle_request(delete_request)
        .await
        .expect("Delete failed");
    assert_eq!(delete_response.status, 200);

    // Verify the session is now invalid (user was deleted)
    let mut retry_request = AuthRequest::new(HttpMethod::Post, "/delete-user");
    retry_request
        .headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    retry_request.body = Some(b"{}".to_vec());

    let retry_response = auth
        .handle_request(retry_request)
        .await
        .expect("Request should not panic");
    assert_eq!(retry_response.status, 401);
}
