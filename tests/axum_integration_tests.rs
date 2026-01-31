#![cfg(feature = "axum")]

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use better_auth::adapters::MemoryDatabaseAdapter;
use better_auth::handlers::AxumIntegration;
use better_auth::plugins::{
    EmailPasswordPlugin, PasswordManagementPlugin, SessionManagementPlugin,
};
use better_auth::{AuthConfig, BetterAuth};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt; // for oneshot
use tower_http::cors::CorsLayer;

/// Helper to create test BetterAuth instance with all plugins
async fn create_test_auth() -> Arc<BetterAuth> {
    let config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000")
        .password_min_length(6);

    Arc::new(
        BetterAuth::new(config)
            .database(MemoryDatabaseAdapter::new())
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(PasswordManagementPlugin::new())
            .build()
            .await
            .expect("Failed to create test auth instance"),
    )
}

/// Helper to create the complete Axum router (mimics the example server)
fn create_test_router(auth: Arc<BetterAuth>) -> axum::Router {
    use axum::{Router, routing::get};

    // Create auth router using the BetterAuth AxumIntegration
    let auth_router = auth.clone().axum_router();

    // Create main application router (simplified version of the example)
    Router::new()
        .route(
            "/api/public",
            get(|| async {
                axum::Json(json!({
                    "message": "This is a public route",
                    "status": "ok"
                }))
            }),
        )
        // Mount auth routes under /auth prefix
        .nest("/auth", auth_router)
        // Add CORS layer
        .layer(CorsLayer::permissive())
        .with_state(auth)
}

/// Helper to create a user and return user data + session token
async fn create_test_user(router: axum::Router) -> (Value, String) {
    let signup_data = json!({
        "email": "test@example.com",
        "password": "password123",
        "name": "Test User"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-up/email")
        .header("content-type", "application/json")
        .body(Body::from(signup_data.to_string()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK); // BetterAuth returns 200, not 201

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    let token = response_data["token"].as_str().unwrap().to_string();
    (response_data, token)
}

/// Test health check endpoint
#[tokio::test]
async fn test_axum_health_check() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/auth/health")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(response_data["status"], "ok");
    assert_eq!(response_data["service"], "better-auth");
}

/// Test public API endpoint
#[tokio::test]
async fn test_axum_public_endpoint() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/public")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(response_data["status"], "ok");
    assert_eq!(response_data["message"], "This is a public route");
}

/// Test user signup via Axum
#[tokio::test]
async fn test_axum_user_signup() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let signup_data = json!({
        "email": "signup@example.com",
        "password": "password123",
        "name": "Signup User"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-up/email")
        .header("content-type", "application/json")
        .body(Body::from(signup_data.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(response_data["user"]["id"].is_string());
    assert_eq!(response_data["user"]["email"], "signup@example.com");
    assert_eq!(response_data["user"]["name"], "Signup User");
    assert!(response_data["token"].is_string());
}

/// Test user signin via Axum
#[tokio::test]
async fn test_axum_user_signin() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    // First create a user
    let (_user_data, _token) = create_test_user(router.clone()).await;

    // Then sign in
    let signin_data = json!({
        "email": "test@example.com",
        "password": "password123"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-in/email")
        .header("content-type", "application/json")
        .body(Body::from(signin_data.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(response_data["user"]["email"], "test@example.com");
    assert!(response_data["token"].is_string());
}

/// Test invalid signin credentials
#[tokio::test]
async fn test_axum_invalid_signin() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let signin_data = json!({
        "email": "nonexistent@example.com",
        "password": "wrongpassword"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-in/email")
        .header("content-type", "application/json")
        .body(Body::from(signin_data.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Test session retrieval via Axum
#[tokio::test]
async fn test_axum_get_session() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let (_user_data, token) = create_test_user(router.clone()).await;

    let request = Request::builder()
        .method(Method::GET)
        .uri("/auth/get-session")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(response_data["session"]["token"].is_string());
    assert!(response_data["user"]["id"].is_string());
    assert_eq!(response_data["user"]["email"], "test@example.com");
}

/// Test session list via Axum
#[tokio::test]
async fn test_axum_list_sessions() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let (_user_data, token) = create_test_user(router.clone()).await;

    let request = Request::builder()
        .method(Method::GET)
        .uri("/auth/list-sessions")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let sessions: Vec<Value> = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(sessions.len(), 1);
    assert!(sessions[0]["token"].is_string());
}

/// Test sign out via Axum
#[tokio::test]
async fn test_axum_sign_out() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let (_user_data, token) = create_test_user(router.clone()).await;

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-out")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(response_data["success"], true);
}

/// Test forget password via Axum
#[tokio::test]
async fn test_axum_forget_password() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let (_user_data, _token) = create_test_user(router.clone()).await;

    let forget_data = json!({
        "email": "test@example.com",
        "redirectTo": "http://localhost:3000/reset"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/forget-password")
        .header("content-type", "application/json")
        .body(Body::from(forget_data.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(response_data["status"], true);
}

/// Test change password via Axum
#[tokio::test]
async fn test_axum_change_password() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let (_user_data, token) = create_test_user(router.clone()).await;

    let change_data = json!({
        "currentPassword": "password123",
        "newPassword": "newpassword123",
        "revokeOtherSessions": "false"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/change-password")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(change_data.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(response_data["user"]["id"].is_string());
    assert!(response_data["token"].is_null()); // No new token when not revoking sessions
}

/// Test change password with session revocation via Axum
#[tokio::test]
async fn test_axum_change_password_with_revocation() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let (_user_data, token) = create_test_user(router.clone()).await;

    let change_data = json!({
        "currentPassword": "password123",
        "newPassword": "newpassword123",
        "revokeOtherSessions": "true"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/change-password")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(change_data.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(response_data["user"]["id"].is_string());
    assert!(response_data["token"].is_string()); // New token when revoking sessions
}

/// Test unauthorized access to protected endpoints
#[tokio::test]
async fn test_axum_unauthorized_access() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    // Test get-session without token
    let request = Request::builder()
        .method(Method::GET)
        .uri("/auth/get-session")
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test change-password without token
    let change_data = json!({
        "currentPassword": "password123",
        "newPassword": "newpassword123"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/change-password")
        .header("content-type", "application/json")
        .body(Body::from(change_data.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Test invalid JSON handling
#[tokio::test]
async fn test_axum_invalid_json() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-up/email")
        .header("content-type", "application/json")
        .body(Body::from("invalid json"))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Test missing required fields
#[tokio::test]
async fn test_axum_missing_fields() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    // Test signup with missing password
    let incomplete_data = json!({
        "email": "incomplete@example.com"
        // missing password
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-up/email")
        .header("content-type", "application/json")
        .body(Body::from(incomplete_data.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Test duplicate email handling
#[tokio::test]
async fn test_axum_duplicate_email() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let signup_data = json!({
        "email": "duplicate@example.com",
        "password": "password123",
        "name": "First User"
    });

    // First signup should succeed
    let request1 = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-up/email")
        .header("content-type", "application/json")
        .body(Body::from(signup_data.to_string()))
        .unwrap();

    let response1 = router.clone().oneshot(request1).await.unwrap();
    assert_eq!(response1.status(), StatusCode::OK);

    // Second signup with same email should fail
    let request2 = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-up/email")
        .header("content-type", "application/json")
        .body(Body::from(signup_data.to_string()))
        .unwrap();

    let response2 = router.oneshot(request2).await.unwrap();
    assert_eq!(response2.status(), StatusCode::CONFLICT);
}

/// Test password validation
#[tokio::test]
async fn test_axum_password_validation() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    // Test with password too short (less than 6 characters)
    let signup_data = json!({
        "email": "short@example.com",
        "password": "123",
        "name": "Short Password User"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-up/email")
        .header("content-type", "application/json")
        .body(Body::from(signup_data.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    // Check password validation message
    let message = response_data["message"].as_str().unwrap();
    assert!(message.contains("6 characters"));
}

/// Test session revocation flow
#[tokio::test]
async fn test_axum_session_revocation_flow() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let (_user_data, token1) = create_test_user(router.clone()).await;

    // Create second session by signing in again
    let signin_data = json!({
        "email": "test@example.com",
        "password": "password123"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-in/email")
        .header("content-type", "application/json")
        .body(Body::from(signin_data.to_string()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();
    let token2 = response_data["token"].as_str().unwrap();

    // Verify we have 2 sessions
    let request = Request::builder()
        .method(Method::GET)
        .uri("/auth/list-sessions")
        .header("authorization", format!("Bearer {}", token1))
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let sessions: Vec<Value> = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(sessions.len(), 2);

    // Revoke the second session using the first session
    let revoke_data = json!({
        "token": token2
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/revoke-session")
        .header("authorization", format!("Bearer {}", token1))
        .header("content-type", "application/json")
        .body(Body::from(revoke_data.to_string()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(response_data["status"], true);

    // Verify token2 is no longer valid
    let request = Request::builder()
        .method(Method::GET)
        .uri("/auth/get-session")
        .header("authorization", format!("Bearer {}", token2))
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Test revoke all sessions
#[tokio::test]
async fn test_axum_revoke_all_sessions() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let (_user_data, token) = create_test_user(router.clone()).await;

    // Revoke all sessions
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/revoke-sessions")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(response_data["status"], true);

    // Verify token is no longer valid
    let request = Request::builder()
        .method(Method::GET)
        .uri("/auth/get-session")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Test session cookies are set on sign-up
#[tokio::test]
async fn test_axum_signup_sets_cookie() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let signup_data = json!({
        "email": "cookie@example.com",
        "password": "password123",
        "name": "Cookie User"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-up/email")
        .header("content-type", "application/json")
        .body(Body::from(signup_data.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Check that Set-Cookie header is present
    let headers = response.headers();
    let cookie_header = headers.get("set-cookie");
    assert!(
        cookie_header.is_some(),
        "Set-Cookie header should be present"
    );

    let cookie_value = cookie_header.unwrap().to_str().unwrap();
    assert!(
        cookie_value.contains("better-auth.session-token="),
        "Cookie should contain session token"
    );
    assert!(cookie_value.contains("Path=/"), "Cookie should have Path=/");
    assert!(
        cookie_value.contains("HttpOnly"),
        "Cookie should be HttpOnly"
    );
    assert!(
        cookie_value.contains("SameSite=Lax"),
        "Cookie should have SameSite=Lax"
    );
}

/// Test session cookies are set on sign-in
#[tokio::test]
async fn test_axum_signin_sets_cookie() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    // First create a user
    let (_user_data, _token) = create_test_user(router.clone()).await;

    // Then sign in
    let signin_data = json!({
        "email": "test@example.com",
        "password": "password123"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-in/email")
        .header("content-type", "application/json")
        .body(Body::from(signin_data.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Check that Set-Cookie header is present
    let headers = response.headers();
    let cookie_header = headers.get("set-cookie");
    assert!(
        cookie_header.is_some(),
        "Set-Cookie header should be present"
    );

    let cookie_value = cookie_header.unwrap().to_str().unwrap();
    assert!(
        cookie_value.contains("better-auth.session-token="),
        "Cookie should contain session token"
    );
    assert!(cookie_value.contains("Path=/"), "Cookie should have Path=/");
    assert!(
        cookie_value.contains("HttpOnly"),
        "Cookie should be HttpOnly"
    );
    assert!(
        cookie_value.contains("SameSite=Lax"),
        "Cookie should have SameSite=Lax"
    );
}

/// Test session cookie is cleared on sign-out
#[tokio::test]
async fn test_axum_signout_clears_cookie() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let (_user_data, token) = create_test_user(router.clone()).await;

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-out")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Check that Set-Cookie header is present and clears the cookie
    let headers = response.headers();
    let cookie_header = headers.get("set-cookie");
    assert!(
        cookie_header.is_some(),
        "Set-Cookie header should be present to clear cookie"
    );

    let cookie_value = cookie_header.unwrap().to_str().unwrap();
    assert!(
        cookie_value.contains("better-auth.session-token="),
        "Cookie should contain session token name"
    );
    assert!(
        cookie_value.contains("Expires=Thu, 01 Jan 1970"),
        "Cookie should be expired to clear it"
    );
    assert!(cookie_value.contains("Path=/"), "Cookie should have Path=/");
}

/// Test 404 for non-existent routes
#[tokio::test]
async fn test_axum_404_routes() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/auth/non-existent-route")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Test user profile update
#[tokio::test]
async fn test_axum_update_user() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let (_user_data, token) = create_test_user(router.clone()).await;

    let update_data = json!({
        "name": "Updated Test User",
        "email": "updated@example.com",
        "username": "updateduser",
        "displayUsername": "Updated User"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/update-user")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(update_data.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(response_data["user"]["name"], "Updated Test User");
    assert_eq!(response_data["user"]["email"], "updated@example.com");
    assert_eq!(response_data["user"]["username"], "updateduser");
    assert_eq!(response_data["user"]["displayUsername"], "Updated User");
}

/// Test unauthorized user profile update
#[tokio::test]
async fn test_axum_update_user_unauthorized() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let update_data = json!({
        "name": "Updated Test User"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/update-user")
        .header("content-type", "application/json")
        .body(Body::from(update_data.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Test user profile update with invalid JSON
#[tokio::test]
async fn test_axum_update_user_invalid_json() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let (_user_data, token) = create_test_user(router.clone()).await;

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/update-user")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from("invalid json"))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Test user deletion
#[tokio::test]
async fn test_axum_delete_user() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let (_user_data, token) = create_test_user(router.clone()).await;

    let request = Request::builder()
        .method(Method::DELETE)
        .uri("/auth/delete-user")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(response_data["success"], true);
    assert_eq!(
        response_data["message"],
        "User account successfully deleted"
    );
}

/// Test unauthorized user deletion
#[tokio::test]
async fn test_axum_delete_user_unauthorized() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let request = Request::builder()
        .method(Method::DELETE)
        .uri("/auth/delete-user")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Test user deletion invalidates sessions
#[tokio::test]
async fn test_axum_delete_user_invalidates_sessions() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    let (_user_data, token) = create_test_user(router.clone()).await;

    // Delete the user
    let delete_request = Request::builder()
        .method(Method::DELETE)
        .uri("/auth/delete-user")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let delete_response = router.clone().oneshot(delete_request).await.unwrap();
    assert_eq!(delete_response.status(), StatusCode::OK);

    // Try to use the same token - should be unauthorized
    let session_request = Request::builder()
        .method(Method::GET)
        .uri("/auth/get-session")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let session_response = router.oneshot(session_request).await.unwrap();
    assert_eq!(session_response.status(), StatusCode::UNAUTHORIZED);
}

/// Test user profile management workflow
#[tokio::test]
async fn test_axum_user_profile_workflow() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    // 1. Create user
    let (_user_data, token) = create_test_user(router.clone()).await;

    // 2. Update profile multiple times
    let update1_data = json!({
        "name": "First Update",
        "username": "firstupdate"
    });

    let request1 = Request::builder()
        .method(Method::POST)
        .uri("/auth/update-user")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(update1_data.to_string()))
        .unwrap();

    let response1 = router.clone().oneshot(request1).await.unwrap();
    assert_eq!(response1.status(), StatusCode::OK);

    // 3. Update profile again
    let update2_data = json!({
        "name": "Second Update",
        "image": "https://example.com/avatar.jpg"
    });

    let request2 = Request::builder()
        .method(Method::POST)
        .uri("/auth/update-user")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(update2_data.to_string()))
        .unwrap();

    let response2 = router.clone().oneshot(request2).await.unwrap();
    assert_eq!(response2.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response2.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    // Should have both updates
    assert_eq!(response_data["user"]["name"], "Second Update");
    assert_eq!(response_data["user"]["username"], "firstupdate"); // Should persist from first update
    assert_eq!(
        response_data["user"]["image"],
        "https://example.com/avatar.jpg"
    );

    // 4. Get current session to verify user data is updated
    let session_request = Request::builder()
        .method(Method::GET)
        .uri("/auth/get-session")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let session_response = router.clone().oneshot(session_request).await.unwrap();
    assert_eq!(session_response.status(), StatusCode::OK);

    let session_body = axum::body::to_bytes(session_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let session_data: Value = serde_json::from_slice(&session_body).unwrap();

    assert_eq!(session_data["user"]["name"], "Second Update");
    assert_eq!(session_data["user"]["username"], "firstupdate");

    // 5. Finally delete the user
    let delete_request = Request::builder()
        .method(Method::DELETE)
        .uri("/auth/delete-user")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let delete_response = router.oneshot(delete_request).await.unwrap();
    assert_eq!(delete_response.status(), StatusCode::OK);
}

/// Test comprehensive authentication workflow
#[tokio::test]
async fn test_axum_complete_workflow() {
    let auth = create_test_auth().await;
    let router = create_test_router(auth);

    // 1. Sign up
    let signup_data = json!({
        "email": "workflow@example.com",
        "password": "password123",
        "name": "Workflow User"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-up/email")
        .header("content-type", "application/json")
        .body(Body::from(signup_data.to_string()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let signup_response: Value = serde_json::from_slice(&body_bytes).unwrap();
    let signup_token = signup_response["token"].as_str().unwrap();

    // 2. Sign in to get a new session
    let signin_data = json!({
        "email": "workflow@example.com",
        "password": "password123"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-in/email")
        .header("content-type", "application/json")
        .body(Body::from(signin_data.to_string()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let signin_response: Value = serde_json::from_slice(&body_bytes).unwrap();
    let signin_token = signin_response["token"].as_str().unwrap();

    // 3. Get session info
    let request = Request::builder()
        .method(Method::GET)
        .uri("/auth/get-session")
        .header("authorization", format!("Bearer {}", signin_token))
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 4. List sessions (should have 2)
    let request = Request::builder()
        .method(Method::GET)
        .uri("/auth/list-sessions")
        .header("authorization", format!("Bearer {}", signin_token))
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let sessions: Vec<Value> = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(sessions.len(), 2);

    // 5. Change password
    let change_data = json!({
        "currentPassword": "password123",
        "newPassword": "newpassword123",
        "revokeOtherSessions": "false"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/change-password")
        .header("authorization", format!("Bearer {}", signin_token))
        .header("content-type", "application/json")
        .body(Body::from(change_data.to_string()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 6. Sign out
    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-out")
        .header("authorization", format!("Bearer {}", signin_token))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 7. Verify session is invalidated
    let request = Request::builder()
        .method(Method::GET)
        .uri("/auth/get-session")
        .header("authorization", format!("Bearer {}", signin_token))
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
