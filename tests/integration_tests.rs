use better_auth::adapters::{
    AccountOps, MemoryDatabaseAdapter, SessionOps, UserOps, VerificationOps,
};
use better_auth::plugins::{
    AccountManagementPlugin, EmailPasswordPlugin, PasswordManagementPlugin, SessionManagementPlugin,
};
use better_auth::{AuthConfig, BetterAuth};
use std::sync::Arc;

#[cfg(feature = "sqlx-postgres")]
use better_auth::adapters::{PoolConfig, SqlxAdapter};

/// Helper to create test BetterAuth instance with memory database
async fn create_test_auth_memory() -> Arc<BetterAuth<MemoryDatabaseAdapter>> {
    let config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000")
        .password_min_length(6);

    Arc::new(
        BetterAuth::<MemoryDatabaseAdapter>::new(config)
            .database(MemoryDatabaseAdapter::new())
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(PasswordManagementPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .build()
            .await
            .expect("Failed to create test auth instance"),
    )
}

/// Helper to create user and get session token
async fn create_test_user_and_session(
    auth: Arc<BetterAuth<MemoryDatabaseAdapter>>,
) -> (String, String) {
    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let signup_data = serde_json::json!({
        "email": "integration@test.com",
        "password": "password123",
        "name": "Integration Test User"
    });

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let signup_request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/sign-up/email".to_string(),
        headers,
        body: Some(signup_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(signup_request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    let user_id = response_data["user"]["id"].as_str().unwrap().to_string();
    let session_token = response_data["token"].as_str().unwrap().to_string();

    (user_id, session_token)
}

/// Integration test for get-session endpoint
#[tokio::test]
async fn test_get_session_integration() {
    let auth = create_test_auth_memory().await;
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/get-session".to_string(),
        headers,
        body: None,
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    assert!(response_data["session"]["token"].is_string());
    assert!(response_data["user"]["id"].is_string());
    assert_eq!(response_data["user"]["email"], "integration@test.com");
}

/// Integration test for sign-out endpoint
#[tokio::test]
async fn test_sign_out_integration() {
    let auth = create_test_auth_memory().await;
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/sign-out".to_string(),
        headers,
        body: Some(b"{}".to_vec()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    assert_eq!(response_data["success"], true);

    // Verify session is no longer valid
    let mut headers2 = HashMap::new();
    headers2.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let get_session_request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/get-session".to_string(),
        headers: headers2,
        body: None,
        query: HashMap::new(),
    };

    let response2 = auth.handle_request(get_session_request).await.unwrap();
    assert_eq!(response2.status, 401); // Session should be invalidated
}

/// Integration test for list-sessions endpoint
#[tokio::test]
async fn test_list_sessions_integration() {
    let auth = create_test_auth_memory().await;
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/list-sessions".to_string(),
        headers,
        body: None,
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let sessions: Vec<serde_json::Value> = serde_json::from_str(&body_str).unwrap();

    assert_eq!(sessions.len(), 1);
    assert!(sessions[0]["token"].is_string());
}

/// Integration test for revoke-session endpoint
#[tokio::test]
async fn test_revoke_session_integration() {
    let auth = create_test_auth_memory().await;
    let (user_id, session_token1) = create_test_user_and_session(auth.clone()).await;

    // Create a second session for the same user
    use better_auth::types::CreateSession;
    use chrono::{Duration, Utc};

    let create_session = CreateSession {
        user_id: user_id.clone(),
        expires_at: Utc::now() + Duration::hours(24),
        ip_address: Some("192.168.1.1".to_string()),
        user_agent: Some("test-agent-2".to_string()),
        impersonated_by: None,
        active_organization_id: None,
    };

    let session2 = auth
        .database()
        .create_session(create_session)
        .await
        .unwrap();

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token1),
    );

    let revoke_data = serde_json::json!({
        "token": session2.token
    });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/revoke-session".to_string(),
        headers,
        body: Some(revoke_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    assert_eq!(response_data["status"], true);
}

/// Integration test for revoke-sessions endpoint
#[tokio::test]
async fn test_revoke_sessions_integration() {
    let auth = create_test_auth_memory().await;
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/revoke-sessions".to_string(),
        headers,
        body: Some(b"{}".to_vec()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    assert_eq!(response_data["status"], true);
}

/// Integration test for unauthorized access
#[tokio::test]
async fn test_unauthorized_session_access() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    // Try to access get-session without token
    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/get-session".to_string(),
        headers: HashMap::new(),
        body: None,
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 401);
}

/// Integration test for forget-password endpoint
#[tokio::test]
async fn test_forget_password_integration() {
    let auth = create_test_auth_memory().await;
    let (_user_id, _session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let forget_data = serde_json::json!({
        "email": "integration@test.com",
        "redirectTo": "http://localhost:3000/reset"
    });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/forget-password".to_string(),
        headers,
        body: Some(forget_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    assert_eq!(response_data["status"], true);
}

/// Integration test for reset-password endpoint
#[tokio::test]
async fn test_reset_password_integration() {
    let auth = create_test_auth_memory().await;
    let (_user_id, _session_token) = create_test_user_and_session(auth.clone()).await;

    // First, create a verification token manually

    use better_auth::types::CreateVerification;
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    let reset_token = format!("reset_{}", Uuid::new_v4());
    let create_verification = CreateVerification {
        identifier: "integration@test.com".to_string(),
        value: reset_token.clone(),
        expires_at: Utc::now() + Duration::hours(24),
    };
    auth.database()
        .create_verification(create_verification)
        .await
        .unwrap();

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let reset_data = serde_json::json!({
        "newPassword": "NewPassword123!",
        "token": reset_token
    });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/reset-password".to_string(),
        headers,
        body: Some(reset_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    assert_eq!(response_data["status"], true);
}

/// Integration test for change-password endpoint
#[tokio::test]
async fn test_change_password_integration() {
    let auth = create_test_auth_memory().await;
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let change_data = serde_json::json!({
        "currentPassword": "password123",
        "newPassword": "NewPassword123!",
        "revokeOtherSessions": "false"
    });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/change-password".to_string(),
        headers,
        body: Some(change_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    assert!(response_data["user"]["id"].is_string());
    assert!(response_data["token"].is_null()); // No new token when not revoking sessions
}

/// Integration test for change-password with session revocation
#[tokio::test]
async fn test_change_password_with_revocation_integration() {
    let auth = create_test_auth_memory().await;
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let change_data = serde_json::json!({
        "currentPassword": "password123",
        "newPassword": "NewPassword123!",
        "revokeOtherSessions": "true"
    });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/change-password".to_string(),
        headers,
        body: Some(change_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    assert!(response_data["user"]["id"].is_string());
    assert!(response_data["token"].is_string()); // New token when revoking sessions
}

/// Integration test for reset-password token endpoint
#[tokio::test]
async fn test_reset_password_token_integration() {
    let auth = create_test_auth_memory().await;
    let (_user_id, _session_token) = create_test_user_and_session(auth.clone()).await;

    // Create a verification token manually

    use better_auth::types::CreateVerification;
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    let reset_token = format!("reset_{}", Uuid::new_v4());
    let create_verification = CreateVerification {
        identifier: "integration@test.com".to_string(),
        value: reset_token.clone(),
        expires_at: Utc::now() + Duration::hours(24),
    };
    auth.database()
        .create_verification(create_verification)
        .await
        .unwrap();

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: format!("/reset-password/{}", reset_token),
        headers: HashMap::new(),
        body: None,
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    assert_eq!(response_data["token"], reset_token);
}

/// Integration test for /ok endpoint
#[tokio::test]
async fn test_ok_endpoint() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/ok".to_string(),
        headers: HashMap::new(),
        body: None,
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(response_data["status"], true);
}

/// Integration test for /error endpoint
#[tokio::test]
async fn test_error_endpoint() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/error".to_string(),
        headers: HashMap::new(),
        body: None,
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(response_data["status"], false);
}

/// Integration test for POST /get-session (in addition to GET)
#[tokio::test]
async fn test_get_session_post_integration() {
    let auth = create_test_auth_memory().await;
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/get-session".to_string(),
        headers,
        body: Some(b"{}".to_vec()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    assert!(response_data["session"]["token"].is_string());
    assert!(response_data["user"]["id"].is_string());
    assert_eq!(response_data["user"]["email"], "integration@test.com");
}

/// Integration test for POST /delete-user (changed from DELETE)
#[tokio::test]
async fn test_delete_user_post_method() {
    let auth = create_test_auth_memory().await;
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/delete-user".to_string(),
        headers,
        body: Some(b"{}".to_vec()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(response_data["success"], true);
}

/// Integration test for set-password success (social-only user, no password)
#[tokio::test]
async fn test_set_password_success() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::{AuthRequest, CreateSession, CreateUser};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    // Create a user WITHOUT a password (social-only account)
    let create_user = CreateUser::new()
        .with_email("social@test.com")
        .with_name("Social User");
    let user = auth.database().create_user(create_user).await.unwrap();

    let create_session = CreateSession {
        user_id: user.id.clone(),
        expires_at: Utc::now() + Duration::hours(24),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
    };
    let session = auth
        .database()
        .create_session(create_session)
        .await
        .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session.token),
    );

    let set_data = serde_json::json!({
        "newPassword": "MyNewPassword123"
    });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/set-password".to_string(),
        headers,
        body: Some(set_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(response_data["status"], true);
}

/// Integration test for set-password when user already has a password → 400
#[tokio::test]
async fn test_set_password_already_has_password() {
    let auth = create_test_auth_memory().await;
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let set_data = serde_json::json!({
        "newPassword": "AnotherPassword123"
    });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/set-password".to_string(),
        headers,
        body: Some(set_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 400);
}

/// Integration test for set-password unauthenticated → 401
#[tokio::test]
async fn test_set_password_unauthenticated() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let set_data = serde_json::json!({
        "newPassword": "SomePassword123"
    });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/set-password".to_string(),
        headers,
        body: Some(set_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 401);
}

/// Integration test for revoke-other-sessions endpoint
#[tokio::test]
async fn test_revoke_other_sessions_integration() {
    let auth = create_test_auth_memory().await;
    let (user_id, session_token1) = create_test_user_and_session(auth.clone()).await;

    // Create a second session for the same user

    use better_auth::types::{AuthRequest, CreateSession};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    let create_session = CreateSession {
        user_id: user_id.clone(),
        expires_at: Utc::now() + Duration::hours(24),
        ip_address: Some("192.168.1.1".to_string()),
        user_agent: Some("other-agent".to_string()),
        impersonated_by: None,
        active_organization_id: None,
    };
    let session2 = auth
        .database()
        .create_session(create_session)
        .await
        .unwrap();

    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token1),
    );

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/revoke-other-sessions".to_string(),
        headers,
        body: Some(b"{}".to_vec()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    // The current session should still be valid
    let s1 = auth.database().get_session(&session_token1).await.unwrap();
    assert!(s1.is_some());

    // The other session should be revoked
    let s2 = auth.database().get_session(&session2.token).await.unwrap();
    assert!(s2.is_none());
}

/// Integration test for cookie-based authentication
#[tokio::test]
async fn test_cookie_based_auth() {
    let auth = create_test_auth_memory().await;
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    // Use cookie header instead of Bearer token
    let mut headers = HashMap::new();
    headers.insert(
        "cookie".to_string(),
        format!("better-auth.session-token={}; other=value", session_token),
    );

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/get-session".to_string(),
        headers,
        body: None,
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(response_data["user"]["email"], "integration@test.com");
}

/// Integration test: Bearer token takes precedence over cookie
#[tokio::test]
async fn test_bearer_takes_precedence_over_cookie() {
    let auth = create_test_auth_memory().await;
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    // Provide both Bearer and cookie, but cookie has invalid token
    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );
    headers.insert(
        "cookie".to_string(),
        "better-auth.session-token=invalid_token".to_string(),
    );

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/get-session".to_string(),
        headers,
        body: None,
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    // Should succeed because Bearer token takes precedence
    assert_eq!(response.status, 200);
}

/// Integration test for unauthorized password operations
#[tokio::test]
async fn test_unauthorized_password_operations() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let change_data = serde_json::json!({
        "currentPassword": "password123",
        "newPassword": "NewPassword123!"
    });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/change-password".to_string(),
        headers,
        body: Some(change_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 401);
}
/// Integration test for change-email success
#[tokio::test]
async fn test_change_email_success() {
    let auth = create_test_auth_memory().await;
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let body = serde_json::json!({ "newEmail": "newemail@test.com" });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/change-email".to_string(),
        headers,
        body: Some(body.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["status"], true);
    assert_eq!(data["message"], "Email updated");
}

/// Integration test for change-email duplicate → 409
#[tokio::test]
async fn test_change_email_duplicate() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::{AuthRequest, CreateUser};
    use std::collections::HashMap;

    // Create first user
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    // Create second user with a different email
    let create_user = CreateUser::new()
        .with_email("existing@test.com")
        .with_name("Existing User");
    auth.database().create_user(create_user).await.unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let body = serde_json::json!({ "newEmail": "existing@test.com" });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/change-email".to_string(),
        headers,
        body: Some(body.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 409);
}

/// Integration test for change-email unauthenticated → 401
#[tokio::test]
async fn test_change_email_unauthenticated() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let body = serde_json::json!({ "newEmail": "x@y.com" });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/change-email".to_string(),
        headers,
        body: Some(body.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 401);
}

/// Integration test for delete-user/callback success
#[tokio::test]
async fn test_delete_user_callback_success() {
    let auth = create_test_auth_memory().await;
    let (user_id, _session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::{AuthRequest, CreateVerification};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    // Create a deletion verification token
    let token = format!("delete_{}", uuid::Uuid::new_v4());
    let create_verification = CreateVerification {
        identifier: user_id.clone(),
        value: token.clone(),
        expires_at: Utc::now() + Duration::hours(24),
    };
    auth.database()
        .create_verification(create_verification)
        .await
        .unwrap();

    let mut query = HashMap::new();
    query.insert("token".to_string(), token);

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/delete-user/callback".to_string(),
        headers: HashMap::new(),
        body: None,
        query,
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["success"], true);

    // Verify user is deleted
    let user = auth.database().get_user_by_id(&user_id).await.unwrap();
    assert!(user.is_none());
}

/// Integration test for delete-user/callback invalid token → 400
#[tokio::test]
async fn test_delete_user_callback_invalid_token() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut query = HashMap::new();
    query.insert("token".to_string(), "invalid_token".to_string());

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/delete-user/callback".to_string(),
        headers: HashMap::new(),
        body: None,
        query,
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 400);
}

/// Integration test for list-accounts (empty)
#[tokio::test]
async fn test_list_accounts_empty() {
    let auth = create_test_auth_memory().await;
    let (_user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/list-accounts".to_string(),
        headers,
        body: None,
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let accounts: Vec<serde_json::Value> = serde_json::from_str(&body_str).unwrap();
    assert_eq!(accounts.len(), 0); // No linked accounts yet
}

/// Integration test for list-accounts with an account
#[tokio::test]
async fn test_list_accounts_with_account() {
    let auth = create_test_auth_memory().await;
    let (user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::{AuthRequest, CreateAccount};
    use std::collections::HashMap;

    // Create an account for the user
    let create_account = CreateAccount {
        account_id: "12345".to_string(),
        provider_id: "google".to_string(),
        user_id: user_id.clone(),
        access_token: Some("access_token".to_string()),
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: Some("email profile".to_string()),
        password: None,
    };
    auth.database()
        .create_account(create_account)
        .await
        .unwrap();

    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/list-accounts".to_string(),
        headers,
        body: None,
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let accounts: Vec<serde_json::Value> = serde_json::from_str(&body_str).unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["provider"], "google");
    assert_eq!(
        accounts[0]["scopes"],
        serde_json::json!(["email", "profile"])
    );
    // Sensitive fields should NOT be present
    assert!(accounts[0].get("access_token").is_none());
    assert!(accounts[0].get("password").is_none());
}

/// Integration test for unlink-account success
#[tokio::test]
async fn test_unlink_account_success() {
    let auth = create_test_auth_memory().await;
    let (user_id, session_token) = create_test_user_and_session(auth.clone()).await;

    use better_auth::types::{AuthRequest, CreateAccount};
    use std::collections::HashMap;

    // Create two accounts
    for provider in &["google", "github"] {
        let create_account = CreateAccount {
            account_id: format!("id_{}", provider),
            provider_id: provider.to_string(),
            user_id: user_id.clone(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: None,
        };
        auth.database()
            .create_account(create_account)
            .await
            .unwrap();
    }

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session_token),
    );

    let unlink_data = serde_json::json!({
        "providerId": "google"
    });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/unlink-account".to_string(),
        headers,
        body: Some(unlink_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    // Verify only one account remains
    let accounts = auth.database().get_user_accounts(&user_id).await.unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].provider_id, "github");
}

/// Integration test for unlink-account last credential → 400
#[tokio::test]
async fn test_unlink_last_account_fails() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::{AuthRequest, CreateAccount, CreateSession, CreateUser};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    // Create a social-only user (NO password)
    let create_user = CreateUser::new()
        .with_email("social-only@test.com")
        .with_name("Social Only");
    let user = auth.database().create_user(create_user).await.unwrap();

    let create_session = CreateSession {
        user_id: user.id.clone(),
        expires_at: Utc::now() + Duration::hours(24),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
    };
    let session = auth
        .database()
        .create_session(create_session)
        .await
        .unwrap();

    // Add one account
    let create_account = CreateAccount {
        account_id: "id_google".to_string(),
        provider_id: "google".to_string(),
        user_id: user.id.clone(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: None,
    };
    auth.database()
        .create_account(create_account)
        .await
        .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", session.token),
    );

    let unlink_data = serde_json::json!({
        "providerId": "google"
    });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/unlink-account".to_string(),
        headers,
        body: Some(unlink_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 400); // Cannot unlink last credential
}

/// Integration test for list-accounts unauthenticated → 401
#[tokio::test]
async fn test_list_accounts_unauthenticated() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/list-accounts".to_string(),
        headers: HashMap::new(),
        body: None,
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 401);
}

/*
/// Test basic Axum integration with memory database
#[tokio::test]
async fn test_axum_health_check() {
    let auth = create_test_auth_memory().await;

    let request = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = call_service(auth, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response_json["status"], "ok");
    assert_eq!(response_json["service"], "better-auth");
}

/// Test signup via Axum integration
#[tokio::test]
async fn test_axum_signup() {
    let auth = create_test_auth_memory().await;

    let signup_data = json!({
        "email": "axum@example.com",
        "password": "password123",
        "name": "Axum User"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/sign-up")
        .header("content-type", "application/json")
        .body(Body::from(signup_data.to_string()))
        .unwrap();

    let response = call_service(auth, request).await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let response_json: Value = serde_json::from_slice(&body).unwrap();

    assert!(response_json["user"]["id"].is_string());
    assert_eq!(response_json["user"]["email"], "axum@example.com");
    assert_eq!(response_json["user"]["name"], "Axum User");
    assert!(response_json["session_token"].is_string());
}

/// Test signin via Axum integration
#[tokio::test]
async fn test_axum_signin() {
    let auth = create_test_auth_memory().await;

    // First signup
    let signup_data = json!({
        "email": "axum_signin@example.com",
        "password": "password123",
        "name": "Axum Signin User"
    });

    let signup_request = Request::builder()
        .method(Method::POST)
        .uri("/sign-up")
        .header("content-type", "application/json")
        .body(Body::from(signup_data.to_string()))
        .unwrap();

    let signup_response = call_service(auth.clone(), signup_request).await;
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Then signin
    let signin_data = json!({
        "email": "axum_signin@example.com",
        "password": "password123"
    });

    let signin_request = Request::builder()
        .method(Method::POST)
        .uri("/sign-in")
        .header("content-type", "application/json")
        .body(Body::from(signin_data.to_string()))
        .unwrap();

    let signin_response = call_service(auth, signin_request).await;

    assert_eq!(signin_response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(signin_response.into_body(), usize::MAX).await.unwrap();
    let response_json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response_json["user"]["email"], "axum_signin@example.com");
    assert!(response_json["session_token"].is_string());
}

/// Test error handling in Axum integration
#[tokio::test]
async fn test_axum_error_handling() {
    let auth = create_test_auth_memory().await;

    // Test invalid JSON
    let request = Request::builder()
        .method(Method::POST)
        .uri("/sign-up")
        .header("content-type", "application/json")
        .body(Body::from("invalid json"))
        .unwrap();

    let response = call_service(auth.clone(), request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test missing required fields
    let incomplete_data = json!({
        "email": "incomplete@example.com"
        // missing password
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/sign-up")
        .header("content-type", "application/json")
        .body(Body::from(incomplete_data.to_string()))
        .unwrap();

    let response = call_service(auth.clone(), request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test non-existent route
    let request = Request::builder()
        .method(Method::GET)
        .uri("/non-existent")
        .body(Body::empty())
        .unwrap();

    let response = call_service(auth, request).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Test duplicate email handling
#[tokio::test]
async fn test_axum_duplicate_email() {
    let auth = create_test_auth_memory().await;

    let signup_data = json!({
        "email": "duplicate_axum@example.com",
        "password": "password123"
    });

    let request1 = Request::builder()
        .method(Method::POST)
        .uri("/sign-up")
        .header("content-type", "application/json")
        .body(Body::from(signup_data.to_string()))
        .unwrap();

    let response1 = call_service(auth.clone(), request1).await;
    assert_eq!(response1.status(), StatusCode::CREATED);

    let request2 = Request::builder()
        .method(Method::POST)
        .uri("/sign-up")
        .header("content-type", "application/json")
        .body(Body::from(signup_data.to_string()))
        .unwrap();

    let response2 = call_service(auth, request2).await;
    assert_eq!(response2.status(), StatusCode::CONFLICT);
}

#[cfg(feature = "sqlx-postgres")]
mod postgres_tests {
    use super::*;
    use std::env;

    /// Helper to create test BetterAuth instance with PostgreSQL
    async fn create_test_auth_postgres() -> Option<Arc<BetterAuth<SqlxAdapter>>> {
        let database_url = env::var("TEST_DATABASE_URL").ok()?;

        let pool_config = PoolConfig {
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(10),
            idle_timeout: Some(std::time::Duration::from_secs(300)),
            max_lifetime: Some(std::time::Duration::from_secs(1800)),
        };

        let database = SqlxAdapter::with_config(&database_url, pool_config).await.ok()?;

        // Test connection
        database.test_connection().await.ok()?;

        let config = AuthConfig::new("postgres-test-secret-key-32-chars-long")
            .base_url("http://localhost:3000")
            .password_min_length(6);

        let auth = BetterAuth::<SqlxAdapter>::new(config)
            .database(database)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .build()
            .await
            .ok()?;

        Some(Arc::new(auth))
    }

    /// Setup test database (run migrations, clean tables)
    async fn setup_test_database() -> Option<()> {
        let database_url = env::var("TEST_DATABASE_URL").ok()?;
        let pool = sqlx::PgPool::connect(&database_url).await.ok()?;

        // Clean up test data
        sqlx::query("DELETE FROM sessions WHERE user_id LIKE 'test_%'")
            .execute(&pool)
            .await
            .ok()?;

        sqlx::query("DELETE FROM users WHERE email LIKE '%test.example%'")
            .execute(&pool)
            .await
            .ok()?;

        pool.close().await;
        Some(())
    }

    /// Test PostgreSQL signup
    #[tokio::test]
    async fn test_postgres_signup() {
        if setup_test_database().await.is_none() {
            println!("Skipping PostgreSQL test - TEST_DATABASE_URL not set or database unavailable");
            return;
        }

        let Some(auth) = create_test_auth_postgres().await else {
            println!("Skipping PostgreSQL test - database setup failed");
            return;
        };

        let signup_data = json!({
            "email": "postgres.test.example@test.com",
            "password": "password123",
            "name": "PostgreSQL Test User"
        });

        let request = Request::builder()
            .method(Method::POST)
            .uri("/sign-up")
            .header("content-type", "application/json")
            .body(Body::from(signup_data.to_string()))
            .unwrap();

        let response = call_service(auth, request).await;

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response_json: Value = serde_json::from_slice(&body).unwrap();

        assert!(response_json["user"]["id"].is_string());
        assert_eq!(response_json["user"]["email"], "postgres.test.example@test.com");
        assert_eq!(response_json["user"]["name"], "PostgreSQL Test User");
        assert!(response_json["session_token"].is_string());
    }

    /// Test PostgreSQL signin
    #[tokio::test]
    async fn test_postgres_signin() {
        if setup_test_database().await.is_none() {
            println!("Skipping PostgreSQL test - TEST_DATABASE_URL not set or database unavailable");
            return;
        }

        let Some(auth) = create_test_auth_postgres().await else {
            println!("Skipping PostgreSQL test - database setup failed");
            return;
        };

        // First signup
        let signup_data = json!({
            "email": "postgres.signin.test.example@test.com",
            "password": "password123",
            "name": "PostgreSQL Signin User"
        });

        let signup_request = Request::builder()
            .method(Method::POST)
            .uri("/sign-up")
            .header("content-type", "application/json")
            .body(Body::from(signup_data.to_string()))
            .unwrap();

        let signup_response = call_service(auth.clone(), signup_request).await;
        assert_eq!(signup_response.status(), StatusCode::CREATED);

        // Then signin
        let signin_data = json!({
            "email": "postgres.signin.test.example@test.com",
            "password": "password123"
        });

        let signin_request = Request::builder()
            .method(Method::POST)
            .uri("/sign-in")
            .header("content-type", "application/json")
            .body(Body::from(signin_data.to_string()))
            .unwrap();

        let signin_response = call_service(auth, signin_request).await;

        assert_eq!(signin_response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(signin_response.into_body(), usize::MAX).await.unwrap();
        let response_json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(response_json["user"]["email"], "postgres.signin.test.example@test.com");
        assert!(response_json["session_token"].is_string());
    }

    /// Test PostgreSQL connection pool and session persistence
    #[tokio::test]
    async fn test_postgres_session_persistence() {
        if setup_test_database().await.is_none() {
            println!("Skipping PostgreSQL test - TEST_DATABASE_URL not set or database unavailable");
            return;
        }

        let Some(auth) = create_test_auth_postgres().await else {
            println!("Skipping PostgreSQL test - database setup failed");
            return;
        };

        // Create a user and session directly via database
        let database = auth.database();
        let session_manager = auth.session_manager();

        let create_user = better_auth::types::CreateUser::new()
            .with_email("session.persistence.test.example@test.com")
            .with_name("Session Persistence User");

        let user = database.create_user(create_user).await.expect("Failed to create user");

        // Create a session
        let session = session_manager.create_session(&user,
            Some("127.0.0.1".to_string()),
            Some("test-user-agent".to_string())
        ).await.expect("Failed to create session");

        // Verify session can be retrieved
        let retrieved_session = session_manager.get_session(&session.token).await
            .expect("Failed to get session")
            .expect("Session not found");

        assert_eq!(retrieved_session.user_id, user.id);
        assert_eq!(retrieved_session.ip_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(retrieved_session.user_agent.as_deref(), Some("test-user-agent"));

        // Test session cleanup
        let cleaned_count = session_manager.cleanup_expired_sessions().await
            .expect("Failed to cleanup sessions");

        // Should be 0 since session is not expired
        assert_eq!(cleaned_count, 0);

        // Delete the session
        session_manager.delete_session(&session.token).await
            .expect("Failed to delete session");

        // Verify session is gone
        let deleted_session = session_manager.get_session(&session.token).await
            .expect("Failed to check deleted session");
        assert!(deleted_session.is_none());
    }

    /// Test PostgreSQL constraint violations (duplicate email)
    #[tokio::test]
    async fn test_postgres_constraints() {
        if setup_test_database().await.is_none() {
            println!("Skipping PostgreSQL test - TEST_DATABASE_URL not set or database unavailable");
            return;
        }

        let Some(auth) = create_test_auth_postgres().await else {
            println!("Skipping PostgreSQL test - database setup failed");
            return;
        };

        let signup_data = json!({
            "email": "constraint.test.example@test.com",
            "password": "password123"
        });

        // First signup should succeed
        let request1 = Request::builder()
            .method(Method::POST)
            .uri("/sign-up")
            .header("content-type", "application/json")
            .body(Body::from(signup_data.to_string()))
            .unwrap();

        let response1 = call_service(auth.clone(), request1).await;
        assert_eq!(response1.status(), StatusCode::CREATED);

        // Second signup with same email should fail
        let request2 = Request::builder()
            .method(Method::POST)
            .uri("/sign-up")
            .header("content-type", "application/json")
            .body(Body::from(signup_data.to_string()))
            .unwrap();

        let response2 = call_service(auth, request2).await;
        assert_eq!(response2.status(), StatusCode::CONFLICT);
    }
}

/// Performance test for concurrent requests
#[tokio::test]
async fn test_concurrent_requests() {
    let auth = create_test_auth_memory().await;

    let mut tasks = Vec::new();

    for i in 0..10 {
        let auth_clone = auth.clone();
        let task = tokio::spawn(async move {
            let signup_data = json!({
                "email": format!("concurrent{}@example.com", i),
                "password": "password123",
                "name": format!("Concurrent User {}", i)
            });

            let request = Request::builder()
                .method(Method::POST)
                .uri("/sign-up")
                .header("content-type", "application/json")
                .body(Body::from(signup_data.to_string()))
                .unwrap();

            call_service(auth_clone, request).await
        });

        tasks.push(task);
    }

    // Wait for all tasks to complete
    for task in tasks {
        let result = task.await;
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }
}
*/

// ---------------------------------------------------------------------------
// Username Support Tests (Stage 1.7)
// ---------------------------------------------------------------------------

/// Sign up with username, then sign in by username
#[tokio::test]
async fn test_sign_up_with_username_and_sign_in() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    // Sign up with username
    let signup_data = serde_json::json!({
        "email": "usernameguy@test.com",
        "password": "password123",
        "name": "Username Guy",
        "username": "cool_user",
        "displayUsername": "Cool User"
    });

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/sign-up/email".to_string(),
        headers: headers.clone(),
        body: Some(signup_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["user"]["username"], "cool_user");
    assert_eq!(data["user"]["displayUsername"], "Cool User");

    // Now sign in by username
    let signin_data = serde_json::json!({
        "username": "cool_user",
        "password": "password123"
    });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/sign-in/username".to_string(),
        headers,
        body: Some(signin_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert!(data["token"].is_string());
    assert_eq!(data["user"]["username"], "cool_user");
    assert_eq!(data["user"]["email"], "usernameguy@test.com");
}

/// Sign in by username with wrong password → 401
#[tokio::test]
async fn test_sign_in_username_wrong_password() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    // Sign up with username
    let signup_data = serde_json::json!({
        "email": "wrongpw@test.com",
        "password": "password123",
        "name": "Wrong PW",
        "username": "wrongpw_user"
    });

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/sign-up/email".to_string(),
        headers: headers.clone(),
        body: Some(signup_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    auth.handle_request(request).await.unwrap();

    // Sign in with wrong password
    let signin_data = serde_json::json!({
        "username": "wrongpw_user",
        "password": "wrong_password"
    });

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/sign-in/username".to_string(),
        headers,
        body: Some(signin_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 401);
}

/// Sign in by nonexistent username → 401
#[tokio::test]
async fn test_sign_in_username_nonexistent() {
    let auth = create_test_auth_memory().await;

    use better_auth::types::AuthRequest;
    use std::collections::HashMap;

    let signin_data = serde_json::json!({
        "username": "no_such_user",
        "password": "password123"
    });

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let request = AuthRequest {
        method: better_auth::types::HttpMethod::Post,
        path: "/sign-in/username".to_string(),
        headers,
        body: Some(signin_data.to_string().into_bytes()),
        query: HashMap::new(),
    };

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 401);
}

/// get_user_by_username works via database adapter
#[tokio::test]
async fn test_get_user_by_username_adapter() {
    use better_auth::adapters::MemoryDatabaseAdapter;
    use better_auth::types::CreateUser;

    let db = MemoryDatabaseAdapter::new();

    // Create user with username
    let create = CreateUser::new()
        .with_email("dbtest@test.com")
        .with_name("DB Test")
        .with_username("db_user");

    let user = db.create_user(create).await.unwrap();

    // Lookup by username
    let found = db.get_user_by_username("db_user").await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, user.id);

    // Lookup nonexistent
    let not_found = db.get_user_by_username("no_user").await.unwrap();
    assert!(not_found.is_none());
}
