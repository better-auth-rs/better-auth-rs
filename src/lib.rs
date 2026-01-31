//! # Better Auth - Rust
//!
//! A comprehensive authentication framework for Rust, inspired by Better-Auth.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use better_auth::{BetterAuth, AuthConfig};
//! use better_auth::plugins::EmailPasswordPlugin;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = AuthConfig::new("your-secret-key-that-is-at-least-32-chars");
//!
//!     let auth = BetterAuth::new(config)
//!         .plugin(EmailPasswordPlugin::new())
//!         .build()
//!         .await?;
//!
//!     Ok(())
//! }
//! ```

// Core module — BetterAuth struct lives here in the root crate
// because it orchestrates plugins (from better-auth-api) + core (from better-auth-core)
pub mod core;
pub mod handlers;

// Re-export core abstractions
pub use better_auth_core as types_mod;
pub use better_auth_core::{
    Account,
    Argon2Config,
    // Config
    AuthConfig,
    AuthContext,
    // Error
    AuthError,
    // Plugin system
    AuthPlugin,
    AuthRequest,
    AuthResponse,
    AuthResult,
    AuthRoute,
    BodyLimitConfig,
    BodyLimitMiddleware,
    CacheAdapter,
    ConsoleEmailProvider,
    CorsConfig,
    CorsMiddleware,
    CreateAccount,
    CreateSession,
    CreateUser,
    CreateVerification,
    CsrfConfig,
    CsrfMiddleware,
    // Adapters
    DatabaseAdapter,
    DatabaseError,
    // Hooks
    DatabaseHooks,
    DeleteUserResponse,
    // Email
    EmailProvider,
    EndpointRateLimit,
    HookedDatabaseAdapter,
    HttpMethod,
    JwtConfig,
    MemoryCacheAdapter,
    MemoryDatabaseAdapter,
    // Middleware
    Middleware,
    OpenApiBuilder,
    // OpenAPI
    OpenApiSpec,
    Passkey,
    PasswordConfig,
    RateLimitConfig,
    RateLimitMiddleware,
    SameSite,
    Session,
    SessionConfig,
    // Session
    SessionManager,
    TwoFactor,
    UpdateUser,
    UpdateUserRequest,
    UpdateUserResponse,
    // Types
    User,
    Verification,
};

// Re-export types under `types` module for backwards compatibility
pub mod types {
    pub use better_auth_core::{
        Account, AuthRequest, AuthResponse, CreateAccount, CreateSession, CreateUser,
        CreateVerification, DeleteUserResponse, HttpMethod, Passkey, Session, TwoFactor,
        UpdateUser, UpdateUserRequest, UpdateUserResponse, User, Verification,
    };
}

// Re-export adapters
pub mod adapters {
    pub use better_auth_core::{
        CacheAdapter, DatabaseAdapter, MemoryCacheAdapter, MemoryDatabaseAdapter,
    };
}

// Re-export plugins
pub mod plugins {
    pub use better_auth_api::plugins::*;
    pub use better_auth_api::*;
}

// Re-export the main BetterAuth struct
pub use core::{AuthBuilder, BetterAuth};

#[cfg(feature = "axum")]
pub use handlers::axum::AxumIntegration;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    fn test_config() -> AuthConfig {
        AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
            .base_url("http://localhost:3000")
            .password_min_length(8)
    }

    async fn create_test_auth() -> BetterAuth {
        BetterAuth::new(test_config())
            .database(MemoryDatabaseAdapter::new())
            .plugin(plugins::EmailPasswordPlugin::new().enable_signup(true))
            .build()
            .await
            .expect("Failed to create test auth instance")
    }

    #[tokio::test]
    async fn test_auth_builder() {
        let auth = create_test_auth().await;
        assert_eq!(auth.plugin_names(), vec!["email-password"]);
        assert_eq!(
            auth.config().secret,
            "test-secret-key-that-is-at-least-32-characters-long"
        );
    }

    #[tokio::test]
    async fn test_signup_flow() {
        let auth = create_test_auth().await;

        let signup_data = json!({
            "email": "test@example.com",
            "password": "password123",
            "name": "Test User"
        });

        let mut request = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
        request.body = Some(signup_data.to_string().into_bytes());
        request
            .headers
            .insert("content-type".to_string(), "application/json".to_string());

        let response = auth
            .handle_request(request)
            .await
            .expect("Signup request failed");

        assert_eq!(response.status, 200);

        let response_json: serde_json::Value =
            serde_json::from_slice(&response.body).expect("Failed to parse response JSON");

        assert!(response_json["user"]["id"].is_string());
        assert_eq!(response_json["user"]["email"], "test@example.com");
        assert_eq!(response_json["user"]["name"], "Test User");
        assert!(response_json["token"].is_string());
    }

    #[tokio::test]
    async fn test_signin_flow() {
        let auth = create_test_auth().await;

        // First, create a user
        let signup_data = json!({
            "email": "signin@example.com",
            "password": "password123",
            "name": "Signin User"
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

        // Now test signin
        let signin_data = json!({
            "email": "signin@example.com",
            "password": "password123"
        });

        let mut signin_request = AuthRequest::new(HttpMethod::Post, "/sign-in/email");
        signin_request.body = Some(signin_data.to_string().into_bytes());
        signin_request
            .headers
            .insert("content-type".to_string(), "application/json".to_string());

        let signin_response = auth
            .handle_request(signin_request)
            .await
            .expect("Signin failed");
        assert_eq!(signin_response.status, 200);

        let response_json: serde_json::Value =
            serde_json::from_slice(&signin_response.body).expect("Failed to parse signin response");

        assert_eq!(response_json["user"]["email"], "signin@example.com");
        assert!(response_json["token"].is_string());
    }

    #[tokio::test]
    async fn test_duplicate_email_signup() {
        let auth = create_test_auth().await;

        let signup_data = json!({
            "name": "Duplicate User",
            "email": "duplicate@example.com",
            "password": "password123"
        });

        let mut request = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
        request.body = Some(signup_data.to_string().into_bytes());
        request
            .headers
            .insert("content-type".to_string(), "application/json".to_string());

        // First signup should succeed
        let response1 = auth
            .handle_request(request.clone())
            .await
            .expect("First signup failed");
        assert_eq!(response1.status, 200);

        // Second signup with same email should fail
        let response2 = auth
            .handle_request(request)
            .await
            .expect("Second signup request failed");
        assert_eq!(response2.status, 409);
    }

    #[tokio::test]
    async fn test_invalid_credentials_signin() {
        let auth = create_test_auth().await;

        // Try to signin with non-existent user
        let signin_data = json!({
            "email": "nonexistent@example.com",
            "password": "password123"
        });

        let mut request = AuthRequest::new(HttpMethod::Post, "/sign-in/email");
        request.body = Some(signin_data.to_string().into_bytes());
        request
            .headers
            .insert("content-type".to_string(), "application/json".to_string());

        let response = auth
            .handle_request(request)
            .await
            .expect("Request should not panic");
        assert_eq!(response.status, 401);
    }

    #[tokio::test]
    async fn test_weak_password_validation() {
        let auth = create_test_auth().await;

        let signup_data = json!({
            "email": "weak@example.com",
            "password": "123", // Too short
            "name": "Weak Password User"
        });

        let mut request = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
        request.body = Some(signup_data.to_string().into_bytes());
        request
            .headers
            .insert("content-type".to_string(), "application/json".to_string());

        let response = auth
            .handle_request(request)
            .await
            .expect("Request should not panic");
        assert_eq!(response.status, 400);

        let response_json: serde_json::Value =
            serde_json::from_slice(&response.body).expect("Failed to parse response");
        assert!(
            response_json["message"]
                .as_str()
                .unwrap_or("")
                .contains("Password must be at least")
        );
    }

    #[tokio::test]
    async fn test_session_management() {
        let auth = create_test_auth().await;
        let session_manager = auth.session_manager();

        // Create a test user first
        let database = auth.database();
        let create_user = CreateUser::new()
            .with_email("session@example.com")
            .with_name("Session User");

        let user = database
            .create_user(create_user)
            .await
            .expect("Failed to create user");

        // Create a session
        let session = session_manager
            .create_session(&user, None, None)
            .await
            .expect("Failed to create session");

        assert!(session.token.starts_with("session_"));
        assert_eq!(session.user_id, user.id);
        assert!(session.active);

        // Retrieve the session
        let retrieved_session = session_manager
            .get_session(&session.token)
            .await
            .expect("Failed to get session")
            .expect("Session not found");

        assert_eq!(retrieved_session.id, session.id);
        assert_eq!(retrieved_session.user_id, user.id);

        // Delete the session
        session_manager
            .delete_session(&session.token)
            .await
            .expect("Failed to delete session");

        // Verify session is deleted
        let deleted_session = session_manager
            .get_session(&session.token)
            .await
            .expect("Failed to check deleted session");
        assert!(deleted_session.is_none());
    }

    #[tokio::test]
    async fn test_token_format_validation() {
        let auth = create_test_auth().await;
        let session_manager = auth.session_manager();

        // Valid token format: "session_" + base64 encoded 32 bytes = "session_" + 43 chars
        assert!(
            session_manager
                .validate_token_format("session_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
        );
        assert!(!session_manager.validate_token_format("invalid_token"));
        assert!(!session_manager.validate_token_format("session_short"));
        assert!(!session_manager.validate_token_format(""));
    }

    #[tokio::test]
    async fn test_health_check_route() {
        let auth = create_test_auth().await;

        let request = AuthRequest::new(HttpMethod::Get, "/health");
        let response = auth
            .handle_request(request)
            .await
            .expect("Health check failed");

        // Health check should return 404 since no plugin handles it
        // In a real Axum integration, this would be handled by the router
        assert_eq!(response.status, 404);
    }

    #[tokio::test]
    async fn test_config_validation() {
        // Test empty secret
        let config = AuthConfig::new("");
        assert!(config.validate().is_err());

        // Test short secret
        let config = AuthConfig::new("short");
        assert!(config.validate().is_err());

        // Test valid secret but no database
        let config = AuthConfig::new("this-is-a-valid-32-character-secret-key");
        assert!(config.validate().is_err());

        // Test valid config
        let mut config = AuthConfig::new("this-is-a-valid-32-character-secret-key");
        config.database = Some(Arc::new(MemoryDatabaseAdapter::new()));
        assert!(config.validate().is_ok());
    }
}
