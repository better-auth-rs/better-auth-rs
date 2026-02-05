use axum::{
    Json, Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use better_auth::adapters::MemoryDatabaseAdapter;
use better_auth::handlers::AxumIntegration;
use better_auth::plugins::{
    AccountManagementPlugin, EmailPasswordPlugin, OrganizationPlugin,
    PasswordManagementPlugin, SessionManagementPlugin,
};
use better_auth::{AuthConfig, BetterAuth};
use chrono;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

#[derive(Serialize, Deserialize)]
struct UserProfile {
    id: String,
    email: String,
    name: Option<String>,
    created_at: String,
}

#[derive(Serialize, Deserialize)]
struct ApiResponse<T = ()> {
    success: bool,
    data: Option<T>,
    message: String,
}

impl<T> ApiResponse<T> {
    fn success(data: T, message: &str) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: message.to_string(),
        }
    }

    fn error(message: &str) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            message: message.to_string(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for better logging
    tracing_subscriber::fmt::init();

    println!("🚀 Starting Better Auth Axum Server");

    // Create configuration
    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:8080")
        .password_min_length(6);

    println!("📋 Configuration created");

    // Create database adapter (use in-memory for this example)
    let database = MemoryDatabaseAdapter::new();

    // Build the authentication system
    let auth = Arc::new(
        BetterAuth::new(config)
            .database(database)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(PasswordManagementPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .plugin(OrganizationPlugin::new())
            .build()
            .await?,
    );

    println!("🔐 BetterAuth instance created");
    println!("📝 Registered plugins: {:?}", auth.plugin_names());

    // Create the main application router
    let app = create_app_router(auth).await;

    println!("🌐 Starting server on http://localhost:8080");
    println!("📖 Available endpoints:");
    println!("   Authentication:");
    println!("     POST /auth/sign-up/email       - Sign up with email/password");
    println!("     POST /auth/sign-in/email       - Sign in with email/password");
    println!("     POST /auth/sign-in/username     - Sign in with username/password");
    println!("   Session Management:");
    println!("     GET  /auth/get-session          - Get current session info");
    println!("     POST /auth/sign-out             - Sign out current session");
    println!("     GET  /auth/list-sessions        - List all user sessions");
    println!("     POST /auth/revoke-session       - Revoke specific session");
    println!("     POST /auth/revoke-sessions      - Revoke all user sessions");
    println!("     POST /auth/revoke-other-sessions - Revoke all except current");
    println!("   Password Management:");
    println!("     POST /auth/forget-password      - Request password reset");
    println!("     POST /auth/reset-password       - Reset password with token");
    println!("     GET  /auth/reset-password/{{token}} - Validate reset token");
    println!("     POST /auth/change-password      - Change password (auth)");
    println!("     POST /auth/set-password         - Set password for OAuth users (auth)");
    println!("   Email Verification:");
    println!("     POST /auth/send-verification-email - Send verification email (auth)");
    println!("     GET  /auth/verify-email         - Verify email with token");
    println!("   User Management:");
    println!("     POST /auth/update-user          - Update user profile (auth)");
    println!("     POST /auth/delete-user          - Delete user account (auth)");
    println!("     POST /auth/change-email         - Change email address (auth)");
    println!("     GET  /auth/delete-user/callback - Confirm deletion via token");
    println!("   Account Management:");
    println!("     GET  /auth/list-accounts        - List linked accounts (auth)");
    println!("     POST /auth/unlink-account       - Unlink an account (auth)");
    println!("   Organization:");
    println!("     POST /auth/organization/create           - Create organization (auth)");
    println!("     POST /auth/organization/update           - Update organization (auth)");
    println!("     POST /auth/organization/delete           - Delete organization (auth)");
    println!("     GET  /auth/organization/list             - List organizations (auth)");
    println!("     GET  /auth/organization/get-full-organization - Get full org (auth)");
    println!("     POST /auth/organization/set-active       - Set active org (auth)");
    println!("     POST /auth/organization/leave            - Leave organization (auth)");
    println!("     POST /auth/organization/check-slug       - Check slug availability (auth)");
    println!("   Organization Members:");
    println!("     GET  /auth/organization/get-active-member  - Get active member (auth)");
    println!("     GET  /auth/organization/list-members       - List members (auth)");
    println!("     POST /auth/organization/remove-member      - Remove member (auth)");
    println!("     POST /auth/organization/update-member-role - Update role (auth)");
    println!("   Organization Invitations:");
    println!("     POST /auth/organization/invite-member      - Invite member (auth)");
    println!("     GET  /auth/organization/get-invitation     - Get invitation (auth)");
    println!("     GET  /auth/organization/list-invitations   - List invitations (auth)");
    println!("     POST /auth/organization/accept-invitation  - Accept invitation (auth)");
    println!("     POST /auth/organization/reject-invitation  - Reject invitation (auth)");
    println!("     POST /auth/organization/cancel-invitation  - Cancel invitation (auth)");
    println!("     POST /auth/organization/has-permission     - Check permission (auth)");
    println!("   Other:");
    println!("     GET  /auth/ok                   - Health check");
    println!("     GET  /api/profile               - Protected API route");
    println!("     GET  /api/public                - Public API route");

    // Start the server
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn create_app_router(auth: Arc<BetterAuth>) -> Router {
    // Create auth router using the BetterAuth AxumIntegration
    // This automatically registers all plugin routes
    let auth_router = auth.clone().axum_router();

    // Create main application router
    Router::new()
        // API routes
        .route("/api/profile", get(get_user_profile))
        .route("/api/protected", get(protected_route))
        .route("/api/public", get(public_route))
        // Mount auth routes under /auth prefix
        .nest("/auth", auth_router)
        // Add middleware
        .layer(CorsLayer::permissive())
        .layer(middleware::from_fn_with_state(
            auth.clone(),
            auth_middleware,
        ))
        // Add the auth state
        .with_state(auth)
}

// Middleware to extract and validate session
async fn auth_middleware(
    State(_auth): State<Arc<BetterAuth>>,
    mut req: Request,
    next: Next,
) -> Response {
    // Extract session token from Authorization header or cookie
    let token = extract_session_token(&req);

    if let Some(token) = token {
        // Validate session (this would be implemented in your auth system)
        // For now, just pass the token along in extensions
        req.extensions_mut().insert(token);
    }

    next.run(req).await
}

fn extract_session_token(req: &Request) -> Option<String> {
    // Try Authorization header first
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                return Some(auth_str[7..].to_string());
            }
        }
    }

    // Try session cookie
    if let Some(cookie_header) = req.headers().get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if cookie.starts_with("session_token=") {
                    return Some(cookie[14..].to_string());
                }
            }
        }
    }

    None
}

// API route handlers
async fn get_user_profile(
    State(_auth): State<Arc<BetterAuth>>,
    req: Request,
) -> Result<Json<ApiResponse<UserProfile>>, StatusCode> {
    // Extract session token from request
    if let Some(_token) = req.extensions().get::<String>() {
        // In a real implementation, you'd validate the session and get user data
        let profile = UserProfile {
            id: "user_123".to_string(),
            email: "user@example.com".to_string(),
            name: Some("Test User".to_string()),
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };

        Ok(Json(ApiResponse::success(
            profile,
            "Profile retrieved successfully",
        )))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn protected_route(req: Request) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    if req.extensions().get::<String>().is_some() {
        let data = serde_json::json!({
            "message": "This is a protected route",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "server": "Better Auth Axum Server"
        });

        Ok(Json(ApiResponse::success(
            data,
            "Access granted to protected route",
        )))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn public_route() -> Json<ApiResponse<serde_json::Value>> {
    let data = serde_json::json!({
        "message": "This is a public route - no authentication required",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "server": "Better Auth Axum Server",
        "endpoints": [
            "POST /auth/sign-up/email",
            "POST /auth/sign-in/email",
            "POST /auth/sign-in/username",
            "GET  /auth/get-session (protected)",
            "POST /auth/sign-out (protected)",
            "GET  /auth/list-sessions (protected)",
            "POST /auth/revoke-session (protected)",
            "POST /auth/revoke-sessions (protected)",
            "POST /auth/revoke-other-sessions (protected)",
            "POST /auth/forget-password",
            "POST /auth/reset-password",
            "GET  /auth/reset-password/{token}",
            "POST /auth/change-password (protected)",
            "POST /auth/set-password (protected)",
            "POST /auth/send-verification-email (protected)",
            "GET  /auth/verify-email",
            "POST /auth/update-user (protected)",
            "POST /auth/delete-user (protected)",
            "POST /auth/change-email (protected)",
            "GET  /auth/delete-user/callback",
            "GET  /auth/list-accounts (protected)",
            "POST /auth/unlink-account (protected)",
            "POST /auth/organization/create (protected)",
            "POST /auth/organization/update (protected)",
            "POST /auth/organization/delete (protected)",
            "GET  /auth/organization/list (protected)",
            "GET  /auth/organization/get-full-organization (protected)",
            "POST /auth/organization/set-active (protected)",
            "POST /auth/organization/leave (protected)",
            "POST /auth/organization/check-slug (protected)",
            "GET  /auth/organization/get-active-member (protected)",
            "GET  /auth/organization/list-members (protected)",
            "POST /auth/organization/remove-member (protected)",
            "POST /auth/organization/update-member-role (protected)",
            "POST /auth/organization/invite-member (protected)",
            "POST /auth/organization/accept-invitation (protected)",
            "POST /auth/organization/reject-invitation (protected)",
            "POST /auth/organization/cancel-invitation (protected)",
            "POST /auth/organization/has-permission (protected)",
            "GET  /auth/ok",
            "GET  /api/profile (protected)",
            "GET  /api/protected (protected)",
            "GET  /api/public"
        ]
    });

    Json(ApiResponse::success(
        data,
        "Public route accessed successfully",
    ))
}
