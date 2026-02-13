use axum::{Json, Router, response::IntoResponse, routing::get};
use better_auth::adapters::MemoryDatabaseAdapter;
use better_auth::handlers::{AxumIntegration, CurrentSession, OptionalSession};
use better_auth::plugins::{
    AccountManagementPlugin, EmailPasswordPlugin, OrganizationPlugin, PasswordManagementPlugin,
    SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthUser, BetterAuth};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

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
        AuthBuilder::new(config)
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

async fn create_app_router(auth: Arc<BetterAuth<MemoryDatabaseAdapter>>) -> Router {
    let auth_router = auth.clone().axum_router();

    Router::new()
        .route("/api/profile", get(get_user_profile))
        .route("/api/protected", get(protected_route))
        .route("/api/public", get(public_route))
        .nest("/auth", auth_router)
        .layer(CorsLayer::permissive())
        .with_state(auth)
}

// ---------------------------------------------------------------------------
// Protected route — uses CurrentSession extractor (returns 401 automatically)
// ---------------------------------------------------------------------------
async fn get_user_profile(session: CurrentSession<MemoryDatabaseAdapter>) -> impl IntoResponse {
    Json(serde_json::json!({
        "id": session.user.id(),
        "email": session.user.email(),
        "name": session.user.name(),
        "created_at": session.user.created_at().to_rfc3339(),
    }))
}

async fn protected_route(session: CurrentSession<MemoryDatabaseAdapter>) -> impl IntoResponse {
    Json(serde_json::json!({
        "message": "This is a protected route",
        "user_id": session.user.id(),
    }))
}

// ---------------------------------------------------------------------------
// Public route — uses OptionalSession to optionally show user info
// ---------------------------------------------------------------------------
async fn public_route(session: OptionalSession<MemoryDatabaseAdapter>) -> impl IntoResponse {
    let user_info = session.0.map(|s| {
        serde_json::json!({
            "id": s.user.id(),
            "email": s.user.email(),
        })
    });

    Json(serde_json::json!({
        "message": "This is a public route",
        "user": user_info,
    }))
}
