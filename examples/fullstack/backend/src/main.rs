use axum::{Json, Router, response::IntoResponse, routing::get};
use better_auth::adapters::MemoryDatabaseAdapter;
use better_auth::handlers::axum::{AxumIntegration, CurrentSession, OptionalSession};
use better_auth::plugins::{EmailPasswordPlugin, PasswordManagementPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, CsrfConfig};
use std::sync::Arc;
use tokio::net::TcpListener;
use axum::http::HeaderName;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("Starting Better Auth RS backend server...");

    // ── Configuration from environment variables ──────────────────────────
    // All values have sensible defaults for local development.
    let backend_url =
        std::env::var("BACKEND_URL").unwrap_or_else(|_| "http://localhost:3001".to_string());
    let frontend_url =
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3001".to_string());

    // Load the secret from the AUTH_SECRET environment variable.
    // For this example you can set any string that is at least 32 characters.
    let secret = std::env::var("AUTH_SECRET").unwrap_or_else(|_| {
        eprintln!("WARN: AUTH_SECRET not set, using a default dev-only value");
        "x".repeat(32)
    });
    let config = AuthConfig::new(secret)
        .base_url(&backend_url)
        .password_min_length(8);

    let database = MemoryDatabaseAdapter::new();

    // Allow the frontend origin through the built-in CSRF middleware.
    let csrf = CsrfConfig::new().trusted_origin(&frontend_url);

    let auth = Arc::new(
        AuthBuilder::new(config)
            .csrf(csrf)
            .database(database)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(PasswordManagementPlugin::new())
            .build()
            .await?,
    );

    println!("Auth instance created with plugins: {:?}", auth.plugin_names());

    let auth_router = auth.clone().axum_router();

    // CORS: allow the frontend origin.
    // When using allow_credentials(true), headers and methods must be listed
    // explicitly — wildcards are not allowed.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list([
            frontend_url.parse().unwrap(),
        ]))
        .allow_methods(AllowMethods::list([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ]))
        .allow_headers(AllowHeaders::list([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("authorization"),
            HeaderName::from_static("cookie"),
        ]))
        .allow_credentials(true);

    let app = Router::new()
        .route("/api/me", get(get_me))
        .route("/api/public", get(public_route))
        // Mount all auth routes under /api/auth to match better-auth's default basePath.
        .nest("/api/auth", auth_router)
        .layer(cors)
        // Log every request/response pair via tracing.
        .layer(TraceLayer::new_for_http())
        .with_state(auth);

    println!("Server listening on {backend_url}");
    println!();
    println!("Auth endpoints (under /api/auth):");
    println!("  POST /api/auth/sign-up/email    - Sign up");
    println!("  POST /api/auth/sign-in/email    - Sign in");
    println!("  GET  /api/auth/get-session      - Get session");
    println!("  POST /api/auth/sign-out         - Sign out");
    println!("  GET  /api/auth/list-sessions    - List all sessions");
    println!("  POST /api/auth/revoke-session   - Revoke a session");
    println!("  POST /api/auth/revoke-other-sessions - Revoke other sessions");
    println!("  POST /api/auth/change-password  - Change password");
    println!("  GET  /api/auth/ok               - Health check");
    println!();
    println!("App endpoints:");
    println!("  GET  /api/me                    - Current user (protected)");
    println!("  GET  /api/public                - Public endpoint");

    let listener = TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Protected route - requires a valid session
async fn get_me(session: CurrentSession<MemoryDatabaseAdapter>) -> impl IntoResponse {
    Json(serde_json::json!({
        "user": {
            "id": session.user.id,
            "email": session.user.email,
            "name": session.user.name,
            "createdAt": session.user.created_at.to_rfc3339(),
        }
    }))
}

/// Public route - optionally shows user info
async fn public_route(session: OptionalSession<MemoryDatabaseAdapter>) -> impl IntoResponse {
    let user_info = session.0.map(|s| {
        serde_json::json!({
            "id": s.user.id,
            "email": s.user.email,
        })
    });

    Json(serde_json::json!({
        "message": "Hello from better-auth-rs!",
        "user": user_info,
    }))
}
