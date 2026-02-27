//! # SQLx Custom Entities Example
//!
//! A complete Axum web server demonstrating custom entity types with PostgreSQL.
//! Each entity struct has extra application-specific columns (billing plan, Stripe ID, etc.)
//! that are stored in PostgreSQL and automatically populated via `SELECT * ... RETURNING *`.
//!
//! ## Setup
//!
//! ```bash
//! # Start PostgreSQL and create the database
//! createdb better_auth_example
//!
//! # Apply migrations
//! export DATABASE_URL="postgresql://user:pass@localhost:5432/better_auth_example"
//! psql "$DATABASE_URL" -f examples/sqlx-custom-entities/migrations/001_init.sql
//!
//! # Run the server
//! cargo run --manifest-path examples/sqlx-custom-entities/Cargo.toml
//! ```

mod entities;

use crate::entities::{SaasAdapter, SaasUser};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use better_auth::handlers::AxumIntegration;
use better_auth::plugins::{
    EmailPasswordPlugin, OrganizationPlugin, PasswordManagementPlugin, SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use serde::Serialize;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

/// Application state shared across all routes.
type AppState = Arc<BetterAuth<SaasAdapter>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL environment variable required");

    // Run migrations
    let pool = sqlx::postgres::PgPool::connect(&database_url).await?;
    let migration_sql = include_str!("../migrations/001_init.sql");
    sqlx::raw_sql(migration_sql).execute(&pool).await?;
    println!("[*] Migrations applied");

    // Build the adapter with custom entity types.
    // SqlxAdapter::from_pool works with any generic parameterization.
    let adapter = SaasAdapter::from_pool(pool);

    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:8080")
        .password_min_length(8);

    let auth: AppState = Arc::new(
        AuthBuilder::new(config)
            .database(adapter)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(PasswordManagementPlugin::new())
            .plugin(OrganizationPlugin::new())
            .build()
            .await?,
    );

    println!("[*] Plugins: {:?}", auth.plugin_names());

    // Build the Axum router
    let auth_router = auth.clone().axum_router();

    let app = Router::new()
        .route("/api/me", get(get_me))
        .nest("/auth", auth_router)
        .layer(CorsLayer::permissive())
        .with_state(auth);

    println!("[*] Listening on http://localhost:8080");
    println!();
    println!("  Auth endpoints:");
    println!("    POST /auth/sign-up/email");
    println!("    POST /auth/sign-in/email");
    println!("    GET  /auth/get-session");
    println!("    POST /auth/sign-out");
    println!("    GET  /auth/list-sessions");
    println!("    POST /auth/change-password");
    println!("    POST /auth/organization/create");
    println!("    GET  /auth/organization/list");
    println!("    GET  /auth/ok");
    println!();
    println!("  Custom API:");
    println!("    GET  /api/me  (Bearer token required)");
    println!();
    println!("  Try it:");
    println!("    curl -X POST http://localhost:8080/auth/sign-up/email \\");
    println!("      -H 'Content-Type: application/json' \\");
    println!("      -d '{{\"email\":\"alice@example.com\",\"password\":\"secure123\",\"name\":\"Alice\"}}'");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Custom API route — demonstrates accessing SaaS-specific fields
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct MeResponse {
    id: String,
    email: Option<String>,
    name: Option<String>,
    plan: String,
    stripe_customer_id: Option<String>,
    phone: Option<String>,
}

/// `GET /api/me` — returns the current user's profile including SaaS fields.
///
/// Validates the session via `auth.handle_request(GET /get-session)`, then
/// queries the database directly to get the full `SaasUser` with custom columns.
async fn get_me(State(auth): State<AppState>, req: Request) -> Response {
    // Extract bearer token
    let token = match req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        Some(t) => t.to_string(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"message": "Missing bearer token"})),
            )
                .into_response();
        }
    };

    // Validate session through better-auth
    let mut headers = std::collections::HashMap::new();
    headers.insert("authorization".to_string(), format!("Bearer {token}"));
    let session_req = better_auth::types::AuthRequest::from_parts(
        better_auth::types::HttpMethod::Get,
        "/get-session".to_string(),
        headers,
        None,
        std::collections::HashMap::new(),
    );

    let session_resp = match auth.handle_request(session_req).await {
        Ok(resp) if resp.status == 200 => resp,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"message": "Invalid session"})),
            )
                .into_response();
        }
    };

    // Parse the user from the session response — this contains all custom fields
    // because the SqlxAdapter uses SELECT * and our SaasUser implements FromRow.
    let body: serde_json::Value =
        serde_json::from_slice(&session_resp.body).unwrap_or_default();

    let user: SaasUser = match serde_json::from_value(body["user"].clone()) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"message": "Failed to parse user"})),
            )
                .into_response();
        }
    };

    let me = MeResponse {
        id: user.id,
        email: user.email,
        name: user.display_name,
        plan: user.plan,
        stripe_customer_id: user.stripe_customer_id,
        phone: user.phone,
    };

    (StatusCode::OK, Json(me)).into_response()
}
