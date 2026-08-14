//! # Sea-ORM Migration Example (SQLite In-Memory)
//!
//! Demonstrates how to use better-auth alongside Sea-ORM in the same application,
//! with schema automatically synced from entity definitions (SeaORM 2.0 entity-first workflow).
//!
//! - **Sea-ORM** (`DatabaseConnection`) — for app-level queries (e.g., find users by plan)
//! - **better-auth** (`SqliteAdapter`) — for authentication (sign-up, sign-in, sessions)
//! - **schema sync** — automatically creates tables from entity definitions
//!
//! The key pattern: extract the underlying `sqlx::SqlitePool` from Sea-ORM's
//! `DatabaseConnection` via `get_sqlite_connection_pool()`, then pass it
//! to `SqliteAdapter::from_pool()`.
//!
//! ## Important: In-Memory Database Pooling
//!
//! This example uses a shared in-memory SQLite database (`sqlite::memory:?cache=shared`)
//! with a single connection. Without this, each connection in the pool would get its own
//! private in-memory database, causing "no such table" errors after schema sync completes
//! on one connection but later queries acquire a different connection.
//!
//! For production use with persistent databases, normal connection pooling is fine.
//!
//! ## Setup
//!
//! ```bash
//! # No database setup needed - uses in-memory SQLite!
//! cargo run --manifest-path examples/sea-orm-migration/Cargo.toml
//! ```

mod auth_entities;
mod entities;

use crate::auth_entities::{AppAdapter, AppUser};
use crate::entities::UserEntity;
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
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::Serialize;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

/// Shared application state.
#[derive(Clone)]
struct AppState {
    auth: Arc<BetterAuth<AppAdapter>>,
    /// Sea-ORM connection for app-level queries.
    db: DatabaseConnection,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // 1. Connect to SQLite in-memory database via Sea-ORM
    //    Use a shared in-memory database with a single connection to avoid pool isolation.
    //    Without this, each connection in the pool would get its own private in-memory DB,
    //    causing "no such table" errors after schema sync.
    let mut opt = sea_orm::ConnectOptions::new("sqlite::memory:?cache=shared");
    opt.max_connections(1) // Ensure all operations use the same connection
        .min_connections(1);
    let db: DatabaseConnection = sea_orm::Database::connect(opt).await?;
    println!("[*] Sea-ORM connected to shared in-memory SQLite (single connection)");

    // 2. Sync schema from entity definitions (SeaORM 2.0 pattern)
    //    This automatically creates tables, columns, and foreign keys
    db.get_schema_registry("sea_orm_migration_example::entities::*")
        .sync(&db)
        .await?;
    println!("[*] Schema synced from entity definitions");

    // 3. Create the better-auth SqlxAdapter from the SAME pool
    //    Both Sea-ORM and better-auth share one connection pool.
    let sqlite_pool = db.get_sqlite_connection_pool();
    let adapter = AppAdapter::from_pool(sqlite_pool.clone());

    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:8080")
        .password_min_length(8);

    let auth = Arc::new(
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

    let state = AppState {
        auth: auth.clone(),
        db,
    };

    // 4. Build Axum router
    //    auth_router has state Arc<BetterAuth<AppAdapter>>, so we convert it
    //    to a stateless router before nesting into our AppState router.
    let auth_router = auth.clone().axum_router().with_state(auth.clone());

    let app = Router::new()
        .route("/api/me", get(get_me))
        .route("/api/users-by-plan", get(get_users_by_plan))
        .nest("/auth", auth_router)
        .layer(CorsLayer::permissive())
        .with_state(state);

    println!("[*] Listening on http://localhost:8080");
    println!();
    println!("  📦 Using shared in-memory SQLite (single connection)");
    println!("  ⚠️  All data will be lost when the server stops!");
    println!("  ℹ️  Shared cache + single connection prevents pool isolation");
    println!();
    println!("  Auth (better-auth):");
    println!("    POST /auth/sign-up/email");
    println!("    POST /auth/sign-in/email");
    println!("    GET  /auth/get-session");
    println!("    POST /auth/sign-out");
    println!("    POST /auth/organization/create");
    println!("    GET  /auth/ok");
    println!();
    println!("  App API (Sea-ORM):");
    println!("    GET  /api/me?token=<session_token>");
    println!("    GET  /api/users-by-plan?plan=free");
    println!();
    println!("  Try it:");
    println!("    # Sign up");
    println!("    curl -s -X POST http://localhost:8080/auth/sign-up/email \\");
    println!("      -H 'Content-Type: application/json' \\");
    println!(
        "      -d '{{\"email\":\"alice@example.com\",\"password\":\"secure123\",\"name\":\"Alice\"}}'"
    );
    println!();
    println!("    # Query users by plan (Sea-ORM)");
    println!("    curl -s 'http://localhost:8080/api/users-by-plan?plan=free'");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/me — uses better-auth to validate session, returns custom fields
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct MeResponse {
    id: String,
    email: Option<String>,
    name: Option<String>,
    plan: String,
    stripe_customer_id: Option<String>,
}

async fn get_me(State(state): State<AppState>, req: Request) -> Response {
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

    let session_resp = match state.auth.handle_request(session_req).await {
        Ok(resp) if resp.status == 200 => resp,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"message": "Invalid session"})),
            )
                .into_response();
        }
    };

    let body: serde_json::Value = serde_json::from_slice(&session_resp.body).unwrap_or_default();

    let user: AppUser = match serde_json::from_value(body["user"].clone()) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"message": "Failed to parse user"})),
            )
                .into_response();
        }
    };

    Json(MeResponse {
        id: user.id,
        email: user.email,
        name: user.name,
        plan: user.plan.unwrap_or_else(|| "free".to_string()),
        stripe_customer_id: user.stripe_customer_id,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// GET /api/users-by-plan?plan=free — uses Sea-ORM for app-level queries
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct UserSummary {
    id: String,
    email: Option<String>,
    name: Option<String>,
    plan: String,
}

async fn get_users_by_plan(State(state): State<AppState>, req: Request) -> Response {
    let plan = req
        .uri()
        .query()
        .and_then(|q| {
            q.split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(k, _)| *k == "plan")
                .map(|(_, v)| v.to_string())
        })
        .unwrap_or_else(|| "free".to_string());

    // This is a Sea-ORM query — completely independent of better-auth.
    // It uses the Sea-ORM entity model and the shared DatabaseConnection.
    let users = UserEntity::find()
        .filter(entities::user::Column::Plan.eq(Some(plan.clone())))
        .all(&state.db)
        .await;

    match users {
        Ok(users) => {
            let summaries: Vec<UserSummary> = users
                .into_iter()
                .map(|u| UserSummary {
                    id: u.id,
                    email: u.email,
                    name: u.name,
                    plan: u.plan.unwrap_or_else(|| "free".to_string()),
                })
                .collect();
            Json(serde_json::json!({
                "plan": plan,
                "count": summaries.len(),
                "users": summaries,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message": e.to_string()})),
        )
            .into_response(),
    }
}
