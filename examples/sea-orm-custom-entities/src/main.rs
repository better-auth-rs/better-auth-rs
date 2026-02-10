//! # Sea-ORM Custom Entities Example
//!
//! Demonstrates how to use better-auth alongside Sea-ORM in the same application.
//! Both share the same PostgreSQL connection pool:
//!
//! - **Sea-ORM** (`DatabaseConnection`) — for app-level queries (e.g., find users by plan)
//! - **better-auth** (`SqlxAdapter`) — for authentication (sign-up, sign-in, sessions)
//!
//! The key pattern: extract the underlying `sqlx::PgPool` from Sea-ORM's
//! `DatabaseConnection` via `get_postgres_connection_pool()`, then pass it
//! to `SqlxAdapter::from_pool()`.
//!
//! ## Setup
//!
//! ```bash
//! createdb better_auth_example
//! export DATABASE_URL="postgresql://user:pass@localhost:5432/better_auth_example"
//! psql "$DATABASE_URL" -f examples/sea-orm-custom-entities/migrations/001_init.sql
//! cargo run -p sea-orm-custom-entities
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

    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL environment variable required");

    // 1. Connect via Sea-ORM (this creates a sqlx pool internally)
    let db: DatabaseConnection = sea_orm::Database::connect(&database_url).await?;
    println!("[*] Sea-ORM connected");

    // 2. Run migrations using the underlying sqlx pool
    let pg_pool = db.get_postgres_connection_pool();
    let migration_sql = include_str!("../migrations/001_init.sql");
    sqlx::raw_sql(migration_sql).execute(pg_pool).await?;
    println!("[*] Migrations applied");

    // 3. Create the better-auth SqlxAdapter from the SAME pool
    //    Both Sea-ORM and better-auth share one connection pool.
    let adapter = AppAdapter::from_pool(pg_pool.clone());

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
    println!("      -d '{{\"email\":\"alice@example.com\",\"password\":\"secure123\",\"name\":\"Alice\"}}'");
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
    let session_req = better_auth::types::AuthRequest {
        method: better_auth::types::HttpMethod::Get,
        path: "/get-session".to_string(),
        headers,
        body: None,
        query: std::collections::HashMap::new(),
    };

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

    let body: serde_json::Value =
        serde_json::from_slice(&session_resp.body).unwrap_or_default();

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
        plan: user.plan,
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

async fn get_users_by_plan(
    State(state): State<AppState>,
    req: Request,
) -> Response {
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
        .filter(entities::user::Column::Plan.eq(&plan))
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
                    plan: u.plan,
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
