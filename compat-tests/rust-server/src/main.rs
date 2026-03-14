use axum::{Router, response::IntoResponse, routing::get};
use better_auth::adapters::MemoryDatabaseAdapter;
use better_auth::handlers::axum::AxumIntegration;
use better_auth::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig};
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3200);

    // Match the reference server's secret exactly
    let secret = "compat-test-only-key-not-real-minimum-32chars";

    let config = AuthConfig::new(secret)
        .base_url(format!("http://localhost:{port}"))
        .password_min_length(8);

    let database = MemoryDatabaseAdapter::new();

    let auth = Arc::new(
        AuthBuilder::new(config)
            .database(database)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?,
    );

    let auth_router = auth.clone().axum_router();

    let app = Router::new()
        .route("/__health", get(health_check))
        .nest("/api/auth", auth_router)
        .with_state(auth);

    let addr = format!("0.0.0.0:{port}");
    println!("[rust-server] Listening on http://localhost:{port}");
    println!("READY");

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "ok": true }))
}
