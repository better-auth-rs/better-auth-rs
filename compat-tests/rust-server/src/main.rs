use axum::{Json, Router, extract::Query, response::IntoResponse, routing::get};
use better_auth::adapters::MemoryDatabaseAdapter;
use better_auth::handlers::axum::AxumIntegration;
use better_auth::plugins::{
    EmailPasswordPlugin, PasswordManagementPlugin, SessionManagementPlugin,
    password_management::SendResetPassword,
};
use better_auth::{AuthBuilder, AuthConfig};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::TcpListener;

#[derive(Clone)]
struct CompatResetSender {
    outbox: Arc<Mutex<HashMap<String, String>>>,
}

#[async_trait::async_trait]
impl SendResetPassword for CompatResetSender {
    async fn send(
        &self,
        user: &serde_json::Value,
        _url: &str,
        token: &str,
    ) -> better_auth::AuthResult<()> {
        if let Some(email) = user.get("email").and_then(|value| value.as_str()) {
            self.outbox
                .lock()
                .await
                .insert(email.to_string(), token.to_string());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct ResetTokenQuery {
    email: String,
}

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
    let reset_outbox = Arc::new(Mutex::new(HashMap::new()));

    let auth = Arc::new(
        AuthBuilder::new(config)
            .database(database)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(
                PasswordManagementPlugin::new()
                    .send_reset_password(Arc::new(CompatResetSender {
                        outbox: reset_outbox.clone(),
                    })),
            )
            .build()
            .await?,
    );

    let auth_router = auth.clone().axum_router();

    let reset_outbox_for_route = reset_outbox.clone();
    let app = Router::new()
        .route("/__health", get(health_check))
        .route(
            "/__test/reset-password-token",
            get(move |Query(query): Query<ResetTokenQuery>| {
                let reset_outbox = reset_outbox_for_route.clone();
                async move {
                    let token = reset_outbox.lock().await.remove(&query.email);
                    match token {
                        Some(token) => (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({ "token": token })),
                        ),
                        None => (
                            axum::http::StatusCode::NOT_FOUND,
                            Json(serde_json::json!({ "message": "Not found" })),
                        ),
                    }
                }
            }),
        )
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
