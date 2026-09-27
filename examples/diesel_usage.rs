//! Better Auth on Diesel.
//!
//! Uses SQLite by default. Set `DATABASE_URL` to a SQLite path, for example
//! `DATABASE_URL=auth.db`, to keep the data between runs.
//!
//! ```bash
//! cargo run --example diesel_usage --features diesel-sqlite
//! ```

use better_auth::diesel::diesel_async::AsyncMigrationHarness;
use better_auth::diesel::diesel_migrations::MigrationHarness;
use better_auth::diesel::{DieselAuthSchema, DieselPool, DieselStore, migrations};
use better_auth::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::prelude::{AuthRequest, HttpMethod};
use better_auth::{AuthConfig, BetterAuth};

fn json_request(method: HttpMethod, path: &str, body: serde_json::Value) -> AuthRequest {
    let mut request = AuthRequest::new(method, path);
    request.body = Some(body.to_string().into_bytes());
    let _ = request
        .headers
        .insert("content-type".to_string(), "application/json".to_string());
    request
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| ":memory:".to_string());
    let pool = DieselPool::sqlite(database_url)?;

    // The application owns its migrations. Here the Better Auth migrations
    // run on their own; a real application runs them next to its own.
    if let Some(sqlite) = pool.as_sqlite() {
        let mut harness = AsyncMigrationHarness::new(sqlite.get().await?);
        let _ = harness.run_pending_migrations(migrations::SQLITE)?;
    }

    let mut config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000");
    // Accept the session token as a bearer token, so that this example needs no cookie jar.
    config.session.bearer = Some(Default::default());
    let store = DieselStore::new(config.clone(), pool);

    let auth = BetterAuth::<DieselAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;

    let response = auth
        .handle_request(json_request(
            HttpMethod::Post,
            "/api/auth/sign-up/email",
            serde_json::json!({
                "name": "Ada Lovelace",
                "email": "ada@example.com",
                "password": "correct-horse-battery-staple",
            }),
        ))
        .await?;
    println!("sign-up: {}", response.status);

    let body: serde_json::Value = serde_json::from_slice(&response.body)?;
    let token = body
        .get("token")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    let mut session_request = AuthRequest::new(HttpMethod::Get, "/api/auth/get-session");
    let _ = session_request
        .headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    let session = auth.handle_request(session_request).await?;
    println!(
        "get-session: {} {}",
        session.status,
        String::from_utf8_lossy(&session.body)
    );

    Ok(())
}
