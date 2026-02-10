use better_auth::adapters::SqlxAdapter;
use better_auth::plugins::{
    AccountManagementPlugin, EmailPasswordPlugin, PasswordManagementPlugin, SessionManagementPlugin,
};
use better_auth::types::{AuthRequest, HttpMethod};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Better Auth PostgreSQL Example\n");

    // Get database URL from environment variable
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://better_auth:password@localhost:5432/better_auth".to_string()
    });

    println!("Connecting to database: {}", hide_password(&database_url));

    // Create PostgreSQL adapter
    let database = SqlxAdapter::new(&database_url).await?;
    println!("Database connection established\n");

    // Create configuration
    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000")
        .password_min_length(8);

    // Build authentication system with all Phase 1 plugins
    let auth = AuthBuilder::new(config)
        .database(database)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(PasswordManagementPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .build()
        .await?;

    println!("BetterAuth instance created");
    println!("Registered plugins: {:?}\n", auth.plugin_names());

    // --- Sign up with username ---
    println!("=== Sign up ===");
    let signup_body = serde_json::json!({
        "email": "postgres_user@example.com",
        "password": "secure_password_123",
        "name": "PostgreSQL Test User",
        "username": "pg_user"
    });

    let response = send(
        &auth,
        HttpMethod::Post,
        "/sign-up/email",
        Some(&signup_body),
        None,
    )
    .await;
    println!("Status: {}", response.status);
    let data = parse_body(&response.body);
    let token = data["token"].as_str().unwrap_or_default().to_string();
    if let Some(user) = data.get("user") {
        println!("User: {}", user["email"]);
        println!("Username: {}", user["username"]);
        println!("ID: {}", user["id"]);
    }
    println!();

    // --- Sign in by email ---
    println!("=== Sign in by email ===");
    let signin_body = serde_json::json!({
        "email": "postgres_user@example.com",
        "password": "secure_password_123"
    });
    let response = send(
        &auth,
        HttpMethod::Post,
        "/sign-in/email",
        Some(&signin_body),
        None,
    )
    .await;
    println!("Status: {}\n", response.status);

    // --- Sign in by username ---
    println!("=== Sign in by username ===");
    let signin_body = serde_json::json!({
        "username": "pg_user",
        "password": "secure_password_123"
    });
    let response = send(
        &auth,
        HttpMethod::Post,
        "/sign-in/username",
        Some(&signin_body),
        None,
    )
    .await;
    println!("Status: {}\n", response.status);

    // --- Get session ---
    println!("=== Get session ===");
    let response = send(&auth, HttpMethod::Get, "/get-session", None, Some(&token)).await;
    println!("Status: {}", response.status);
    let data = parse_body(&response.body);
    println!("Session user: {}\n", data["user"]["email"]);

    // --- List sessions ---
    println!("=== List sessions ===");
    let response = send(&auth, HttpMethod::Get, "/list-sessions", None, Some(&token)).await;
    println!("Status: {}\n", response.status);

    // --- List accounts ---
    println!("=== List accounts ===");
    let response = send(&auth, HttpMethod::Get, "/list-accounts", None, Some(&token)).await;
    println!("Status: {}\n", response.status);

    // --- Duplicate registration (should fail) ---
    println!("=== Duplicate registration (should fail) ===");
    let response = send(
        &auth,
        HttpMethod::Post,
        "/sign-up/email",
        Some(&signup_body),
        None,
    )
    .await;
    println!("Status: {} (expected error)\n", response.status);

    // --- Wrong password (should fail) ---
    println!("=== Wrong password (should fail) ===");
    let wrong_body = serde_json::json!({
        "email": "postgres_user@example.com",
        "password": "wrong_password"
    });
    let response = send(
        &auth,
        HttpMethod::Post,
        "/sign-in/email",
        Some(&wrong_body),
        None,
    )
    .await;
    println!("Status: {} (expected 401)\n", response.status);

    println!("PostgreSQL example completed successfully!");

    Ok(())
}

/// Helper: send a request through the auth handler
async fn send(
    auth: &BetterAuth<SqlxAdapter>,
    method: HttpMethod,
    path: &str,
    body: Option<&serde_json::Value>,
    bearer_token: Option<&str>,
) -> better_auth::types::AuthResponse {
    let mut headers = HashMap::new();
    if body.is_some() {
        headers.insert("content-type".to_string(), "application/json".to_string());
    }
    if let Some(token) = bearer_token {
        headers.insert("authorization".to_string(), format!("Bearer {}", token));
    }

    let request = AuthRequest {
        method,
        path: path.to_string(),
        headers,
        body: body.map(|b| b.to_string().into_bytes()),
        query: HashMap::new(),
    };

    auth.handle_request(request).await.unwrap()
}

/// Helper: parse JSON body
fn parse_body(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap_or(serde_json::Value::Null)
}

/// Hide password in database URL for logging output
fn hide_password(url: &str) -> String {
    if let Some(at_pos) = url.find('@') {
        if let Some(colon_pos) = url[..at_pos].rfind(':') {
            if let Some(slash_pos) = url[..colon_pos].rfind('/') {
                let before_password = &url[..slash_pos + 1];
                let after_password = &url[at_pos..];
                return format!("{}****{}", before_password, after_password);
            }
        }
    }
    url.to_string()
}
