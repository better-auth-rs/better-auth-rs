use better_auth::adapters::MemoryDatabaseAdapter;
use better_auth::plugins::{
    AccountManagementPlugin, EmailPasswordPlugin, EmailVerificationPlugin,
    OrganizationPlugin, PasswordManagementPlugin, SessionManagementPlugin,
};
use better_auth::types::{AuthRequest, HttpMethod};
use better_auth::{AuthConfig, BetterAuth};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Better Auth Rust Example\n");

    // Create configuration
    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000")
        .password_min_length(8);

    // Build the authentication system with all plugins
    let auth = BetterAuth::new(config)
        .database(MemoryDatabaseAdapter::new())
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(PasswordManagementPlugin::new())
        .plugin(EmailVerificationPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .plugin(OrganizationPlugin::new())
        .build()
        .await?;

    println!("BetterAuth instance created");
    println!("Registered plugins: {:?}\n", auth.plugin_names());

    // --- Sign up with email + username ---
    println!("=== Sign up with email and username ===");
    let signup_body = serde_json::json!({
        "email": "test@example.com",
        "password": "password123",
        "name": "Test User",
        "username": "testuser",
        "displayUsername": "Test User"
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
    println!("User: {}", data["user"]["email"]);
    println!("Username: {}", data["user"]["username"]);
    println!("Token: {}...\n", &token[..20.min(token.len())]);

    // --- Sign in by email ---
    println!("=== Sign in by email ===");
    let signin_body = serde_json::json!({
        "email": "test@example.com",
        "password": "password123"
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
        "username": "testuser",
        "password": "password123"
    });
    let response = send(
        &auth,
        HttpMethod::Post,
        "/sign-in/username",
        Some(&signin_body),
        None,
    )
    .await;
    println!("Status: {}", response.status);
    let data = parse_body(&response.body);
    println!("Logged in as: {}\n", data["user"]["email"]);

    // --- Get session ---
    println!("=== Get session ===");
    let response = send(&auth, HttpMethod::Get, "/get-session", None, Some(&token)).await;
    println!("Status: {}", response.status);
    let data = parse_body(&response.body);
    println!("Session user: {}\n", data["user"]["email"]);

    // --- List sessions ---
    println!("=== List sessions ===");
    let response = send(&auth, HttpMethod::Get, "/list-sessions", None, Some(&token)).await;
    println!("Status: {}", response.status);
    let data = parse_body(&response.body);
    println!(
        "Active sessions: {}\n",
        data["sessions"].as_array().map(|a| a.len()).unwrap_or(0)
    );

    // --- Change password ---
    println!("=== Change password ===");
    let body = serde_json::json!({
        "currentPassword": "password123",
        "newPassword": "newpassword456"
    });
    let response = send(
        &auth,
        HttpMethod::Post,
        "/change-password",
        Some(&body),
        Some(&token),
    )
    .await;
    println!("Status: {}\n", response.status);

    // --- Change email ---
    println!("=== Change email ===");
    let body = serde_json::json!({ "newEmail": "newemail@example.com" });
    let response = send(
        &auth,
        HttpMethod::Post,
        "/change-email",
        Some(&body),
        Some(&token),
    )
    .await;
    println!("Status: {}", response.status);
    let data = parse_body(&response.body);
    println!("New email: {}\n", data["user"]["email"]);

    // --- List accounts ---
    println!("=== List accounts ===");
    let response = send(&auth, HttpMethod::Get, "/list-accounts", None, Some(&token)).await;
    println!("Status: {}", response.status);
    let data = parse_body(&response.body);
    println!("Accounts: {}\n", data["accounts"]);

    // --- Create organization ---
    println!("=== Create organization ===");
    let body = serde_json::json!({
        "name": "Acme Corp",
        "slug": "acme-corp"
    });
    let response = send(
        &auth,
        HttpMethod::Post,
        "/organization/create",
        Some(&body),
        Some(&token),
    )
    .await;
    println!("Status: {}", response.status);
    let data = parse_body(&response.body);
    let org_id = data["id"].as_str().unwrap_or_default().to_string();
    println!("Organization: {} ({})", data["name"], data["slug"]);
    println!("Org ID: {}\n", org_id);

    // --- List organizations ---
    println!("=== List organizations ===");
    let response = send(
        &auth,
        HttpMethod::Get,
        "/organization/list",
        None,
        Some(&token),
    )
    .await;
    println!("Status: {}", response.status);
    let data = parse_body(&response.body);
    println!(
        "Organizations: {}\n",
        data.as_array().map(|a| a.len()).unwrap_or(0)
    );

    // --- Check slug availability ---
    println!("=== Check slug availability ===");
    let body = serde_json::json!({ "slug": "acme-corp" });
    let response = send(
        &auth,
        HttpMethod::Post,
        "/organization/check-slug",
        Some(&body),
        Some(&token),
    )
    .await;
    println!("Status: {}", response.status);
    let data = parse_body(&response.body);
    println!("Slug 'acme-corp' available: {}\n", data["status"]);

    // --- Set active organization ---
    println!("=== Set active organization ===");
    let body = serde_json::json!({ "organizationId": org_id });
    let response = send(
        &auth,
        HttpMethod::Post,
        "/organization/set-active",
        Some(&body),
        Some(&token),
    )
    .await;
    println!("Status: {}\n", response.status);

    // --- Invite member ---
    println!("=== Invite member ===");
    let body = serde_json::json!({
        "organizationId": org_id,
        "email": "colleague@example.com",
        "role": "member"
    });
    let response = send(
        &auth,
        HttpMethod::Post,
        "/organization/invite-member",
        Some(&body),
        Some(&token),
    )
    .await;
    println!("Status: {}", response.status);
    let data = parse_body(&response.body);
    println!("Invitation ID: {}\n", data["id"]);

    // --- Update organization ---
    println!("=== Update organization ===");
    let body = serde_json::json!({
        "organizationId": org_id,
        "name": "Acme Corporation"
    });
    let response = send(
        &auth,
        HttpMethod::Post,
        "/organization/update",
        Some(&body),
        Some(&token),
    )
    .await;
    println!("Status: {}", response.status);
    let data = parse_body(&response.body);
    println!("Updated name: {}\n", data["name"]);

    // --- Sign out ---
    println!("=== Sign out ===");
    let response = send(&auth, HttpMethod::Post, "/sign-out", None, Some(&token)).await;
    println!("Status: {}", response.status);

    // --- Verify session is gone ---
    let response = send(&auth, HttpMethod::Get, "/get-session", None, Some(&token)).await;
    println!("Session after sign-out: {}\n", response.status);

    // --- Invalid route ---
    println!("=== Invalid route ===");
    let response = send(&auth, HttpMethod::Get, "/invalid-route", None, None).await;
    println!("Status: {}\n", response.status);

    println!("Example completed successfully!");

    Ok(())
}

/// Helper: send a request through the auth handler
async fn send(
    auth: &BetterAuth,
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
