//! # Custom Entity Types Example
//!
//! Demonstrates how to use your own database entity structs with better-auth-rs.
//! Custom types can have extra fields beyond what the framework requires.
//!
//! - `Auth*` derive macros implement the read-only entity traits (getters).
//! - `Memory*` derive macros implement construction/mutation for the in-memory adapter.
//! - Custom fields default to `Default::default()`, or use `#[auth(default = "expr")]`.
//!
//! Run with: `cargo run --example custom_entities --features derive`

use better_auth::plugins::{EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin};
use better_auth::types::{AuthRequest, HttpMethod, InvitationStatus};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth, MemoryDatabaseAdapter};
use better_auth_core::{
    AuthAccount, AuthInvitation, AuthMember, AuthOrganization, AuthSession, AuthUser,
    AuthVerification, MemoryAccount, MemoryInvitation, MemoryMember, MemoryOrganization,
    MemorySession, MemoryUser, MemoryVerification,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;

// ===========================================================================
// Custom Entity Types — derive both Auth* (getters) and Memory* (construct/mutate)
// ===========================================================================

/// Custom user with SaaS-specific fields.
#[derive(Clone, Debug, Serialize, AuthUser, MemoryUser)]
struct AppUser {
    id: String,
    email: Option<String>,
    #[auth(field = "name")]
    display_name: Option<String>,
    email_verified: bool,
    image: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    username: Option<String>,
    display_username: Option<String>,
    two_factor_enabled: bool,
    role: Option<String>,
    banned: bool,
    ban_reason: Option<String>,
    ban_expires: Option<DateTime<Utc>>,
    metadata: HashMap<String, serde_json::Value>,
    // --- Custom fields ---
    #[auth(default = r#""free".to_string()"#)]
    plan: String,
    stripe_customer_id: Option<String>,
    phone: Option<String>,
}

/// Custom session with device tracking.
#[derive(Clone, Debug, Serialize, AuthSession, MemorySession)]
struct AppSession {
    id: String,
    expires_at: DateTime<Utc>,
    token: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    user_id: String,
    impersonated_by: Option<String>,
    active_organization_id: Option<String>,
    active: bool,
    // --- Custom fields ---
    device_id: Option<String>,
    country: Option<String>,
}

/// Standard account (no extra fields needed).
#[derive(Clone, Debug, Serialize, AuthAccount, MemoryAccount)]
struct AppAccount {
    id: String,
    account_id: String,
    provider_id: String,
    user_id: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    access_token_expires_at: Option<DateTime<Utc>>,
    refresh_token_expires_at: Option<DateTime<Utc>>,
    scope: Option<String>,
    password: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Custom organization with billing info.
#[derive(Clone, Debug, Serialize, AuthOrganization, MemoryOrganization)]
struct AppOrganization {
    id: String,
    name: String,
    slug: String,
    logo: Option<String>,
    metadata: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    // --- Custom fields ---
    billing_email: Option<String>,
}

/// Custom member with invite tracking.
#[derive(Clone, Debug, Serialize, AuthMember, MemoryMember)]
struct AppMember {
    id: String,
    organization_id: String,
    user_id: String,
    role: String,
    created_at: DateTime<Utc>,
    // --- Custom fields ---
    invited_by: Option<String>,
}

/// Standard invitation.
#[derive(Clone, Debug, Serialize, AuthInvitation, MemoryInvitation)]
struct AppInvitation {
    id: String,
    organization_id: String,
    email: String,
    role: String,
    status: InvitationStatus,
    inviter_id: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

/// Standard verification.
#[derive(Clone, Debug, Serialize, AuthVerification, MemoryVerification)]
struct AppVerification {
    id: String,
    identifier: String,
    value: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

// Type alias for the adapter parameterized with our custom types.
type AppDatabaseAdapter = MemoryDatabaseAdapter<
    AppUser,
    AppSession,
    AppAccount,
    AppOrganization,
    AppMember,
    AppInvitation,
    AppVerification,
>;

// ===========================================================================
// Main — Run the Full Auth Flow
// ===========================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Custom Entity Types Example ===\n");

    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000")
        .password_min_length(8);

    let auth = AuthBuilder::new(config)
        .database(AppDatabaseAdapter::default())
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(OrganizationPlugin::new())
        .build()
        .await?;

    println!("Plugins: {:?}\n", auth.plugin_names());

    // --- Sign up ---
    println!("--- Sign Up ---");
    let resp = send(
        &auth,
        HttpMethod::Post,
        "/sign-up/email",
        Some(&serde_json::json!({
            "email": "alice@example.com",
            "password": "secure_password_123",
            "name": "Alice",
            "username": "alice"
        })),
        None,
    )
    .await;
    println!("Status: {}", resp.status);
    let data = parse_body(&resp.body);
    let token = data["token"].as_str().unwrap_or_default().to_string();
    println!("User email: {}", data["user"]["email"]);
    println!("User name: {}", data["user"]["name"]);
    // Custom fields appear in the serialized JSON
    println!("User plan: {}", data["user"]["plan"]);
    println!(
        "User stripe_customer_id: {}",
        data["user"]["stripe_customer_id"]
    );
    println!();

    // --- Sign in ---
    println!("--- Sign In ---");
    let resp = send(
        &auth,
        HttpMethod::Post,
        "/sign-in/email",
        Some(&serde_json::json!({
            "email": "alice@example.com",
            "password": "secure_password_123"
        })),
        None,
    )
    .await;
    println!("Status: {}", resp.status);
    let data = parse_body(&resp.body);
    println!("Session device_id: {}", data["session"]["device_id"]);
    println!("Session country: {}", data["session"]["country"]);
    println!();

    // --- Get session ---
    println!("--- Get Session ---");
    let resp = send(&auth, HttpMethod::Get, "/get-session", None, Some(&token)).await;
    println!("Status: {}", resp.status);
    let data = parse_body(&resp.body);
    println!("Session user: {}", data["user"]["email"]);
    println!("User plan: {}", data["user"]["plan"]);
    println!();

    // --- Create organization ---
    println!("--- Create Organization ---");
    let resp = send(
        &auth,
        HttpMethod::Post,
        "/organization/create",
        Some(&serde_json::json!({
            "name": "Acme Corp",
            "slug": "acme-corp"
        })),
        Some(&token),
    )
    .await;
    println!("Status: {}", resp.status);
    let data = parse_body(&resp.body);
    println!("Org: {} ({})", data["name"], data["slug"]);
    println!("Org billing_email: {}", data["billing_email"]);
    println!();

    // --- List sessions ---
    println!("--- List Sessions ---");
    let resp = send(&auth, HttpMethod::Get, "/list-sessions", None, Some(&token)).await;
    println!("Status: {}", resp.status);
    let data = parse_body(&resp.body);
    let count = data["sessions"].as_array().map(|a| a.len()).unwrap_or(0);
    println!("Active sessions: {}", count);
    println!();

    // --- Sign out ---
    println!("--- Sign Out ---");
    let resp = send(&auth, HttpMethod::Post, "/sign-out", None, Some(&token)).await;
    println!("Status: {}", resp.status);

    let resp = send(&auth, HttpMethod::Get, "/get-session", None, Some(&token)).await;
    println!("Session after sign-out: {}\n", resp.status);

    println!("=== Example Complete ===");
    Ok(())
}

// ===========================================================================
// Helpers
// ===========================================================================

async fn send(
    auth: &BetterAuth<AppDatabaseAdapter>,
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

fn parse_body(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap_or(serde_json::Value::Null)
}
