# Better Auth RS

The most comprehensive authentication framework for Rust. Inspired by [Better Auth](https://www.better-auth.com/).

[![Crates.io](https://img.shields.io/crates/v/better-auth.svg)](https://crates.io/crates/better-auth)
[![Documentation](https://docs.rs/better-auth/badge.svg)](https://docs.rs/better-auth)
[![CI](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/better-auth.svg)](LICENSE-MIT)

## Features

- **Plugin Architecture** - Extend and customize authentication flows
- **Type Safety** - Leverages Rust's type system for compile-time guarantees
- **Async First** - Built on Tokio with full async/await support
- **Database Agnostic** - Support for multiple databases through adapter pattern
- **Web Framework Integration** - First-class Axum support
- **OpenAPI** - Built-in OpenAPI spec generation
- **Middleware** - CSRF, CORS, rate limiting, body size limits

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
better-auth = "0.1"
```

```rust
use better_auth::{BetterAuth, AuthConfig};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::adapters::MemoryDatabaseAdapter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000")
        .password_min_length(8);

    let auth = BetterAuth::new(config)
        .database(MemoryDatabaseAdapter::new())
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await?;

    println!("Authentication system ready!");
    println!("Registered plugins: {:?}", auth.plugin_names());

    Ok(())
}
```

### Axum Integration

Enable the `axum` feature:

```toml
[dependencies]
better-auth = { version = "0.1", features = ["axum"] }
```

```rust
use better_auth::{BetterAuth, AuthConfig};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::adapters::MemoryDatabaseAdapter;
use better_auth::handlers::AxumIntegration;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AuthConfig::new("your-secret-key");

    let auth = Arc::new(
        BetterAuth::new(config)
            .database(MemoryDatabaseAdapter::new())
            .plugin(EmailPasswordPlugin::new())
            .build()
            .await?
    );

    let app = auth.axum_router();

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

## Crate Structure

| Crate | Description |
|-------|-------------|
| [`better-auth`](https://crates.io/crates/better-auth) | Main crate, re-exports and Axum integration |
| [`better-auth-core`](https://crates.io/crates/better-auth-core) | Core abstractions: traits, config, middleware, error handling |
| [`better-auth-api`](https://crates.io/crates/better-auth-api) | Plugin implementations (email/password, session management, organization, etc.) |
| [`better-auth-entity`](https://crates.io/crates/better-auth-entity) | Entity definitions (User, Session, Account, Organization, Member, Invitation) |
| [`better-auth-migration`](https://crates.io/crates/better-auth-migration) | Database migrations using sea-orm-migration |

## Plugins

| Plugin | Status | Description |
|--------|--------|-------------|
| Email/Password | Done | Sign up/sign in with email & password, username support |
| Password Management | Done | Password reset, change, set |
| Email Verification | Done | Email verification workflows |
| Session Management | Done | Session listing and revocation |
| Account Management | Done | Account linking and unlinking |
| Organization | Done | Multi-tenant organizations with RBAC |
| OAuth | Planned | Social sign-in (OAuth 2.0) |
| Two-Factor Auth | Planned | TOTP, backup codes |

## API Endpoints

Endpoints are registered by plugins:

```
# Authentication
POST /sign-up/email          # User registration
POST /sign-in/email          # Email-based login
POST /sign-in/username       # Username-based login

# Password Management
POST /forget-password        # Password reset request
POST /reset-password         # Password reset confirmation
POST /change-password        # Change password (authenticated)
POST /set-password           # Set password (authenticated)

# Email Verification
POST /send-verification-email
POST /verify-email

# Session Management
GET  /sessions               # List active sessions
POST /revoke-session         # Revoke a session

# Account Management
GET  /accounts               # List linked accounts
POST /unlink-account         # Unlink an account

# Organization (multi-tenant)
POST /organization/create           # Create organization
POST /organization/update           # Update organization
POST /organization/delete           # Delete organization
GET  /organization/list             # List user's organizations
GET  /organization/get-full-organization
POST /organization/set-active       # Set active organization
POST /organization/leave            # Leave organization
POST /organization/check-slug       # Check slug availability

# Organization Members
GET  /organization/get-active-member
GET  /organization/list-members
POST /organization/remove-member
POST /organization/update-member-role

# Organization Invitations
POST /organization/invite-member
GET  /organization/get-invitation
GET  /organization/list-invitations
POST /organization/accept-invitation
POST /organization/reject-invitation
POST /organization/cancel-invitation

# RBAC
POST /organization/has-permission   # Check permissions
```

## Database Adapters

- **MemoryDatabaseAdapter** - In-memory storage for development and testing
- **SqlxAdapter** - PostgreSQL with connection pooling and migrations (`sqlx-postgres` feature)

## Feature Flags

```toml
[features]
axum = []           # Axum web framework integration
sqlx-postgres = []  # PostgreSQL database support
redis-cache = []    # Redis caching (planned)
```

## Examples

```bash
# Basic usage (in-memory)
cargo run --example basic_usage

# PostgreSQL
export DATABASE_URL="postgresql://user:pass@localhost:5432/better_auth"
cargo run --example postgres_usage --features sqlx-postgres

# Axum web server with interactive demo
cargo run --example axum_server --features axum
```

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
