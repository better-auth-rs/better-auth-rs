# Better Auth RS

The most comprehensive authentication framework for Rust. Inspired by [Better Auth](https://www.better-auth.com/).

[![Crates.io](https://img.shields.io/crates/v/better-auth.svg)](https://crates.io/crates/better-auth)
[![Documentation](https://docs.rs/better-auth/badge.svg)](https://docs.rs/better-auth)
[![CI](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/better-auth.svg)](LICENSE-MIT)
[![better-auth compatibility](https://img.shields.io/badge/better--auth-v1.4.19-blue?logo=typescript&logoColor=white)](https://www.npmjs.com/package/better-auth/v/1.4.19)

## Features

- **Plugin Architecture** — compose only the auth features you need
- **Type Safety** — leverages Rust's type system for compile-time guarantees
- **Async First** — built on Tokio with full async/await support
- **App-Owned SeaORM Schema** — auth entities live in your SeaORM model graph
- **Framework Integration** — first-class Axum support with session extractors
- **OpenAPI** — auto-generated API specification
- **Middleware** — CSRF, CORS, rate limiting, body size limits
- **Database Hooks** — intercept create/update/delete operations

## Quick Start

```toml
[dependencies]
better-auth = { version = "0.10", features = ["axum", "seaorm2"] }
```

```rust,ignore
use better_auth::{AuthConfig, AuthSchema, BetterAuth};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::seaorm::{AuthEntity, Database, SeaOrmStore};
use better_auth::seaorm::sea_orm::entity::prelude::*;

#[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
#[auth(role = "user")]
#[sea_orm(table_name = "users")]
pub struct UserModel {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub two_factor_enabled: bool,
    pub role: Option<String>,
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTimeUtc>,
    pub metadata: Json,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(AuthSchema)]
#[auth(user = "crate::UserModel")]
#[auth(session = "crate::SessionModel")]
#[auth(account = "crate::AccountModel")]
#[auth(verification = "crate::VerificationModel")]
pub struct AppAuthSchema;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000");
    let store = SeaOrmStore::<AppAuthSchema>::new(config.clone(), database);

    let auth = BetterAuth::<AppAuthSchema>::new(
            config,
        )
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await?;

    Ok(())
}
```

Better Auth no longer owns your SeaORM schema or migrations. Your app defines the auth entities and migrates them alongside the rest of your data model.

## Plugins

Better Auth RS ships with a rich set of plugins. Enable only what you need:

| Plugin | Description |
|--------|-------------|
| **Email/Password** | Sign up/sign in with email & password, username support |
| **Session Management** | Session listing, revocation, and token refresh |
| **Password Management** | Password reset, change, and set flows |
| **Email Verification** | Email verification workflows |
| **Account Management** | Account linking and unlinking |
| **Organization** | Multi-tenant organizations with RBAC |
| **OAuth** | Social sign-in via OAuth 2.0 providers |
| **Two-Factor** | TOTP-based 2FA with backup codes |
| **Passkey** | WebAuthn passkey authentication |
| **API Key** | API key generation, rotation, and revocation |
| **Admin** | User management and administrative operations |

> See the [Plugins documentation](docs/content/docs/concepts/plugins.mdx) for usage details.

## Feature Flags

| Feature | Description |
|---------|-------------|
| `axum` | Axum web framework integration |

## Crate Structure

| Crate | Description |
|-------|-------------|
| [`better-auth`](https://crates.io/crates/better-auth) | Main crate — re-exports and framework integration |
| [`better-auth-core`](https://crates.io/crates/better-auth-core) | Core auth runtime, store, middleware, and error handling |
| [`better-auth-api`](https://crates.io/crates/better-auth-api) | Plugin implementations |

## Documentation

Detailed guides and API reference are available in the [`docs/`](docs/) directory:

- [Contributing](CONTRIBUTING.md)
- [Alignment Roadmap](ROADMAP.md)
- [Installation](docs/content/docs/installation.mdx)
- [Quick Start](docs/content/docs/quick-start.mdx)
- **Authentication** — [Email/Password](docs/content/docs/authentication/email-password.mdx) · [Sessions](docs/content/docs/authentication/sessions.mdx) · [Email Verification](docs/content/docs/authentication/email-verification.mdx)
- **Concepts** — [Configuration](docs/content/docs/concepts/configuration.mdx) · [Database](docs/content/docs/concepts/database.mdx) · [Plugins](docs/content/docs/concepts/plugins.mdx) · [Middleware](docs/content/docs/concepts/middleware.mdx) · [Hooks](docs/content/docs/concepts/hooks.mdx)
- **Plugins** — [OAuth](docs/content/docs/plugins/oauth.mdx) · [Organization](docs/content/docs/plugins/organization.mdx) · [Two-Factor](docs/content/docs/plugins/two-factor.mdx) · [Passkey](docs/content/docs/plugins/passkey.mdx) · [API Key](docs/content/docs/plugins/api-key.mdx) · [Admin](docs/content/docs/plugins/admin.mdx)
- **Reference** — [API Routes](docs/content/docs/reference/api-routes.mdx) · [Configuration Options](docs/content/docs/reference/configuration-options.mdx) · [Errors](docs/content/docs/reference/errors.mdx) · [Security](docs/content/docs/reference/security.mdx) · [OpenAPI](docs/content/docs/reference/openapi.mdx)
- **Integrations** — [Axum](docs/content/docs/integrations/axum.mdx)
- **Compatibility** — [Compatibility Harness](compat-tests/README.md)

## Examples

```bash
# Axum web server
cargo run --example axum_server --features axum

# PostgreSQL
cargo run --example postgres_usage

# Full-stack (better-auth frontend + better-auth-rs backend)
cargo run --manifest-path examples/fullstack/backend/Cargo.toml
```

> See [examples/README.md](examples/README.md) for detailed documentation on each example.

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
