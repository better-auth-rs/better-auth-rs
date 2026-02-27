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
- **Database Agnostic** — in-memory for development, PostgreSQL for production
- **Framework Integration** — first-class Axum support with session extractors
- **OpenAPI** — auto-generated API specification
- **Middleware** — CSRF, CORS, rate limiting, body size limits
- **Database Hooks** — intercept create/update/delete operations

## Quick Start

```toml
[dependencies]
better-auth = "0.8"
```

```rust
use better_auth::{BetterAuth, AuthConfig};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::adapters::MemoryDatabaseAdapter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = BetterAuth::new(
            AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
                .base_url("http://localhost:3000"),
        )
        .database(MemoryDatabaseAdapter::new())
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await?;

    // Mount as an Axum router (requires `axum` feature)
    // let app = auth.axum_router();

    Ok(())
}
```

> See the [Quick Start guide](docs/content/docs/quick-start.mdx) for a complete walkthrough including sign-up, sign-in, and session usage.

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
| `derive` | Derive macros for custom entity types (`AuthUser`, `MemoryUser`, etc.) |
| `sqlx-postgres` | PostgreSQL database support via SQLx |

## Crate Structure

| Crate | Description |
|-------|-------------|
| [`better-auth`](https://crates.io/crates/better-auth) | Main crate — re-exports and framework integration |
| [`better-auth-core`](https://crates.io/crates/better-auth-core) | Core abstractions: traits, config, middleware, error handling |
| [`better-auth-api`](https://crates.io/crates/better-auth-api) | Plugin implementations |
| [`better-auth-derive`](https://crates.io/crates/better-auth-derive) | Derive macros for custom entity types |

## Documentation

Detailed guides and API reference are available in the [`docs/`](docs/) directory:

- [Installation](docs/content/docs/installation.mdx)
- [Quick Start](docs/content/docs/quick-start.mdx)
- **Authentication** — [Email/Password](docs/content/docs/authentication/email-password.mdx) · [Sessions](docs/content/docs/authentication/sessions.mdx) · [Email Verification](docs/content/docs/authentication/email-verification.mdx)
- **Concepts** — [Configuration](docs/content/docs/concepts/configuration.mdx) · [Database](docs/content/docs/concepts/database.mdx) · [Plugins](docs/content/docs/concepts/plugins.mdx) · [Middleware](docs/content/docs/concepts/middleware.mdx) · [Hooks](docs/content/docs/concepts/hooks.mdx)
- **Plugins** — [OAuth](docs/content/docs/plugins/oauth.mdx) · [Organization](docs/content/docs/plugins/organization.mdx) · [Two-Factor](docs/content/docs/plugins/two-factor.mdx) · [Passkey](docs/content/docs/plugins/passkey.mdx) · [API Key](docs/content/docs/plugins/api-key.mdx) · [Admin](docs/content/docs/plugins/admin.mdx)
- **Reference** — [API Routes](docs/content/docs/reference/api-routes.mdx) · [Configuration Options](docs/content/docs/reference/configuration-options.mdx) · [Errors](docs/content/docs/reference/errors.mdx) · [Security](docs/content/docs/reference/security.mdx) · [OpenAPI](docs/content/docs/reference/openapi.mdx)
- **Integrations** — [Axum](docs/content/docs/integrations/axum.mdx)

## Examples

```bash
# Basic usage (in-memory)
cargo run --example basic_usage

# Axum web server
cargo run --example axum_server --features axum

# PostgreSQL
cargo run --example postgres_usage --features sqlx-postgres

# Custom entity types with derive macros
cargo run --example custom_entities --features derive

# Custom ORM adapter
cargo run --example custom_orm_adapter

# Full-stack (better-auth frontend + better-auth-rs backend)
cargo run --manifest-path examples/fullstack/backend/Cargo.toml
```

> See [examples/README.md](examples/README.md) for detailed documentation on each example.

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
