# Better Auth RS

Authentication for Rust with Axum integration and application-owned SeaORM entities. The compatibility target is `better-auth@1.7.6`: routes, payloads, cookies, and errors follow the upstream TypeScript runtime.

> [!WARNING]
> Version `1.0.0-alpha.3` is in development. Public Rust APIs and database schemas can change between alpha releases.

Sessions use signed cookies. Enable `SessionConfig.bearer` explicitly for Authorization header authentication; see the [session guide](docs/content/docs/authentication/sessions.mdx) for cache and application field configuration.

[![Crates.io](https://img.shields.io/crates/v/better-auth.svg)](https://crates.io/crates/better-auth)
[![Documentation](https://docs.rs/better-auth/badge.svg)](https://docs.rs/better-auth)
[![CI](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml)

## Quick start

These examples use the current `master` branch. The DX changes are not yet published as a new crate release. Add these dependencies to your application's `Cargo.toml`:

```toml
[dependencies]
better-auth = { version = "1.0.0-alpha.3", git = "https://github.com/better-auth-rs/better-auth-rs", branch = "master", features = ["axum", "seaorm2"] }
axum = "0.8"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

Generate the core auth entities:

```sh
cargo install better-auth-cli --git https://github.com/better-auth-rs/better-auth-rs --branch master --locked
better-auth-rs generate --output src/auth_schema.rs
```

Use this `src/main.rs`:

```rust,ignore
mod auth_schema;

use auth_schema::{AppAuthSchema, create_auth_tables};
use better_auth::{AuthConfig, BetterAuth};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::seaorm::{Database, SeaOrmStore};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    create_auth_tables(&database).await?;
    let config = AuthConfig::new(std::env::var("AUTH_SECRET")?)
        .base_url("http://localhost:3000");
    let store = SeaOrmStore::<AppAuthSchema>::new(config.clone(), database);
    let auth = Arc::new(
        BetterAuth::<AppAuthSchema>::new(config)
            .store(store)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?,
    );
    let app = axum::Router::new()
        .nest("/auth", auth.clone().axum_router())
        .with_state(auth);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

Set `AUTH_SECRET` to a random secret of at least 32 characters, then run `cargo run`. The in-memory database resets when the process stops. Use application-owned versioned migrations for persistent databases; `create_auth_tables` only initializes an empty database.

The [quick-start guide](docs/content/docs/quick-start.mdx) includes sign-up and cookie session requests; the check gate compiles and runs the documented application. The [independent consumer](compat-tests/schema-consumer) verifies public schema derives, generated entities, registration, login, Axum sessions, API keys, and TOTP.

## Plugins and features

Plugins include email/password, username, sessions, password management, email verification, account management, OAuth, organizations, two-factor authentication, passkeys, API keys, and admin. Enable username with `EmailPasswordPlugin::username(true)`. Generate fields and tables for each selected plugin; startup rejects missing entity fields. See [database integration](docs/content/docs/concepts/database.mdx).

Configure Generic OAuth or OIDC with `OAuthPlugin::add_generic_provider` and `GenericOAuthConfig`. OIDC discovery supplies endpoints and JWKS; set `require_id_token_verification: true` to require verification capability. The [OAuth guide](docs/content/docs/plugins/oauth.mdx) covers client authentication, profile mapping, sign-up restrictions, and email verification. Signature verification requires OpenSSL 3.0 or newer; the complete ML-DSA algorithm set requires OpenSSL 3.5 or newer.

| Cargo feature | Purpose |
| --- | --- |
| `native-tls` | Default TLS backend |
| `rustls` | Alternative TLS backend; disable default features |
| `axum` | Routes and session extractors |
| `seaorm2` | SeaORM store and entity derives |
| `diesel-postgres` | Diesel store on PostgreSQL |
| `diesel-sqlite` | Diesel store on SQLite (bundled) |
| `redis-cache` | Standalone asynchronous Redis cache adapter; not a session storage backend |

## Documentation and development

- [Installation](docs/content/docs/installation.mdx), [Axum integration](docs/content/docs/integrations/axum.mdx), and [Diesel integration](docs/content/docs/integrations/diesel.mdx)
- [API key server API](docs/content/docs/plugins/api-key.mdx) and [database hooks](docs/content/docs/concepts/hooks.mdx)
- [Examples](examples/README.md), [contributing](CONTRIBUTING.md), and [alignment roadmap](ROADMAP.md)
- [Compatibility harness](compat-tests/README.md); upstream behavior remains the source of truth

Install [devenv](https://devenv.sh/getting-started/), then run `devenv test`. Local checks and CI use `scripts/check.sh`.

## License

Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
