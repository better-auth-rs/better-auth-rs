# Better Auth RS

Authentication for Rust with Axum integration and application-owned SeaORM entities. The compatibility target is `better-auth@1.7.6`: routes, payloads, cookies, and errors follow the upstream TypeScript runtime.

> [!WARNING]
> Version `1.0.0-alpha.3` is in development. Public Rust APIs and database schemas can change between alpha releases.

Configure model IDs and application-owned defaults through [database ID generation](docs/content/docs/concepts/database.mdx#model-ids).

Sessions use signed cookies. Response headers preserve repeated cookie writes in order; explicit expiration removes earlier values and chunks. Enable `SessionConfig.bearer` explicitly for Authorization header authentication; see the [session guide](docs/content/docs/authentication/sessions.mdx) for cache and application field configuration. Use [Custom Session](docs/content/docs/plugins/custom-session.mdx) to transform public session responses with typed application context. Use [Multi Session](docs/content/docs/plugins/multi-session.mdx) to remember and switch between accounts, with adapter-specific session selection.

Use `BetterAuth::stateless(config)` without an application schema or database. Encrypted session and OAuth cookies survive adapter restart; process-local users and plugin records do not. See [stateless sessions](docs/content/docs/authentication/sessions.mdx#stateless-sessions) for storage defaults, hooks, and revocation behavior.

Configure application user fields with `AuthConfig.user.additional_fields` and matching application-owned entity columns. See [user fields](docs/content/docs/concepts/users-accounts.mdx) for input validation, defaults, transforms, public visibility, and synchronous batch projection.

User record updates preserve raw `name` and `image` values through `SchemaValue`; see [database integration](docs/content/docs/concepts/database.mdx#existing-databases) for physical column contracts and the SQLite parameter-binding safety boundary.

Use [OAuth Popup](docs/content/docs/plugins/oauth-popup.mdx) to return OAuth sign-in results to a trusted popup opener. Enable [OpenAPI](docs/content/docs/reference/openapi.mdx) for the configured runtime schema and Scalar reference page.

The [JWT plugin](docs/content/docs/plugins/jwt.mdx) supports local and custom signing, server-only verification, and asymmetric session cookie caches. Database key selection follows the configured query limit.

Use [CAPTCHA](docs/content/docs/plugins/captcha.mdx) for request verification and [Have I Been Pwned](docs/content/docs/plugins/have-i-been-pwned.mdx) for compromised-password checks. [Versioned secrets](docs/content/docs/reference/security.mdx#secret-rotation) support encryption-key rotation with retained legacy data.

[![Crates.io](https://img.shields.io/crates/v/better-auth.svg)](https://crates.io/crates/better-auth)
[![Documentation](https://docs.rs/better-auth/badge.svg)](https://docs.rs/better-auth)
[![CI](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml)

For integration tests, enable `TestUtilsPlugin` and use `auth.test()` for seeded users, authenticated cookies, and OTP capture. See the [test utilities guide](docs/content/docs/plugins/test-utils.mdx).

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

Use `--generate-id serial` for integer IDs. Use `--generate-id uuid --database postgres` for native PostgreSQL UUIDs. Match the generated schema to `AuthConfig.advanced.database.generate_id`. Derived plugin and organization bindings expose declared ID references so Serial writes normalize numeric aliases after configured input transforms.

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

Set `AUTH_SECRET` to a random secret of at least 32 characters, then run `cargo run`. The builder resolves explicit secrets before `BETTER_AUTH_SECRET` and `AUTH_SECRET`; short secrets warn, while `NODE_ENV=production` rejects the default development key. The in-memory database resets when the process stops. Use application-owned versioned migrations for persistent databases; `create_auth_tables` only initializes an empty database.

The [quick-start guide](docs/content/docs/quick-start.mdx) includes sign-up and cookie session requests; the check gate compiles and runs the documented application. The [independent consumer](compat-tests/schema-consumer) verifies public schema derives, generated entities, registration, login, Axum sessions, API keys, and TOTP.

## Plugins and features

Plugins include email/password, username, sessions, password management, email verification, email OTP, phone numbers, anonymous accounts, SIWE, Magic Link, one-time tokens, multiple sessions, last login method, JWT, OAuth, One Tap, OAuth Proxy, organizations, two-factor authentication, passkeys, API keys, and admin. Use `UsernamePlugin` for username options or `EmailPasswordPlugin::username(true)` for defaults. Generate fields and tables for each selected plugin; startup rejects missing entity fields. Bind generated custom plugin tables with `with_plugin_schema::<AppPluginSchema>()`. See [database integration](docs/content/docs/concepts/database.mdx).

Configure Generic OAuth or OIDC with `OAuthPlugin::add_generic_provider` and `GenericOAuthConfig`. OIDC discovery supplies endpoints and JWKS; set `require_id_token_verification: true` to require verification capability. The [OAuth guide](docs/content/docs/plugins/oauth.mdx) covers client authentication, profile mapping, sign-up restrictions, and email verification. Signature verification requires OpenSSL 3.0 or newer; the complete ML-DSA algorithm set requires OpenSSL 3.5 or newer.

The [organization plugin](docs/content/docs/plugins/organization.mdx) supports optional teams, team membership limits, active teams, and persisted roles scoped to an organization. Enable teams through `OrganizationTeamsConfig` and dynamic roles through `dynamic_access_control(true)` with access-control statements. Use `auth.organization()?.add_member(Some(body)).await` for server-only member creation through the native hook pipeline.

The [device authorization plugin](docs/content/docs/plugins/device-authorization.mdx) supports asynchronous code generators and propagates callback errors before persistence.

[HTTP rate limits](docs/content/docs/reference/configuration-options.mdx#ratelimitconfig) support memory, database, secondary, and custom storage. Use `BetterAuth::call_endpoint` for trusted [native endpoint calls](docs/content/docs/concepts/plugins.mdx) with the registered plugin hooks.

Passwords use Better Auth's scrypt format by default. The [password guide](docs/content/docs/authentication/email-password.mdx) explains explicit Argon2 migration. Add [HaveIBeenPwnedPlugin](docs/content/docs/plugins/have-i-been-pwned.mdx) to reject compromised passwords before hashing.

| Cargo feature | Purpose |
| --- | --- |
| `native-tls` | Default TLS backend |
| `rustls` | Alternative TLS backend; disable default features |
| `axum` | Routes and session extractors |
| `seaorm2` | SeaORM store and entity derives |
| `redis-cache` | Asynchronous Redis secondary storage for sessions, verifications, and atomic rate-limit counters |

Logger options retain omission: assign `Some(LogLevel::Info)` to `config.logger.level` and `Some(true)` to `config.logger.disabled`. Session, account, plugin, HTTP rate-limit, IP, and cross-subdomain options also preserve omission through `Option`; use `Some(Duration::zero())` for refresh on every authoritative session read. Plugin builders keep their scalar arguments; direct plugin config assignments use `Some(value)` for password lengths, automatic sign-in, token lifetimes, and change-email enablement. Direct trusted-origin/provider assignments use `Some(TrustedValues::...)`; existing origin builders keep their arguments. ID policy assignments use `config.advanced.database.generate_id = Some(IdGeneration::Uuid)`; omission keeps random IDs. Cookie override maps use `Option<HashMap<...>>`; call `get_or_insert_default()` before inserting an override. An explicit zero session lifetime resolves to seven days while telemetry retains 0. Stateless cookie-cache defaults appear in initialization telemetry. Telemetry reports upstream plugin IDs; core option wrappers are omitted from the plugin array. Init metadata includes environment, deployment vendor, and an environment-supplied package manager, with explicit Rust system-information limits. See [configuration options](docs/content/docs/reference/configuration-options.mdx) and [observability](docs/content/docs/concepts/observability.mdx) for defaults and the current telemetry projection.

## Documentation and development

- [Installation](docs/content/docs/installation.mdx) and [Axum integration](docs/content/docs/integrations/axum.mdx)
- [API key server API](docs/content/docs/plugins/api-key.mdx) and [database hooks](docs/content/docs/concepts/hooks.mdx)
- [Secondary storage](docs/content/docs/concepts/secondary-storage.mdx) for sessions, one-time verification values, and API keys
- [Examples](examples/README.md), [contributing](CONTRIBUTING.md), and [alignment roadmap](ROADMAP.md)
- [Compatibility harness](compat-tests/README.md); upstream behavior remains the source of truth

Install [devenv](https://devenv.sh/getting-started/), then run `devenv test`. Local checks and CI use `scripts/check.sh`.

## License

Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
