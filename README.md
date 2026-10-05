# Better Auth RS

Authentication for Rust with Axum integration and application-owned SeaORM entities. The compatibility target is `better-auth@1.7.6`: routes, payloads, cookies, and errors follow the upstream TypeScript runtime.

> [!WARNING]
> Version `1.0.0-alpha.3` is in development. Public Rust APIs and database schemas can change between alpha releases.

Configure model IDs and application-owned defaults through [database ID generation](docs/content/docs/concepts/database.mdx#model-ids).

Custom adapters must provide a credential-account point query independent of list pagination; see [adapter configuration](docs/content/docs/concepts/database.mdx#adapter-configuration). Enable `advanced.database.joins = Some(true)` for typed core and Organization associations with Memory child references or SeaORM query snapshots.

Sessions use signed cookies. Response headers preserve repeated cookie writes in order; explicit expiration removes earlier values and chunks. Enable `SessionConfig.bearer` explicitly for Authorization header authentication; see the [session guide](docs/content/docs/authentication/sessions.mdx) for cache and application field configuration. Use [Custom Session](docs/content/docs/plugins/custom-session.mdx) to transform public session responses with typed application context. Use [Multi Session](docs/content/docs/plugins/multi-session.mdx) to remember and switch between accounts, with adapter-specific session selection and joined field projection.

Use `BetterAuth::stateless(config)` without an application schema or database. Encrypted session and OAuth cookies survive adapter restart; process-local users and plugin records do not. See [stateless sessions](docs/content/docs/authentication/sessions.mdx#stateless-sessions) for storage defaults, hooks, and revocation behavior.

Configure application user fields with `AuthConfig.user.fields_mut()` and matching application-owned entity columns. Configured fields use their logical name when `field_name` is omitted or empty, including username projections. User lists filter and sort declared scalar display fields by logical or mapped name before output transforms, including nullable String, Boolean, and Number filters. SeaORM reads non-reference String query values from model columns; SQLite also reads declared Boolean and Number additional columns. SQLite additional-field output also reads supported non-reference column values before callbacks and decoding, preserving null and empty values despite Serde omission. Undeclared filters return an error. Undeclared nonempty sort fields fail before SQL reads; Memory reports the error when at least two filtered rows require comparison. See [user fields](docs/content/docs/concepts/users-accounts.mdx) for input validation, defaults, transforms, public visibility, output coverage, Memory JSON representation, and SQL query column mappings.

Adapter-created JSON text uses JavaScript property ordering and number formatting. See [JSON field bindings](docs/content/docs/concepts/database.mdx#json-field-bindings) for the fallible conversion API and native SQL JSON storage boundary.

Account and Verification Memory fields store JSON as text and retain native arrays. See [field representation](docs/content/docs/concepts/account-verification-fields.mdx#memory-json-and-arrays) for callback values and reference conversion.

User record updates preserve raw `name` and `image` values through `SchemaValue`; see [database integration](docs/content/docs/concepts/database.mdx#existing-databases) for physical column contracts and the SQLite parameter-binding safety boundary.

Native SQLite User timestamp writes use UTC text with millisecond precision. See the [database guide](docs/content/docs/concepts/database.mdx#existing-databases) for precision and custom-model limits; the paired contract verifies equal raw text and four public reads for its fixed inputs.

The schema generator keeps its default table name when `modelName` is omitted or empty. Fresh SQLite generation uses upstream native table and column defaults for User, Account, Verification, JWK, RateLimit, Member, OrganizationRole, Team, and Invitation with teams enabled; bundled entities retain their existing mappings. Generated SQLite User email is required by the database while its Rust input remains optional. Generated SQLite Invitation storage uses an optional role; public invitation inputs and role logic remain unchanged. Fresh SQLite Session generation uses an explicit row-presence model; `--session-active-column` retains the Rust active-column extension for regeneration. See [schema mapping](docs/content/docs/concepts/database.mdx#map-plugin-tables-and-columns) for configuration, preserved declarations, and migration boundaries.

Passkey `name`/`aaguid` and API Key `name` preserve omitted and null display values through `SchemaValue<Option<String>>`; see [plugin fields](docs/content/docs/concepts/database.mdx#plugin-fields).

API Key expiration configuration accepts fractional seconds for its default and fractional days for its bounds; see [API Key configuration](docs/content/docs/plugins/api-key.mdx#expiration-configuration) for units and the floating-point field migration.

Configure Social LINE with `OAuthProvider::line`, or Generic LINE with `GenericOAuthConfig::line` and resolved inputs through `GenericOAuthProfileContext`; see the [OAuth guide](docs/content/docs/plugins/oauth.mdx) for provider-specific PKCE options, the alpha callback migration, and the verification boundary. Social profile fields preserve omitted and null email/verification values; callbacks preserve application errors; the guide describes provider-specific missing-profile responses.

Use [OAuth Popup](docs/content/docs/plugins/oauth-popup.mdx) to return OAuth sign-in results to a trusted popup opener. Enable [OpenAPI](docs/content/docs/reference/openapi.mdx) for the configured runtime schema and Scalar reference page, including custom JWT discovery paths, registered model presence and declaration order, JavaScript model and field-key enumeration, and storage-dependent Verification components.

The [JWT plugin](docs/content/docs/plugins/jwt.mdx) supports local and custom signing, server-only verification, and asymmetric session cookie caches. Database key selection follows the configured query limit.

Use [CAPTCHA](docs/content/docs/plugins/captcha.mdx) for request verification and [Have I Been Pwned](docs/content/docs/plugins/have-i-been-pwned.mdx) for compromised-password checks. [Versioned secrets](docs/content/docs/reference/security.mdx#secret-rotation) support encryption-key rotation with retained legacy data.

[![Crates.io](https://img.shields.io/crates/v/better-auth.svg)](https://crates.io/crates/better-auth)
[![Documentation](https://docs.rs/better-auth/badge.svg)](https://docs.rs/better-auth)
[![CI](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml)

For integration tests, enable `TestUtilsPlugin` and use `auth.test()` for seeded users, authenticated cookies, and OTP capture. See the [test utilities guide](docs/content/docs/plugins/test-utils.mdx).

Cookie lifetime configuration and HTTP cookie helper parameters accept fractional seconds. Explicit `CookieAttributes.expires` uses `chrono::DateTime<Utc>`. HTTP issuance and clearing return `AuthResult` and enforce the 400-day limits before formatting; see [cookie configuration](docs/content/docs/concepts/cookies.mdx) for numeric types and override precedence. The two [Two Factor cookie lifetimes](docs/content/docs/plugins/two-factor.mdx#configuration) use `f64` seconds and preserve explicit zero. The TOTP period and account lockout duration also accept fractional seconds; see the same guide for their numeric and timing boundaries. Direct `TwoFactorStore::record_two_factor_failure` callers provide a borrowed deadline closure, evaluated after the counter reaches the threshold. [OAuth Proxy](docs/content/docs/plugins/oauth-proxy.mdx) accepts finite `f64` seconds for its maximum profile age.

Use `user.additionalFields` and `session.additionalFields` in the CLI schema configuration to generate application columns. Register matching runtime field policies through `AuthConfig.user` and `AuthConfig.session`; see [schema mapping](docs/content/docs/concepts/database.mdx#map-plugin-tables-and-columns).

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

The CLI also preserves explicit core model declarations and the bound rate-limit model name for initialization telemetry. Empty native field mappings retain the model's resolved defaults and raw declarations; see [schema generation](docs/content/docs/concepts/database.mdx#generate-an-initial-schema).

Use `--generate-id serial` for integer IDs. Use `--generate-id uuid --database postgres` for native PostgreSQL UUIDs. The database option also selects storage for fresh application JSON fields: SQLite uses scalar-capable `SqlText`, while PostgreSQL/MySQL retain `Json`. Match the generated schema to the database backend and `AuthConfig.advanced.database.generate_id`. Derived plugin and organization bindings expose declared ID references so Serial writes normalize numeric aliases after configured input transforms.

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

Configure Generic OAuth or OIDC with `OAuthPlugin::add_generic_provider` and `GenericOAuthConfig`, including constructors for Auth0, Keycloak, Okta, Microsoft Entra ID, Gumroad, HubSpot, Patreon, Slack, and Yandex. OIDC discovery supplies endpoints and JWKS; set `require_id_token_verification: true` to require verification capability. The [OAuth guide](docs/content/docs/plugins/oauth.mdx) covers client authentication, profile mapping, sign-up restrictions, and email verification. Signature verification requires OpenSSL 3.0 or newer; the complete ML-DSA algorithm set requires OpenSSL 3.5 or newer.

The [organization plugin](docs/content/docs/plugins/organization.mdx) supports optional teams, team membership limits, active teams, and persisted roles scoped to an organization. Enable teams through `OrganizationTeamsConfig` and dynamic roles through `dynamic_access_control(true)` with access-control statements. Use `auth.organization()?.add_member(Some(body)).await` for server-only member creation through the native hook pipeline.

Memory Serial mode applies Organization reference conversion to stored fields, queries, and internal relation keys. See [Organization field policies](docs/content/docs/plugins/organization.mdx#additional-fields) for typed storage boundaries.

The [device authorization plugin](docs/content/docs/plugins/device-authorization.mdx) supports asynchronous code generators and propagates callback errors before persistence. Default device codes contain ASCII letters and digits; verification links replace any existing user-code query parameter.

The [Admin plugin](docs/content/docs/plugins/admin.mdx) preserves a cancelled user update as a nullable response. Database-hook errors continue to propagate.

[HTTP rate limits](docs/content/docs/reference/configuration-options.mdx#ratelimitconfig) support memory, database, secondary, and custom storage. Use `BetterAuth::call_endpoint` for trusted [native endpoint calls](docs/content/docs/concepts/plugins.mdx) with the registered plugin hooks.

Passwords use Better Auth's scrypt format by default. The [password guide](docs/content/docs/authentication/email-password.mdx) explains explicit Argon2 migration. Add [HaveIBeenPwnedPlugin](docs/content/docs/plugins/have-i-been-pwned.mdx) to reject compromised passwords before hashing.

| Cargo feature | Purpose |
| --- | --- |
| `native-tls` | Default TLS backend |
| `rustls` | Alternative TLS backend; disable default features |
| `axum` | Routes and session extractors |
| `seaorm2` | SeaORM store, entity derives, and SQLite/PostgreSQL/MySQL drivers |
| `redis-cache` | Asynchronous Redis secondary storage for sessions, verifications, and atomic rate-limit counters |

Plugins can register adapter field policies for supported typed model fields and declared DeviceCode, JWK, or WalletAddress additional fields. Supported native display fields use their logical name when `field_name` is omitted or empty; see [plugin field policies](docs/content/docs/concepts/plugins.mdx#register-adapter-field-policies). Wallet create and lookup methods are also available through `AuthTransaction`. Memory Device create, ordinary update, and code lookups read each additional field when its output callback runs. Ordinary JSON uses stored text, while reference arrays reach callbacks before public string conversion; see [Device field policies](docs/content/docs/plugins/device-authorization.mdx#adapter-field-policies) for the supported Memory representations. Direct Organization store configuration also resolves built-in field order.

Optional configuration fields use `Option` to distinguish omission from an explicit value. Construct social providers with a built-in constructor or `OAuthProvider::custom`. See [configuration options](docs/content/docs/reference/configuration-options.mdx) for defaults and [OAuth](docs/content/docs/plugins/oauth.mdx) for provider configuration. [Observability](docs/content/docs/concepts/observability.mdx) documents logging, tracing, opt-in telemetry, and the current alignment boundaries.

Google sign-in maps verified ID-token claims through the shared Google verifier used by One Tap. See [Google profile behavior](docs/content/docs/plugins/oauth.mdx#social-provider-inputs) for custom callbacks and account-info behavior.

Built-in provider constructors supply provider defaults and profile mapping. See [built-in providers](docs/content/docs/plugins/oauth.mdx#built-in-providers) for supported constructors and configuration.

Set `OAuthProvider::redirect_uri` to use a configured provider callback URI for both authorization and code exchange. The optional `client_key` follows each Social provider’s code-exchange options; see the [OAuth guide](docs/content/docs/plugins/oauth.mdx#social-provider-inputs) for exceptions.

Custom `OAuthUserInfoHandler` implementations return `AuthResult<Option<OAuthUserInfoResponse>>` to distinguish a missing profile from an application error. Profile names, emails, and mapper overrides preserve missing, null, and string values, including GitHub email-list fallback. Sign-in normalizes omitted and null names to an empty string for storage and admission; see the [OAuth guide](docs/content/docs/plugins/oauth.mdx).

## Documentation and development

- [Installation](docs/content/docs/installation.mdx) and [Axum integration](docs/content/docs/integrations/axum.mdx)
- [API key server API](docs/content/docs/plugins/api-key.mdx) and [database hooks](docs/content/docs/concepts/hooks.mdx)
- [Secondary storage](docs/content/docs/concepts/secondary-storage.mdx) for sessions, one-time verification values, and API keys
- [Examples](examples/README.md), [contributing](CONTRIBUTING.md), and [alignment roadmap](ROADMAP.md)
- [Compatibility harness](compat-tests/README.md); upstream behavior remains the source of truth

Install [devenv](https://devenv.sh/getting-started/), then run `devenv test`. Local checks and CI use `scripts/check.sh`.

## License

Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

Password reset lifetime configuration uses fractional seconds (`Option<f64>`); see the [password management guide](docs/content/docs/authentication/password-management.mdx) for defaults and migration examples.
