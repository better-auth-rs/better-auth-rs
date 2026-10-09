# Better Auth RS

Authentication for Rust with Axum integration and application-owned SeaORM entities. The compatibility target is `better-auth@1.7.6`: routes, payloads, cookies, and errors follow the upstream TypeScript runtime.

> [!WARNING]
> Version `1.0.0-alpha.3` is in development. Public Rust APIs and database schemas can change between alpha releases.

Configure model IDs and application-owned defaults through [database ID generation](docs/content/docs/concepts/database.mdx#model-ids). User creation evaluates the ID generator at the ID field's schema position among input callbacks.

Custom adapters must provide a credential-account point query independent of list pagination; see [adapter configuration](docs/content/docs/concepts/database.mdx#adapter-configuration). Enable `advanced.database.joins = Some(true)` for typed core and Organization associations with Memory child references or SeaORM query snapshots. Plugins can declare custom models for reference resolution through [runtime model registration](docs/content/docs/concepts/plugins.mdx#register-adapter-field-policies); custom persistence remains the application adapter's responsibility.

Sessions use signed cookies. Cookie attributes follow upstream serialization and mutation order; see the [cookie guide](docs/content/docs/concepts/cookies.mdx) for partitioned chunks and LastLogin prefix behavior. Response headers preserve repeated cookie writes in order; explicit expiration removes earlier values and chunks. Enable `SessionConfig.bearer` explicitly for Authorization header authentication; see the [session guide](docs/content/docs/authentication/sessions.mdx) for cache and application field configuration. Use [Custom Session](docs/content/docs/plugins/custom-session.mdx) to transform public session responses with typed application context. Use [Multi Session](docs/content/docs/plugins/multi-session.mdx) to remember and switch between accounts, with adapter-specific session selection and joined field projection.

Endpoint responses and hook contexts retain native fields until a JSON or byte boundary. Read `AuthResponse.body` with `field_value()`, `json()`, or `bytes()`; hook and endpoint context bodies use `FieldValue`. Explicit native responses expose their own headers through `AuthResponse::explicit_response_headers()`; `headers` retains the endpoint accumulator until HTTP materialization. `native_status()` retains absent, undefined, and explicit native status separately from the effective HTTP `status`. Pass `None` to JSON/native constructors when the endpoint has no explicit status. See [response hooks](docs/content/docs/concepts/plugins.mdx) for native values, replacement, and HTTP header merging.

Use `SessionManager::resolve_native`, `AuthContext::require_native_session`, and `AuthRequest::native_session_snapshot()` to retain native User relationship results. Endpoint and Custom Session callbacks receive `NativeSessionData`; `user_field` reads native properties, and `user_view` exposes object fields through Rust slots. Typed convenience methods require one User. Account and Session stores expose native selectors for complete field mapping and conversion; string methods remain available. Email OTP and Magic Link share sequential access cleanup with the upstream lock and partial-persistence behavior; see [database integration](docs/content/docs/concepts/database.mdx) and [Magic Link](docs/content/docs/plugins/magic-link.mdx).

Use `BetterAuth::stateless(config)` without an application schema or database. Encrypted session and OAuth cookies survive adapter restart; process-local users and plugin records do not. See [stateless sessions](docs/content/docs/authentication/sessions.mdx#stateless-sessions) for storage defaults, hooks, and revocation behavior.

Configure application user fields with `AuthConfig.user.fields_mut()` and matching application-owned entity columns. Configured fields use their logical name when `field_name` is omitted or empty, including username projections. User lists filter and sort declared scalar display fields by logical or mapped name before output transforms, including nullable String, Boolean, and Number filters. SeaORM reads non-reference String query values from model columns; SQLite also reads declared Boolean and Number additional columns. SQLite additional-field output also reads supported non-reference column values before callbacks and decoding, preserving null and empty values despite Serde omission. Undeclared filters return an error. Undeclared nonempty sort fields fail before SQL reads; Memory reports the error when at least two filtered rows require comparison. Runtime callbacks and record fields use `FieldValue`, `FieldDate`, and `FieldMap`; JSON conversion occurs at explicit input, cache, and output boundaries. Use `FieldValidators.input` for public input validation. Default and update factories return `AuthResult<FieldValue>` and propagate failures before storage writes. User creation/update hooks and Session creation hooks receive complete native fields through `FieldMap` and return `DatabaseHookUpdate<FieldMap>`; see [database hooks](docs/content/docs/concepts/hooks.mdx) for patch and secondary-storage ordering. See [user fields](docs/content/docs/concepts/users-accounts.mdx) for input validation, defaults, transforms, public visibility, output coverage, Memory JSON representation, and SQL query column mappings.

API Key, Passkey, DeviceCode, TwoFactor, JWK, and WalletAddress use shared declarations, including index and reference metadata, and adapter policies for all native and additional fields; see [API Key fields](docs/content/docs/plugins/api-key.mdx) and [Passkey fields](docs/content/docs/plugins/passkey.mdx). Direct API Key refill writes must clone the observed `last_refill_at` field to preserve Memory Date identity.

Adapter-created JSON text uses JavaScript property ordering and number formatting. Custom adapters can use `FieldValue` to retain runtime values until an explicit JSON boundary. Manual SeaORM models can use `seaorm::field_value::{from_column, decode_column}` for typed column conversion. See [JSON field bindings](docs/content/docs/concepts/database.mdx#json-field-bindings) for value conversion and native SQL JSON storage.

Account and Verification Memory fields store JSON as text and retain native arrays. See [field representation](docs/content/docs/concepts/account-verification-fields.mdx#memory-json-and-arrays) for callback values and reference conversion. Account/User and Session/User joins execute the selected schema relationship and preserve single, missing, or array results through `better_auth::store::JoinValue`. Memory User associations also preserve omitted fields instead of converting them to null. Session snapshots retain loaded relationships as `SessionData<JoinValue<UserView>>`; see [database integration](docs/content/docs/concepts/database.mdx) for custom adapter migration. `NativeSessionData` preserves native snapshots; `SessionData` defaults to a typed User.

Verification-email hooks and delivery callbacks, user-management callbacks, and Two Factor OTP senders receive native `FieldValue` users. `VerificationEmail::user_view()` provides object field access when an application requires it. See [email verification](docs/content/docs/authentication/email-verification.mdx) for null update results and callback ordering.

Account after-update hooks use `DatabaseUpdateResult` to distinguish a projected single-row result from a batch count. Password-reset flows select all credential Accounts by the original user, provider, and account fields. One Time Token generators can borrow the active endpoint and transaction through `OneTimeTokenCallbacks`; see [database hooks](docs/content/docs/concepts/hooks.mdx) and [One Time Token](docs/content/docs/plugins/one-time-token.mdx).

Account, Verification, and Session before-update hooks receive a mutable `FieldMap` and return `DatabaseHookUpdate<FieldMap>`. Their typed caller DTOs convert once before the shared patch policy. Session cache writers receive the final fields through the same boundary. Trusted plugins can use `BeforeRequestAction::InjectNativeSession` to preserve native Session values through endpoint dispatch. `AdminApi::create_user` uses the same validator, handler, and before/after hooks as its routed endpoint; see [plugin hooks](docs/content/docs/concepts/plugins.mdx).

Session runtime tokens, dates, and optional native strings also use `SchemaValue`; see [Session fields](docs/content/docs/authentication/sessions.mdx#native-runtime-fields) for getters, setters, and custom model migration. User and Session views retain field order through projection and serialization. Creation-after hooks receive nullable results; see [database hooks](docs/content/docs/concepts/hooks.mdx) for committed null readbacks and cancellation.

Public User projection preserves already transformed fields, including missing and own-undefined properties, without repeating adapter callbacks. Declared `returned: false` fields are removed after the output clone. Session expiry, revocation, and refresh consume the projected Session fields, so hiding a native field also changes the value visible to those operations.

All native `UserView` fields and `AuthUser` getters retain replacement values through `SchemaValue`. `FieldValue::Function` retains default callback identity; public output and transaction snapshots propagate `AuthError::DataClone` for function values. Use `.typed()?` for an operation that requires the default Rust type or `.field_value()` to retain the complete value. User input DTOs retain typed convenience fields and accept native replacements through `additional_fields`. The adapter converts each DTO once to an ordered `FieldMap` before hooks and field policies. SQL User/Account rows remain raw until output policies finish. Use `get_user_by_field_value` and `update_user_by_field_value` for native selectors; `update_user_by_id_value` delegates to the same policy and updates retain nullable results. See [database integration](docs/content/docs/concepts/database.mdx#existing-databases) for custom model migration, physical column contracts, and the SQLite parameter-binding safety boundary.

Native SQLite User timestamp writes use UTC text with millisecond precision. See the [database guide](docs/content/docs/concepts/database.mdx#existing-databases) for precision and custom-model limits; the paired contract verifies equal raw text and four public reads for its fixed inputs.

The schema generator keeps its default table name when `modelName` is omitted or empty. Fresh SQLite generation uses upstream native table and column defaults for User, Account, Verification, JWK, RateLimit, Member, OrganizationRole, Team, Invitation with teams enabled, DeviceCode, and WalletAddress. Fresh PostgreSQL and MySQL generation uses native column defaults for User, Account, Verification, JWK, RateLimit, Member, OrganizationRole, Team, Invitation, DeviceCode, and WalletAddress; bundled entities retain their existing mappings. Generated User email is required and uses a native unique constraint; its Rust input remains optional. Generated Invitation storage uses an optional role; public invitation inputs and role logic remain unchanged. Fresh Session generation uses an explicit row-presence model; `--session-active-column` retains the Rust active-column extension for regeneration. Use `--device-code-legacy-schema` to retain the previous DeviceCode representation. See [schema mapping](docs/content/docs/concepts/database.mdx#map-plugin-tables-and-columns) for configuration, preserved declarations, and migration boundaries.

API Key, Passkey, DeviceCode, TwoFactor, JWK, and WalletAddress runtime fields preserve omitted, null, and cross-type values through `SchemaValue<T>`, including response decoding and API Key cache reads. Device consumption retains private storage bindings across output transforms; use a record returned by the adapter for consumption. Custom secondary-storage backends implement `set_native` to receive native cache keys and floating-point TTLs. `get_native` and `delete_native` preserve keys for Session deletion; their default bridges accept strings. Memory preserves key identity, and Redis applies its existing string conversion. Ordinary callers can keep using `get`, `set`, and `delete`. Use `CreateSession.inherited_fields` for values that precede native creation fields and defaults; `additional_fields` retains explicit override precedence. Register replacements after the native plugin to override complete declarations; later native plugins restore their declarations at the original field positions. Generate matching application-owned columns for changed storage types. Cached name sorting propagates ordinary JSON object conversion errors; see [API Key storage](docs/content/docs/plugins/api-key.mdx#storage).

Generate Passkey storage with `--plugins passkey` for the 11 standard columns, or add `--passkey-legacy-schema` to retain opaque credential storage. Bind the generated `AppPluginSchema`; see [Passkey storage modes](docs/content/docs/plugins/passkey.mdx#storage-modes) for typed inputs and application-owned migrations.

Passkey authentication callbacks receive the output-projected `credential_id` as `SchemaValue<String>`. Registration user IDs and `CreatePasskey.user_id` also retain native values through `SchemaValue<String>`. Custom stores implement `list_passkeys_by_user_value`; the existing string method delegates to this boundary. Use `.typed()?` for operations that require ordinary strings or `.field_value()` to retain replacement values; see [Passkey callbacks](docs/content/docs/plugins/passkey.mdx#registration-and-authentication-callbacks).

Generate TwoFactor storage with `--plugins two-factor` for the seven upstream columns and nullable verification fields. Use `--two-factor-legacy-schema` when regenerating the previous schema. Declare application columns with `twoFactor.additionalFields` and register matching runtime policies; see [TwoFactor storage](docs/content/docs/plugins/two-factor.mdx#storage) for the public `additional_fields` maps.

Fresh API Key generation uses table `apikey`, native camelCase columns, nullable Boolean flags, INTEGER numeric columns, and nonunique credential indexes. Use `--api-key-legacy-schema` to retain the previous names, types, nullability, and indexes during regeneration. Runtime flags preserve NULL through `SchemaValue<bool>`; see [schema mapping](docs/content/docs/concepts/database.mdx#map-plugin-tables-and-columns) for the public type and database migration boundaries. API Key expiration configuration accepts fractional seconds for its default and fractional days for its bounds; see [API Key configuration](docs/content/docs/plugins/api-key.mdx#expiration-configuration) for units. Declare application columns with `apikey.additionalFields` and register matching runtime policies; [API Key storage](docs/content/docs/plugins/api-key.mdx#storage) describes the `additional_fields` maps, guarded usage updates, and cache behavior.

Configure Social Twitch with `OAuthProvider::twitch` and `TwitchOptions`, Social LINE with `OAuthProvider::line`, or Generic LINE with `GenericOAuthConfig::line` and resolved inputs through `GenericOAuthProfileContext`; see the [OAuth guide](docs/content/docs/plugins/oauth.mdx) for provider-specific PKCE options, fractional token lifetimes, the alpha callback migration, and the verification boundary. Use `OAuthProvider::gitlab_with_issuer` for self-hosted GitLab. `OAuthCallbacks` supplies custom ID-token verifiers with the typed endpoint context, runtime, and resolved session. Social refresh callbacks and legacy ID-token verifiers retain optional `NativeRequest` metadata. Social profile fields preserve omitted and null email/verification values; callbacks preserve application errors. Verification-email delivery failures are logged without changing the verification decision. The guide describes provider-specific missing-profile responses.

Use `get_oauth_state(&request)?` in request hooks to read generated or validated OAuth state with native values. See the [OAuth state contract](docs/content/docs/plugins/oauth.mdx#state-management) for trusted fields and the UTF-16 object-key boundary. Use [OAuth Popup](docs/content/docs/plugins/oauth-popup.mdx) to return OAuth sign-in results to a trusted popup opener. Enable [OpenAPI](docs/content/docs/reference/openapi.mdx) for the configured runtime schema and Scalar reference page, including custom JWT discovery paths, registered model presence and declaration order, JavaScript model and field-key enumeration, and storage-dependent Verification components.

The [JWT plugin](docs/content/docs/plugins/jwt.mdx) supports local and custom signing, server-only verification, and asymmetric session cookie caches. Database key selection follows the configured query limit.

Use [CAPTCHA](docs/content/docs/plugins/captcha.mdx) for request verification and [Have I Been Pwned](docs/content/docs/plugins/have-i-been-pwned.mdx) for compromised-password checks. [Versioned secrets](docs/content/docs/reference/security.mdx#secret-rotation) support encryption-key rotation with retained legacy data.

[![Crates.io](https://img.shields.io/crates/v/better-auth.svg)](https://crates.io/crates/better-auth)
[![Documentation](https://docs.rs/better-auth/badge.svg)](https://docs.rs/better-auth)
[![CI](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml)

For integration tests, enable `TestUtilsPlugin` and use `auth.test()` for seeded users, authenticated cookies, and OTP capture. See the [test utilities guide](docs/content/docs/plugins/test-utils.mdx).

Cookie lifetime configuration and HTTP cookie helper parameters accept fractional seconds. Explicit `CookieAttributes.expires` uses `chrono::DateTime<Utc>`. HTTP issuance and clearing return `AuthResult` and enforce the 400-day limits before formatting; see [cookie configuration](docs/content/docs/concepts/cookies.mdx) for numeric types and override precedence. The two [Two Factor cookie lifetimes](docs/content/docs/plugins/two-factor.mdx#configuration) use `f64` seconds and preserve explicit zero. The TOTP period and account lockout duration also accept fractional seconds. TOTP counters preserve JavaScript Number window offsets and unsigned 64-bit wrapping; see the same guide for numeric and timing boundaries. Direct `TwoFactorStore::record_two_factor_failure` callers provide a borrowed `FieldDate` deadline closure, evaluated after the projected counter reaches the threshold. `view_backup_codes` returns `FieldValue` so declared native replacements remain observable. [OAuth Proxy](docs/content/docs/plugins/oauth-proxy.mdx) accepts `f64` seconds for its maximum profile age, including the upstream non-finite comparisons.

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

Plugins include email/password, username, sessions, password management, email verification, email OTP, phone numbers, anonymous accounts, SIWE, Magic Link, one-time tokens, multiple sessions, last login method, JWT, OAuth, One Tap, OAuth Proxy, organizations, two-factor authentication, passkeys, API keys, and admin. Use `UsernamePlugin` for username options or `EmailPasswordPlugin::username(true)` for defaults. Generate fields and tables for each selected plugin; startup rejects missing entity fields. Bind generated custom plugin tables with `with_plugin_schema::<AppPluginSchema>()`. See [database integration](docs/content/docs/concepts/database.mdx) and [User field declaration order](docs/content/docs/concepts/users-accounts.mdx).

One-time token lifetimes include storage hashing time. See [session transfer](docs/content/docs/plugins/one-time-token.mdx) for expiration and consumption behavior.

Generic raw-profile handlers return `AuthResult<Option<serde_json::Value>>`: `Some` supplies a profile, `None` reports absence, and application errors propagate. Configure Generic OAuth or OIDC with `OAuthPlugin::add_generic_provider` and `GenericOAuthConfig`, including constructors for Auth0, Keycloak, Okta, Microsoft Entra ID, Gumroad, HubSpot, Patreon, Slack, and Yandex. OIDC discovery supplies endpoints and JWKS; set `require_id_token_verification: true` to require verification capability. The [OAuth guide](docs/content/docs/plugins/oauth.mdx) covers client authentication, profile mapping, sign-up restrictions, and email verification. Signature verification requires OpenSSL 3.0 or newer; the complete ML-DSA algorithm set requires OpenSSL 3.5 or newer.

The [organization plugin](docs/content/docs/plugins/organization.mdx) supports optional teams, team membership limits, active teams, and persisted roles scoped to an organization. Enable teams through `OrganizationTeamsConfig` and dynamic roles through `dynamic_access_control(true)` with access-control statements. Use `auth.organization()?.add_member(Some(body)).await` for server-only member creation through the native hook pipeline.

Memory Serial mode stores numeric primary IDs and returns string IDs through public record APIs. Verification reservations retain their deterministic string IDs. Wallet, Passkey, TwoFactor, and TeamMember owner values use `SchemaValue<String>` and preserve numeric references in storage; use `user_id.typed()?` when you need a string. API Key `referenceId` also preserves native values through `SchemaValue<String>`; upstream does not declare an ID reference, so Serial reference conversion does not apply. Memory Serial mode applies Organization reference conversion to stored fields, queries, and internal relation keys. See [Organization field policies](docs/content/docs/plugins/organization.mdx#additional-fields) for typed storage boundaries.

User, Session, JWK, and Wallet ID declarations retain their field position. The adapter controls their generation and conversion; see [model IDs](docs/content/docs/concepts/database.mdx#model-ids) for nested callback behavior.

The [device authorization plugin](docs/content/docs/plugins/device-authorization.mdx) supports asynchronous code generators and propagates callback errors before persistence. Default device codes contain ASCII letters and digits; verification links replace any existing user-code query parameter.

The [Admin plugin](docs/content/docs/plugins/admin.mdx) preserves a cancelled user update as a nullable response. Database-hook errors continue to propagate. User cache refresh errors use the instance logger and preserve the update result; see [commit ordering](docs/content/docs/concepts/hooks.mdx#provisioning-after-signup).

[HTTP rate limits](docs/content/docs/reference/configuration-options.mdx#ratelimitconfig) support memory, database, secondary, and custom storage. Use `BetterAuth::call_endpoint` for trusted [native endpoint calls](docs/content/docs/concepts/plugins.mdx) with the registered plugin hooks.

Passwords use Better Auth's scrypt format by default. The [password guide](docs/content/docs/authentication/email-password.mdx) explains explicit Argon2 migration. Add [HaveIBeenPwnedPlugin](docs/content/docs/plugins/have-i-been-pwned.mdx) to reject compromised passwords before hashing.

| Cargo feature | Purpose |
| --- | --- |
| `native-tls` | Default TLS backend |
| `rustls` | Alternative TLS backend; disable default features |
| `axum` | Routes and session extractors |
| `seaorm2` | SeaORM store, entity derives, and SQLite/PostgreSQL/MySQL drivers |
| `redis-cache` | Asynchronous Redis secondary storage for sessions, verifications, and atomic rate-limit counters |

API Key, Passkey, DeviceCode, TwoFactor, JWK, and WalletAddress merge complete native and application field declarations through `ModelFields`. Both adapters apply the same record and patch policies before runtime record construction; Memory retains live field reads and SQL retains query snapshots. Native runtime fields preserve dynamic values through `SchemaValue<T>`, while ordinary typed inputs remain available. Generate matching columns with the CLI schema configuration. See [plugin field policies](docs/content/docs/concepts/plugins.mdx#register-adapter-field-policies) and the [alignment inventory](docs/upstream-alignment-backlog.md) for acceptance and remaining differences.

Device request fields support ordered synchronous or asynchronous validation with structured issues. See [request field validation](docs/content/docs/plugins/device-authorization.mdx#request-field-validation) for configuration, storage separation, and the `BodyValidator` migration. A [configured grant](docs/content/docs/plugins/device-authorization.mdx#grant-callbacks) adds typed request authorization, declared stored fields, a required session-redemption policy, and owner-only verification context. Server-only redemption accepts `DeviceCodeOwnership::Where(DeviceCodeWhere)` with 11 comparison operators and two string comparison modes. Conditions use native `scope`, declared non-reference fields, or String, Json, and Date references to `id`, and retain the original code and owner bindings. `In` requires an array before adapter conversion. `FieldEquals`, `FieldIn`, and `FieldNotIn` accept String references; Serial IDs retain the shared numeric conversion. The helper returns the active internal user schema, including hidden fields. See [ownership conditions](docs/content/docs/plugins/device-authorization.mdx#ownership-conditions) for values, backend behavior, and remaining reference limitations.

Optional configuration fields use `Option` to distinguish omission from an explicit value. Construct social providers with a built-in constructor or `OAuthProvider::custom`. See [configuration options](docs/content/docs/reference/configuration-options.mdx) for defaults and [OAuth](docs/content/docs/plugins/oauth.mdx) for provider configuration. [Observability](docs/content/docs/concepts/observability.mdx) documents logging, tracing, opt-in telemetry, Linux CPU and memory metadata, kernel and WSL detection, process-cached Docker detection, and the current alignment boundaries.

Google sign-in maps verified ID-token claims through the shared Google verifier used by One Tap. `GoogleOptions` adds accepted client IDs while retaining the primary ID for authorization and token requests. See [Google profile behavior](docs/content/docs/plugins/oauth.mdx#social-provider-inputs) for configuration, custom callbacks, and account-info behavior.

Built-in provider constructors supply provider defaults and profile mapping, including Sign in with Apple. Social Microsoft uses `OAuthProvider::microsoft` with `MicrosoftOptions`; Generic Entra keeps its separate constructor. See [built-in providers](docs/content/docs/plugins/oauth.mdx#built-in-providers) for supported constructors and configuration.

Set `OAuthProvider::redirect_uri` to use a configured provider callback URI for both authorization and code exchange. The optional `client_key` follows each Social provider’s code-exchange options; see the [OAuth guide](docs/content/docs/plugins/oauth.mdx#social-provider-inputs) for exceptions.

Custom `OAuthUserInfoHandler` implementations return `AuthResult<Option<OAuthUserInfoResponse>>` to distinguish a missing profile from an application error. Profile names, emails, and mapper overrides preserve missing, null, and string values, including GitHub email-list fallback. Sign-in normalizes omitted and null names to an empty string for storage and admission; see the [OAuth guide](docs/content/docs/plugins/oauth.mdx).

## Documentation and development

- [Installation](docs/content/docs/installation.mdx) and [Axum integration](docs/content/docs/integrations/axum.mdx)
- [API key server API](docs/content/docs/plugins/api-key.mdx) and [database hooks](docs/content/docs/concepts/hooks.mdx)
- [Secondary storage](docs/content/docs/concepts/secondary-storage.mdx) for sessions, one-time verification values, and API keys
- [Examples](examples/README.md), [contributing](CONTRIBUTING.md), and [alignment roadmap](ROADMAP.md)
- [Compatibility harness](compat-tests/README.md); upstream behavior remains the source of truth

Install [devenv](https://devenv.sh/getting-started/), then run `devenv test`. Local checks and CI use `scripts/check.sh`. The shell supplies ICU 78.3 for Memory string collation; external builds must configure the ICU library path and major version as described in [installation](docs/content/docs/installation.mdx).

## License

Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

Password reset lifetime configuration uses fractional seconds (`Option<f64>`); see the [password management guide](docs/content/docs/authentication/password-management.mdx) for defaults and migration examples.
