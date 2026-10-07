# Compatibility Testing Framework

This directory contains the portable compatibility infrastructure for
validating `better-auth-rs` against the canonical TypeScript Better Auth
runtime.

Run the commands below inside `devenv shell`, or prefix each command with
`devenv shell --`. Run `devenv test` from the repository root for the full gate.

The reference contract gate includes `contracts/telemetry-options.test.ts`. The test compares the pinned upstream telemetry projection with `tests/fixtures/telemetry-options-1.7.6.json` and does not write the fixture. Run `bun test compat-tests/reference-server/contracts/telemetry-options.test.ts` from the repository root for this contract alone. To regenerate the fixture explicitly, run `TELEMETRY_REFERENCE_OUTPUT=tests/fixtures/telemetry-options-1.7.6.json node compat-tests/reference-server/contracts/telemetry-options.mjs` inside the project devenv.

The `Upstream fixture capture` workflow runs each selected capture twice and requires byte-identical JSON before generating `SHA256SUMS`. Artifacts retain both documents and logs, including failed comparisons. Import a fixture only after its capture job succeeds and the source commit and checksum match.

Run `./scripts/check.sh cookie-attributes` inside devenv for focused cookie checks. The stage replays the complete `cookie-attribute-mutation-1.7.6.json` document and runs the related Rust serializer, chunk, LastLogin, expiration, lifetime, and cleanup regressions. The replay compares serialized JSON bytes without rewriting the fixture. Rust compares all captured wire headers in order and checks attribute values before and after writes. JavaScript object identity, property order, own-undefined distinctions, and HTTP `statusText` remain upstream observations; see the [alignment inventory](../docs/upstream-alignment-backlog.md) for the exact boundaries.

## Model

The compatibility system has two layers:

1. **Client-first Bun scenarios** — the primary gate. These use the real
   `better-auth/client` SDK and run each scenario against both the TS
   reference server and the Rust compat server.
2. **Thin raw wire smoke tests** — a small retained Rust suite for
   cookie/header/null-session transport behavior and other cases the
   client layer cannot prove well on its own.

Client observations, response shapes, selected headers, and cookie attributes must match. No scenario-level diff allowlist suppresses mismatches.

Each scenario must assert the intended success or failure before returning observations. Comparing two matching failures does not prove a successful flow. Assert identity relationships with the original IDs before normalizing generated values.

The comparator assigns stable aliases to explicitly listed generated IDs and session secrets across each complete scenario. Aliases preserve identity relationships between responses. A credential account's `accountId` uses the generated user identity; other account IDs remain literal. RP IDs, provider IDs, configuration IDs, provider tokens, token types, missing fields, and external redirect origins remain observable. Metadata and permissions are compared literally. Date values retain their meaning; listed clock fields allow at most 10 seconds of skew between sequential runs. Expiry scenarios must also assert the expected lifetime or exact seeded timestamp.

Configuration scenarios start fresh server pairs with the same `COMPAT_PROFILE`. The profiles cover API keys, device authorization, OTP storage and delivery, Magic Link, one-time tokens, multiple sessions, anonymous upgrades, phone numbers, SIWE, JWT algorithms, Google One Tap, and OAuth Proxy. The `oauth-proxy-env` profile starts a fresh server pair for each hosting-variable and URL-priority case, with environment changes confined to child processes. Set `COMPAT_TEST_PROFILE` to run one configuration during development. The full gate runs every configuration. Each Bun directory argument has a `./` prefix and trailing slash so similarly named profiles cannot run under the wrong server configuration.

The `user-fields` profile uses an application-owned user model. The scenarios cover required fields, constant and dynamic defaults, `onUpdate`, validators, input and output transforms, storage types, protected fields, hidden fields, Email OTP creation, administrator writes, signed JWT claims, and session cache reads. JSON application data is compared literally. A second auth instance shares the database with every user plugin disabled. An existing signed session cache retains disabled plugin fields, matching Better Auth 1.7.6. A read with `disableCookieCache=true` applies the current user schema and removes disabled plugin fields. A third instance marks previously public fields `returned: false`; those fields disappear from both cached and database responses.

Passkey scenarios use an ES256 software authenticator. JWT and One Tap scenarios verify real asymmetric signatures. SIWE scenarios sign Ethereum messages. OAuth Proxy scenarios exchange encrypted profiles between the TS and Rust servers in both directions. The Proxy profiles also verify real OIDC code exchange, API-key account linking, and anonymous upgrades without the original session cookie. These checks preserve identity, expiry, and replay assertions before projecting generated cryptographic material for comparison.

Route checks require zero missing routes in both configured profiles. The all-in profile must match the empty backlog in `deferred-routes.txt`; new gaps and stale backlog entries fail. Route coverage does not establish support for every plugin option or server-only API.

The `organization-core-fields` profile compares built-in field policies across all five Organization models. The scenarios cover transforms, defaults versus explicit null, base-schema precedence, role visibility, timestamp updates, and caller-supplied IDs. ID policy callbacks fail if either adapter invokes them.

The option profiles also cover API Key generators, getters, validators, dynamic default permissions, custom/secondary storage, and database fallback. `plugin-schema` verifies model and column mappings through actual plugin operations. Organization dynamic, member, and native-JSON profiles cover replacement types, nullability, omitted output, nested role overrides, and internal team counters. These scenarios verify the pinned upstream release; route inventory alone is not evidence for untested option combinations.

`organization-invitation-teams` verifies replacement `teamId` values through truthiness checks, before-create hook inputs, adapter joining, persistence, and runtime failures without partial writes.

Secondary-storage profiles exercise session snapshots, cache misses, revocation, preserved database rows, transaction rollback, verification updates, and concurrent consumption. Verification identifier profiles cover hashing, custom functions, prefix selection, and legacy plaintext records with and without secondary storage. The three `session-fields` profiles compare defaults, validators, transforms, `onUpdate`, visibility, and JSON fields with database storage, secondary storage, and both together.

The four `cookie-version-*` profiles compare asynchronous version callbacks, hidden-field visibility, invalidation after revocation, and callback failures for Compact, JWT, JWE, and plugin-signed JWT caches against the upstream runtime.

The `jwt-claims`, `jwt-date`, and `jwt-relative` profiles verify signatures, audience-array intersection, payload overrides, fractional NumericDate values, and relative-duration rounding. Every observed issuer must equal its runtime's base URL before comparison normalizes the local test ports.

The `jwt-adapter` profile verifies custom key callbacks, native request context, per-call option replacement, header decoding, claim errors, cookie caches and after-hook session snapshots. Native token calls distinguish omitted headers from an empty collection and authenticate both `Cookie` and `cookie`. SQLite and Ephemeral transaction tests verify that native and cookie signing share uncommitted keys and preserve rollback. An expired session's null response can carry a JWT header in upstream 1.7.6; the scenario preserves that behavior without treating the header as authenticated session state.

The three `custom-session*` profiles cover typed callback store access, original internal authentication, null results, nested read errors, callback rejection, response headers and cache cookies. A two-callback barrier proves concurrent list execution. A delayed side effect proves another callback's rejection does not cancel pending work. The deferred profile verifies the refresh signal and the GET-only override.

The `organization-jwt` profile verifies teams together with asymmetric session caches, JWT callbacks, transformed user fields, and application-owned session fields. It compares complete session and user objects after cryptographic verification. The same profile verifies OIDC mapped field creation and updates.

The Cargo runner builds the Rust fixture before starting either server. Each server binds port `0`, keeps its listener open, and reports `COMPAT_SERVER_PORT=<assigned port>` on stdout. Fixture URLs use that assigned port. The wire smoke tests use the same startup helper and stop their reference child when each test releases its fixture guard; separate test processes do not share a fixed port. Hosting-variable `{base}` templates are expanded inside each child after binding; the Rust child expands them before creating its Tokio runtime. Health deadlines include the bound-port report and initialization, not compilation or Cargo lock waits. The full gate starts two OIDC issuers and two TS/Rust pairs concurrently to verify distinct listeners, health checks, and discovery URLs. Run that regression alone with `cargo test --locked --test client_compat_tests parallel_server_startup -- --ignored --nocapture`.

Paired scenarios have a 30-second default deadline for both runtimes together. Multi-step authentication retains the upstream scrypt parameters; Cargo optimizes the scrypt dependency in development builds. The Cargo runner stops Bun at the first failed scenario because a timed-out callback can still write to the shared fixture database. Individual scenarios may specify a longer deadline for deliberate expiry waits. Assertions and trace comparison remain unchanged.

Generic OAuth scenarios use a shared local OIDC issuer with real signed ID tokens, discovery, JWKS, and token endpoints. They cover nonce binding, issuer and audience checks, key rotation, profile mapping, authorization parameters, client authentication, refresh, and provider logout. The Cargo runner starts the issuer and both auth servers. Run only these scenarios with `devenv shell -- cargo test --test client_compat_tests oidc_client_compat -- --ignored --nocapture`.

## Components

### `compat-tests/reference-server/`

Portable Bun-native TypeScript reference server.

- Runtime: Bun
- Database: `bun:sqlite`
- Better Auth version: published `better-auth@1.7.6`
- Test controls: reset state, reset-password token seeding, sender mode,
  OAuth account seeding, OAuth refresh mode, server-only API key creation,
  update, and verification

Start directly for debugging:

```bash
cd compat-tests/reference-server
bun install
bun run server.ts
```

### `compat-tests/client-tests/`

Bun test project containing phase-scoped client scenarios and the shared
TS-vs-Rust diff harness.

Direct phase runs:

```bash
cd compat-tests/client-tests
bun test tests/phase0
bun test tests/phase1
bun test tests/phase2
bun test tests/phase3
bun test tests/phase4
bun test tests/phase5
bun test tests/phase6
bun test tests/phase7
bun test tests/phase8
bun test tests/phase9
bun test tests/phase10
bun test tests/phase11
bun test tests/phase12
```

### `compat-tests/rust-server/`

Minimal Axum server matching the reference server config exactly.

## Primary commands

Cargo-native orchestration:

```bash
cargo test --test client_compat_tests phase0_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase1_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase2_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase3_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase4_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase5_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase6_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase7_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase8_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase9_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase10_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase11_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase12_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests full_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests configuration_client_compat -- --ignored --nocapture
```

Thin raw wire smoke:

```bash
cargo test --test wire_compat_smoke_tests -- --nocapture
```

Convenience wrapper:

```bash
bash compat-tests/client-tests/run-against-both.sh phase0
bash compat-tests/client-tests/run-against-both.sh phase1
bash compat-tests/client-tests/run-against-both.sh phase2
bash compat-tests/client-tests/run-against-both.sh phase3
bash compat-tests/client-tests/run-against-both.sh phase4
bash compat-tests/client-tests/run-against-both.sh phase5
bash compat-tests/client-tests/run-against-both.sh phase6
bash compat-tests/client-tests/run-against-both.sh phase7
bash compat-tests/client-tests/run-against-both.sh phase8
bash compat-tests/client-tests/run-against-both.sh phase9
bash compat-tests/client-tests/run-against-both.sh phase10
bash compat-tests/client-tests/run-against-both.sh phase11
bash compat-tests/client-tests/run-against-both.sh phase12
bash compat-tests/client-tests/run-against-both.sh all
```

### Enabled organization profiles

`organization-extended` enables teams and dynamic access control with the upstream default access-control statements. The scenarios verify team and role lifecycles, active team sessions, membership identity, duplicate membership, permission revocation, assigned-role deletion, and tenant isolation. `organization-limits` disables default teams, permits removing the last team, and verifies team, member, and role limits plus concurrent duplicate membership. `organization-no-ac` verifies the explicit missing-access-control configuration error. `organization-cache` verifies upstream cache write timing, fresh database session identities, and active-team selection with the session cookie cache enabled. Phase 6 retains the default organization configuration.

`organization-invitation-options` and `organization-invitation-unverified` verify invitation replacement with a pending-invitation limit of one. Both profiles check resend identity, cancellation before validation, recipient authorization, pending-state errors, departed inviters, and the distinction between invitation lookup and acceptance. They enable and explicitly disable recipient email verification respectively. Listing invitations for a session email requires verification in both profiles.

`organization-fields` uses application-owned tables for all six organization models. The scenarios compare additional fields on organizations, members, invitations, teams, and roles. They cover required and nullable input, protected and hidden fields, defaults, transforms, update callbacks, and custom table and column names. Role updates return the upstream request projection; later reads verify transformed storage separately.

`organization-callbacks` compares lifecycle hook arguments, data overrides, dynamic limits, metadata, and server-only member creation. `organization-custom-team` verifies custom default-team creation. Failed invitation acceptance must preserve the upstream compensation updates without creating organization or team memberships.

`organization-metadata` compares raw test-helper storage on Memory and SQLite. Raw strings and SQL NULL retain their values; Memory accepts raw objects, while SQLite rejects them. Normal create and update responses decode metadata, and later reads retain the stored JSON text. Rust persistence tests separately retain the explicit JSON-model contract.

Run each profile with the existing dual-runtime harness:

```bash
COMPAT_TEST_PROFILE=organization-extended devenv shell -- cargo test --locked --test client_compat_tests configuration_client_compat -- --ignored --nocapture
COMPAT_TEST_PROFILE=organization-cache devenv shell -- cargo test --locked --test client_compat_tests configuration_client_compat -- --ignored --nocapture
COMPAT_TEST_PROFILE=organization-limits devenv shell -- cargo test --locked --test client_compat_tests configuration_client_compat -- --ignored --nocapture
COMPAT_TEST_PROFILE=organization-no-ac devenv shell -- cargo test --locked --test client_compat_tests configuration_client_compat -- --ignored --nocapture
```

The `aligned-rs` and `all-in` OpenAPI profiles enable teams and dynamic roles. Both profiles require zero route gaps.

The `organization-empty-roles` profile preserves the distinction between omitted roles and an explicit empty role map. The owner receives no default permissions, denied mutations retain upstream error codes, and the organization remains unchanged.

The eight `two-factor-*` option profiles verify passwordless management and per-factor overrides, disabled TOTP, server-only TOTP generation, digit counts and periods, plain/hashed/encrypted/custom OTP storage, OTP attempt limits, custom backup generation, and backup-code storage. Scenarios decrypt actual persisted secrets and backup codes with the pinned upstream crypto implementation. Custom-codec failure, duplicate backup codes, OTP exhaustion, and replay remain observable.

The `two-factor-context` profile installs only the context-aware sender. The callback reads the typed store and observes validated input, request headers, and the resolved session. The scenario verifies rejected unauthenticated requests, input filtering, and delivery errors after OTP persistence.

`password-scrypt` verifies bidirectional credentials with the pinned upstream: each server verifies the other's persisted hash and signs in after a database credential transfer. The five `password-security*` profiles cover HIBP path selection, registration order, disabled checks, custom messages, actual range HTTP headers and failures, hash ordering, reset-token consumption, admin partial persistence, and sign-in validation.

The nine `captcha-*` profiles exercise real local provider requests, endpoint matching, provider failures and BotID callbacks. Unknown paths and unsupported HTTP methods still execute HTTP request hooks. CAPTCHA runs before media-type and JSON parsing errors. Sign-in fixtures also exercise URL-encoded bodies and schema/CSRF ordering.

The three `http-body*` profiles verify matched-route JSON decoding before origin checks and authentication, persisted form signup, and the OAuth/device-code form exceptions. They distinguish explicit `disableCSRFCheck: false` from an omitted value when `disableOriginCheck` is enabled. The successful multi-login scenario uses the existing 30-second scrypt test budget.

`crypto-database` and `crypto-cookie` transfer encrypted records, OAuth state and account cookies between runtimes. The scenarios preserve key versions, state bindings and error redirects while checking rotation, key retirement, explicit legacy fallback and cookie confidentiality. Large account cookies cross runtimes unchanged, clear stale chunks when replaced, and expire all chunks on sign-out. Access-token retrieval covers damaged and retired credentials before and after expiry, including unused refresh tokens. `device-generators` awaits both generators and verifies failure persistence, retry order and Unicode limits.

The three `auth-lifecycle*` profiles inspect reset expiry, session freshness, deletion confirmation and callback failures at their persistence boundaries. `user-admission` and `user-admission-protected` verify typed creation sources, transaction rollback, OAuth admission and protected signup responses.

The five `email-otp-native*` profiles call the server-only creation and recovery APIs. The scenarios compare plain, hashed, encrypted and custom storage, callback failures, missing/expired records and generation context without adding public authentication routes.

The five `stateless-*` profiles create authentication without a database, rebuild the whole auth instance between requests, and preserve only explicitly configured secondary storage. They compare omitted and explicit defaults, JWE session recovery, cache bypass and tampering, OAuth PKCE state, account-cookie token refresh, secondary revocation, lifecycle hook context, and both directions of encrypted-cookie interoperability. The two refresh profiles check actual expiry and confirm that renewal does not extend the original session expiry. The Rust application route uses `CachedSession` and propagates its response cookies.

The `oauth-popup-database` and `oauth-popup-cookie` profiles use real provider token and user-info HTTP requests. They check signed opener markers, state persistence, bearer authentication, completion HTML and CSP, error-cookie ordering, marker cleanup, and JSON date revival. The OAuth state Unicode boundary remains explicitly recorded in the alignment inventory.

The `dispatch-errors` profile compares HTTP and native calls at the request, before-hook, endpoint, and after-hook boundaries. Five scenarios cover 38 combinations of API errors, ordinary errors, redirects, returned responses, and recovered errors. The fixture observes explicit error headers, captured context headers, hook order, and persisted verification writes independently.

The `last-login-*` profiles exercise the Last Login Method plugin with real SQLite, secondary session storage and the implicit adapter. Their shared scenarios cover HTTP/native context, native and replaced request bodies, resolver and cookie veto callbacks, persistence failures, protected input, mapped fields, adapter/public field precedence and cached output transforms. The cookie profile also checks a custom `__Host-` name and fractional lifetime. `tests/plugin_runtime_tests.rs` verifies per-instance policy isolation over shared records and plugin/application hooks inside a real rollback/commit transaction.

The `identity-context` profile compares typed Magic Link and Anonymous callbacks and signup session issuance. Five scenarios cover 34 HTTP/native combinations: header presence, callback input and response context, hidden issued snapshots despite later database mutations, failure persistence, response cookies, and `rememberMe` validation and lifetime.

The seven `username-*` profiles compare all Username options through actual SQLite persistence. Seventeen scenarios cover omitted/pre/post validation order, non-idempotent normalization counts, asynchronous rejection, mapped user columns, case-sensitive identities, disabled display fields, immutable and nullable updates, native endpoints, direct adapter writes, and Email OTP/Phone/Admin creation. `tests/username_runtime_tests.rs` separately verifies active-transaction uniqueness and rollback for SQLite and EphemeralStore, plus verification delivery failure boundaries.


The `dynamic-context` profile passes nine paired scenarios for request URL resolution, proxy trust, asynchronous origins/providers, native source precedence, initialization and callback errors, plugin origin merging, and concurrent tenant isolation. Cookie cases use real signup and authentication with custom names and attributes, a chunked cache, and complete deletion. The shared renderer preserves dotted Domain spelling and parent chunk attributes.

`dynamic-environment` runs ten independent server processes with isolated URL environment sources. `dynamic-oauth` verifies tenant-bound persisted OAuth state and trusted-provider linking in real SQLite. `dynamic-native` passes five scenarios for source-free/fallback facades, header-only Admin and transaction-bound Email OTP; rejected transactions retain no OTP. `tests/dynamic_runtime_tests.rs` separately verifies per-instance database-hook context and scope restoration after errors.

`request-oauth-memory` and `request-oauth-sqlite` compare HTTP and native input schemas before session authentication. The scenarios preserve nested error order, raw hook input, projected provider callbacks, original Request bytes, account-token writes, and unchanged credentials after a rejected ID token.

### Trailing slashes and HTTP response hooks

The `trailing-slashes-default`, `trailing-slashes-true`, and `trailing-slashes-false` profiles run four paired scenarios each. They cover GET/POST route shapes, declared trailing slashes, dynamic endpoint templates, consecutive slashes, base-path boundaries, disabled-path precedence, original Request URLs, body errors, early replies, mutable response-hook chains, and replacement stopping. Query coverage uses single values; repeated query values remain a separate contract.


The `request-query-memory` and `request-query-sqlite` profiles cover raw HTTP duplicate parameters, native omitted/null/mixed-array input, validated handler scope, and unchanged before/after hook input. The profiles also execute actual Session, Admin, and Organization routes. Array filter tests use real rows and authenticated sessions, and session tests distinguish stale cookie data from an authoritative read.


The same request-query profiles verify unknown-key removal, optional account-selection unions, API-key numeric coercion, passkey registration queries, and actual member/user pagination. SQLite rejects fractional SQL pagination; the implicit memory adapter follows JavaScript slice semantics. Body cases inspect real password hashing, verification senders, database hooks, and session deletion. They compare JSON, form, native, and native-with-Request calls, including delayed before-hook changes and body-before-query error order.


The request-query profiles verify validation before authentication, strict account selection, empty session-token acceptance, and actual email updates and session revocation. Separate `request-record-memory` and `request-record-sqlite` profiles verify required bodies, prototype-key projection, raw hooks, persisted profile updates and truthy email rejection. Raw-value persistence scenarios use separate fixture storage from string-query contracts. HTTP origin checks retain their earlier rejection boundary. Endpoint hooks see raw input; database hooks see the validated projection. The reference fixture captures original request bytes before dispatch because endpoints can consume the Request stream.


The `request-plugin-memory` and `request-plugin-sqlite` profiles each run five scenarios. Username, one-time token, multi-session, and email-verification bodies validate at the shared endpoint boundary before authentication and side effects. Tests preserve raw hooks, validated sender/storage input, real credentials and token replay rejection. A null signup body also proves that Username before hooks run before the core schema and retain the upstream ordinary error.

The four `request-change-email*` profiles run 22 scenarios across HTTP and native calls. They cover disabled configuration, missing verification delivery, confirmation and verification flows, custom/default token expiry, stale session-cache bypass, existing target emails, async delivery failure, and cancelled database updates. Cancelled updates retain the stored email while the endpoint still issues credentials and sends its requested-email snapshot. Cookie jars apply repeated cookie names in browser order; the separate raw-header difference remains in the alignment backlog. Three `nullable_user_update_tests` exercise SQLite and Ephemeral transactions, secondary-cache ordering, missing rows, cancellation, and unmasked hook/transform errors.

The `request-organization-memory` and `request-organization-sqlite` profiles validate all 22 Organization HTTP body schemas through both HTTP and native dispatch. They cover ordered multi-field errors, nested unknown-field projection, role-selector unions, deprecated permission input, real role/team/invitation writes, raw endpoint hooks and validated lifecycle hooks. Native organization creation distinguishes omitted headers from explicit empty headers and preserves user ownership. A shared-store Rust regression proves that two auth instances keep independent captured field schemas.

`request-security-memory` and `request-security-sqlite` verify shared body validation for Magic Link, One Tap, Passkey, Device Authorization, and SIWE. The scenarios compare HTTP and native error aggregation, raw endpoint hooks, projected sender input, SIWE Request presence, device form multiplicity, and real Magic Link, claimed-device, and WebAuthn success flows.

The `request-admin-memory` and `request-admin-sqlite` profiles compare all twelve Admin body schemas, ID coercion, raw endpoint hooks, and validated lifecycle input. They exercise requestless provisioning, credential creation and login, fractional bans, authoritative revocation, impersonation, role changes, and deletion through HTTP and native endpoints.

`request-api-key-memory` and `request-api-key-sqlite` compare API Key body validation through HTTP and native calls. The scenarios cover schema-order aggregation, raw hook input, callback defaults, unknown-key removal, client-only restrictions, requestless acting-user coercion, ownership rejection, update and deletion persistence, and verification errors that do not consume quota.

The four `request-two-factor-*` profiles exercise eight HTTP body schemas and two server-only body schemas. The Memory and SQLite flows verify real TOTP enrollment, the stale response versus persisted user state, OTP delivery and consumption, backup-code replay rejection, password checks, and disablement. The two option profiles invert global and nested password requirements. Raw endpoint hooks and projected password/sender inputs remain separate; native-only helpers remain unavailable through HTTP.

### Native endpoint dispatch

The `native-dispatch` profile exercises six server-only endpoints through Email OTP, JWT and Two Factor facades in five scenarios. It compares raw before/after input, delayed context patches, validated callback input, original Request/header presence, private HTTP visibility, real OTP persistence and JWT claims, hook response replacements, API-error headers and ordinary failures. Signing-option patches must change the resulting JWT claims. Rust integration tests separately verify operation spans, transaction rollback and dispatcher lifetime ownership.

The three `phone-native-*` profiles exercise `consumePhoneNumberOTP` through Memory, SQLite, and a custom verifier. Fifteen paired scenarios cover raw hooks, projected callback input, body errors, delayed patches, response replacement, original Request/header presence, attempts, expiry, replay, borrowed transactions, and HTTP exclusion. A separate real SQLite regression compares commit, rollback, hook cancellation, cache deletion failure, and after-hook failure against pinned upstream observations.

The `two-factor-after-memory` and `two-factor-after-sqlite` profiles compare credential sign-in through HTTP and native endpoints. The traces retain global and plugin after-hook order, session creation and deletion, proof creation, response replacement, ordinary errors, pending cookie cleanup, and real trusted-device rotation.

`reference-server/required-headers-oracle.ts` reads the pinned endpoint schemas and executes 184 native cases across every registered `requireHeaders` endpoint. `tests/required_headers_tests.rs` compares exact status and body values for omitted headers, an original Request alone, explicit empty headers, invalid bodies, and invalid queries. The regression also checks raw before/after hook input after header validation fails. Regenerate `tests/fixtures/required-headers-upstream.json` with `bun run required-headers-oracle.ts ../../tests/fixtures/required-headers-upstream.json` from `reference-server` inside the project devenv.

The default Bun contract gate also checks `network-options.test.ts`. The contract compares normal IP and cookie resolution plus telemetry presence against `tests/fixtures/network-options-1.7.6.json` in a fresh production process. The test does not rewrite the fixture. To regenerate the fixture explicitly, run `NODE_ENV=production NETWORK_REFERENCE_OUTPUT=/absolute/path/network-options-1.7.6.json node contracts/network-options.mjs` from the reference-server directory.
