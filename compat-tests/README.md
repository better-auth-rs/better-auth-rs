# Compatibility Testing Framework

This directory contains the portable compatibility infrastructure for
validating `better-auth-rs` against the canonical TypeScript Better Auth
runtime.

Run the commands below inside `devenv shell`, or prefix each command with
`devenv shell --`. Run `devenv test` from the repository root for the full gate.

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

The `organization-jwt` profile verifies teams together with asymmetric session caches, JWT callbacks, transformed user fields, and application-owned session fields. It compares complete session and user objects after cryptographic verification. The same profile verifies OIDC mapped field creation and updates.

The Cargo runner builds the Rust fixture before starting either server. Health deadlines measure server startup, not compilation or Cargo lock waits.

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

Run each profile with the existing dual-runtime harness:

```bash
COMPAT_TEST_PROFILE=organization-extended devenv shell -- cargo test --locked --test client_compat_tests configuration_client_compat -- --ignored --nocapture
COMPAT_TEST_PROFILE=organization-cache devenv shell -- cargo test --locked --test client_compat_tests configuration_client_compat -- --ignored --nocapture
COMPAT_TEST_PROFILE=organization-limits devenv shell -- cargo test --locked --test client_compat_tests configuration_client_compat -- --ignored --nocapture
COMPAT_TEST_PROFILE=organization-no-ac devenv shell -- cargo test --locked --test client_compat_tests configuration_client_compat -- --ignored --nocapture
```

The `aligned-rs` and `all-in` OpenAPI profiles enable teams and dynamic roles. Both profiles require zero route gaps.
