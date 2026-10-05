# Contributing

This project targets strict 1:1 wire-level compatibility with the
canonical TypeScript Better Auth implementation. The TypeScript runtime
is the spec.

The primary compatibility contract is behavior exercised by the official
`better-auth/client` SDK and the TypeScript reference server. Routes,
payloads, headers, cookies, redirects, status codes, and error behavior
must match upstream.

Rust does not need to mirror the TypeScript embedding interface. Public
Rust APIs should follow native Rust ecosystem conventions for the
integrations we support. Axum + SeaORM is the current Rust integration
surface, but it is not itself the compatibility contract.

## Source of Truth

When sources disagree, trust them in this order:

1. Runtime behavior of the TypeScript reference server in
   `compat-tests/reference-server/`
2. TypeScript source in a local checkout of `better-auth@1.7.6` when
   available
3. Generated upstream OpenAPI profiles from the pinned published package
4. Better Auth documentation

The pinned reference version is `better-auth@1.7.6`.

## Non-Negotiables

- No extra public route, wire behavior, or client-observable capability
  beyond upstream TS
- No missing upstream route or behavior
- No legacy Rust-only migration shims or compatibility paths
- Rust-native integration APIs are allowed when they preserve the same
  client-observable contract
- If TS looks buggy, match it anyway and document that choice in code
- If a test conflicts with verified upstream behavior, update the test and
  implementation to match upstream

## Before You Change Code

Install [devenv](https://devenv.sh/getting-started/). The committed
`devenv.lock` pins Rust, Bun, Node.js, pnpm, and native build dependencies.

Run tools through the development shell:

```bash
devenv shell -- bun install --cwd compat-tests/reference-server --frozen-lockfile
devenv shell -- bun install --cwd compat-tests/client-tests --frozen-lockfile
devenv shell -- cargo test --workspace
```

Inspect upstream behavior in the installed `better-auth@1.7.6` and
`@better-auth/api-key@1.7.6` packages or the matching upstream tag.

## Workflow

1. Read the relevant phase in [ROADMAP.md](ROADMAP.md)
2. Compare Rust behavior against the TS reference server
3. Implement the smallest self-contained fix that removes the diff
4. Add or update tests in the same change
5. Do not batch unrelated endpoint fixes into one commit

Use any downstream compatibility target only as a downstream signal, not
as the source of truth.

## Docs OpenAPI

The docs site consumes a committed schema artifact at `docs/better-auth.json`.
That file should reflect the Rust runtime, not an upstream TypeScript export.

When the documented v1 route surface changes, regenerate the docs OpenAPI
artifacts with:

```bash
devenv shell -- pnpm --dir docs install --frozen-lockfile
devenv shell -- cargo run --bin generate_docs_openapi --features seaorm2
devenv shell -- pnpm --dir docs exec biome format --write better-auth.json
devenv shell -- bun run --cwd docs scripts/generate-openapi.mts
```

## Testing Strategy

There are three layers:

1. Rust unit/integration tests and the generated public consumer: `cargo test --workspace --features axum,seaorm2,redis-cache` and `./scripts/consumer-check.sh`
2. Raw wire smoke tests:
   `cargo test --test wire_compat_smoke_tests -- --nocapture`
3. Dual-server client compatibility tests using the real
   `better-auth/client` SDK:
   `cargo test --test client_compat_tests phase0_client_compat -- --ignored --nocapture`

The Diesel store has its own conformance suite. It runs on SQLite by
default; set `BETTER_AUTH_DIESEL_POSTGRES_URL` to also run it on
PostgreSQL:
`BETTER_AUTH_DIESEL_POSTGRES_URL=postgres://postgres@localhost/postgres cargo test -p better-auth-diesel`

The client-compat layer is the hard gate and the primary compatibility
contract. For more detail, see
[compat-tests/README.md](compat-tests/README.md).

## Required Checks

Before committing, run the full check:

```bash
devenv test
```

Local checks and CI use `scripts/check.sh`. The script installs locked compatibility dependencies, checks formatting and Clippy, runs workspace tests with Axum, SeaORM, and Redis features, checks the alternative Rustls configuration, builds Rustdoc, and tests a freshly generated schema in an independent consumer. The dual-server suite compares all supported phases against the pinned TypeScript runtime.

For a focused check, run the applicable command through `devenv shell --`:

```bash
devenv shell -- cargo fmt --all -- --check
devenv shell -- cargo clippy --workspace --locked -- -D warnings
devenv shell -- cargo clippy --workspace --locked --features axum,seaorm2,redis-cache -- -D warnings
devenv shell -- cargo test --workspace --locked --features axum,seaorm2,redis-cache
devenv shell -- ./scripts/consumer-check.sh
devenv shell -- cargo test --test client_compat_tests phase5_client_compat -- --ignored --nocapture
```
