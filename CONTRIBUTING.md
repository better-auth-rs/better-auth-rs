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
2. TypeScript source in a local checkout of `better-auth@1.4.19` when
   available
3. Generated upstream OpenAPI profiles from the pinned published package
4. Better Auth documentation

The pinned reference version is `better-auth@1.4.19`.

## Non-Negotiables

- No extra public route, wire behavior, or client-observable capability
  beyond upstream TS
- No missing upstream route or behavior
- No legacy Rust-only migration shims or compatibility paths
- Rust-native integration APIs are allowed when they preserve the same
  client-observable contract
- If TS looks buggy, match it anyway and document that choice in code

## Before You Change Code

Install the Bun workspaces used by the compatibility harness:

```bash
cd compat-tests/reference-server && bun install
cd ../client-tests && bun install
```

You should have a local checkout of `better-auth@1.4.19` to inspect
upstream behavior and source.

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
cargo run --bin generate_docs_openapi --features seaorm2
cd docs && bun scripts/generate-openapi.mts
```

## Testing Strategy

There are three layers:

1. Rust unit/integration tests: `cargo test --workspace --lib`
2. Raw wire smoke tests:
   `cargo test --test wire_compat_smoke_tests -- --nocapture`
3. Dual-server client compatibility tests using the real
   `better-auth/client` SDK:
   `cargo test --test client_compat_tests phase0_client_compat -- --ignored --nocapture`

The client-compat layer is the hard gate and the primary compatibility
contract. For more detail, see
[compat-tests/README.md](compat-tests/README.md).

## Required Checks

Before committing, these must pass:

```bash
cargo fmt --check
cargo clippy --workspace
cargo clippy --workspace --features axum
cargo test --workspace --lib
```

Then run the phase-appropriate compatibility checks for the behavior you
changed.
