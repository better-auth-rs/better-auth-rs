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
integrations we support (Axum, sqlx), but those integrations are not
themselves the compatibility contract.

## Source of Truth

When sources disagree, trust them in this order:

1. Runtime behavior of the TypeScript reference server in
   `compat-tests/reference-server/`
2. TypeScript source in a local checkout of
   https://github.com/better-auth/better-auth, when available
3. Generated upstream OpenAPI profiles from the pinned published package
4. Better Auth documentation

The pinned reference version is `better-auth@1.4.19` (see
`compat-tests/reference-server/package.json`).

## Non-Negotiables

- No extra public route, wire behavior, or client-observable capability
  beyond upstream TS
- No missing upstream route or behavior
- No legacy Rust-only migration shims or compatibility paths
- Rust-native integration APIs are allowed when they preserve the same
  client-observable contract
- If TS looks buggy, match it anyway and document that choice in code

## Before You Change Code

Install the TypeScript reference server used by the compatibility
harness:

```bash
cd compat-tests/reference-server && npm install
```

A local checkout of https://github.com/better-auth/better-auth is
useful for inspecting upstream source and runtime behavior.

## Workflow

1. Read the relevant phase in [ROADMAP.md](ROADMAP.md)
2. Compare Rust behavior against the TS reference server
3. Implement the smallest self-contained fix that removes the diff
4. Add or update tests in the same change
5. Do not batch unrelated endpoint fixes into one commit

## Testing Strategy

1. Rust unit tests: `cargo test --workspace --lib`
2. Integration and compatibility tests against the pinned TS reference
   server: `cargo test --workspace --tests`. See
   [compat-tests/README.md](compat-tests/README.md) for how the
   dual-server harness is wired.

Compatibility coverage against the TypeScript reference server is the
hard gate — endpoint behavior must match upstream.

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
