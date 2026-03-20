# Compatibility Testing Framework

This directory contains the portable compatibility infrastructure for
validating `better-auth-rs` against the canonical TypeScript Better Auth
runtime.

## Model

The compatibility system now has two layers:

1. **Client-first Bun scenarios** — the primary gate. These use the real
   `better-auth/client` SDK and run each scenario against both the TS
   reference server and the Rust compat server.
2. **Thin raw wire smoke tests** — a small retained Rust suite for
   cookie/header/null-session transport behavior and other cases the
   client layer cannot prove well on its own.

Client drift is a hard failure. Raw response-shape drift is best-effort
unless it is client-visible or otherwise clearly consumer-relevant.

## Components

### `compat-tests/reference-server/`

Portable Bun-native TypeScript reference server.

- Runtime: Bun
- Database: `bun:sqlite`
- Better Auth version: published `better-auth@1.4.19`
- Test controls: reset state, reset-password token seeding, sender mode,
  OAuth account seeding, OAuth refresh mode

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
```

### `compat-tests/rust-server/`

Minimal Axum server matching the reference server config exactly.

## Primary commands

Cargo-native orchestration:

```bash
cargo test --test client_compat_tests phase0_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase1_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests phase2_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests full_client_compat -- --ignored --nocapture
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
bash compat-tests/client-tests/run-against-both.sh all
```
