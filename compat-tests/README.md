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
