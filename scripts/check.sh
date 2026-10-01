#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
bun install --cwd compat-tests/reference-server --frozen-lockfile
bun install --cwd compat-tests/client-tests --frozen-lockfile
cargo fmt --all -- --check
cargo clippy --workspace --locked -- -D warnings
cargo clippy --workspace --locked --features axum,seaorm2,redis-cache -- -D warnings
cargo test --workspace --locked --features axum,seaorm2,redis-cache --no-fail-fast
cargo check -p better-auth --locked --no-default-features --features rustls,axum,seaorm2,redis-cache
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps --features axum,seaorm2,redis-cache
./scripts/consumer-check.sh
cargo check --locked --manifest-path examples/fullstack/backend/Cargo.toml
bun scripts/quick-start-check.ts
./scripts/alignment-check.sh
