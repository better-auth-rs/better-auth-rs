#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
bun install --cwd compat-tests/reference-server --frozen-lockfile
bun install --cwd compat-tests/client-tests --frozen-lockfile
cargo fmt --all -- --check
cargo clippy --workspace --locked -- -D warnings
cargo clippy --workspace --locked --features axum,seaorm2,redis-cache,diesel-postgres,diesel-sqlite -- -D warnings
cargo clippy -p better-auth-diesel --all-targets --locked --no-default-features --features postgres -- -D warnings
cargo clippy -p better-auth-diesel --all-targets --locked --no-default-features --features sqlite -- -D warnings
cargo test --workspace --locked --features axum,seaorm2,redis-cache
cargo check -p better-auth --locked --no-default-features --features rustls,axum,seaorm2,redis-cache
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps --features axum,seaorm2,redis-cache,diesel-postgres,diesel-sqlite
./scripts/consumer-check.sh
bun scripts/quick-start-check.ts
./scripts/alignment-check.sh
