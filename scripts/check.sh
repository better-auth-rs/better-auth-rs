#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if (( $# > 1 )); then
  echo "Usage: $0 [stage]" >&2
  exit 1
fi

run_stage() {
  echo "Running check stage: $1"
  case "$1" in
    dependencies)
      bun install --cwd compat-tests/reference-server --frozen-lockfile
      bun install --cwd compat-tests/client-tests --frozen-lockfile
      ;;
    format) cargo fmt --all -- --check ;;
    lint-default) cargo clippy --workspace --locked -- -D warnings ;;
    lint-features) cargo clippy --workspace --locked --features axum,seaorm2,redis-cache -- -D warnings ;;
    workspace-tests) cargo test --workspace --locked --features axum,seaorm2,redis-cache --no-fail-fast ;;
    rustls) cargo check -p better-auth --locked --no-default-features --features rustls,axum,seaorm2,redis-cache ;;
    rustdoc) RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps --features axum,seaorm2,redis-cache ;;
    consumer) ./scripts/consumer-check.sh ;;
    fullstack) cargo check --locked --manifest-path examples/fullstack/backend/Cargo.toml ;;
    quick-start) bun scripts/quick-start-check.ts ;;
    alignment) ./scripts/alignment-check.sh --skip-build ;;
    client-configuration)
      cargo test --locked --test client_compat_tests -- \
        --ignored --nocapture --exact --test-threads=1 configuration_client_compat
      ;;
    *) echo "Unknown check stage: $1" >&2; exit 1 ;;
  esac
}

if [[ "${1:-all}" == "all" ]]; then
  for stage in dependencies format lint-default lint-features workspace-tests rustls rustdoc consumer fullstack quick-start alignment; do
    run_stage "$stage"
  done
else
  run_stage "$1"
fi
