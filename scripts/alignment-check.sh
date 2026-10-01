#!/usr/bin/env bash
set -euo pipefail

skip_build=false

for arg in "$@"; do
  case "$arg" in
    --skip-build) skip_build=true ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

if ! command -v bun >/dev/null 2>&1; then
  echo "bun is required for alignment checks. Install Bun first." >&2
  exit 1
fi

if [[ ! -d compat-tests/reference-server/node_modules ]]; then
  echo "compat-tests/reference-server dependencies are missing. Run 'cd compat-tests/reference-server && bun install'." >&2
  exit 1
fi

if [[ ! -d compat-tests/client-tests/node_modules ]]; then
  echo "compat-tests/client-tests dependencies are missing. Run 'cd compat-tests/client-tests && bun install'." >&2
  exit 1
fi

if [[ "$skip_build" != "true" ]]; then
  cargo build --locked --workspace
  cargo build --locked --manifest-path compat-tests/rust-server/Cargo.toml
fi

cargo test --locked --features axum --test axum_integration_tests
cargo test --locked --test compat_endpoint_tests -- --nocapture
cargo test --locked --test compat_coverage_tests -- --nocapture
cargo test --locked --test wire_compat_smoke_tests -- --nocapture
bun test compat-tests/reference-server/contracts
bun test compat-tests/client-tests/support
cargo test --locked --test client_compat_tests full_client_compat -- --ignored --nocapture
cargo test --locked --test client_compat_tests configuration_client_compat -- --ignored --nocapture
