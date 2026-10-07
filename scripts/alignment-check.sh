#!/usr/bin/env bash
set -euo pipefail

skip_build=false
reference_only=false

for arg in "$@"; do
  case "$arg" in
    --skip-build) skip_build=true ;;
    --reference-only) reference_only=true ;;
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

if [[ "$reference_only" != "true" && "$skip_build" != "true" ]]; then
  cargo build --locked --workspace
fi

if [[ "$reference_only" != "true" ]]; then
  cargo test --locked --features axum --test axum_integration_tests
  cargo test --locked \
    --test compat_endpoint_tests \
    --test compat_coverage_tests \
    --test wire_compat_smoke_tests -- --nocapture
  cargo test --locked --features seaorm2 --test transform_order_oracle
fi
bun test ./compat-tests/reference-server/contracts ./tests/fixtures/fallback-joins-upstream.test.ts ./tests/fixtures/organization-lists-upstream.test.ts ./tests/fixtures/organization-native-teams-upstream.test.ts ./tests/fixtures/organization-async-upstream.test.ts ./tests/fixtures/organization-join-continuation-upstream.test.ts ./tests/fixtures/account-owner-multiple-fields-upstream.test.ts ./tests/fixtures/fallback-continuation-upstream.test.ts ./tests/fixtures/organization-native-joins-upstream.test.ts ./tests/fixtures/organization-fallback-parent-upstream.test.ts ./tests/fixtures/organization-invitation-presence-upstream.test.ts
bun test ./compat-tests/client-tests/support
# One test process reuses the compat server build through the existing OnceLock.
if [[ "$reference_only" != "true" ]]; then
  cargo test --locked --test client_compat_tests -- \
    --ignored --nocapture --exact --test-threads=1 \
    parallel_server_startup full_client_compat configuration_client_compat
fi
