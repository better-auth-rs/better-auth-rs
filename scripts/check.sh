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
    consumer)
      cargo clippy --locked -p better-auth-core -p better-auth-cli -p better-auth-seaorm-macros -p better-auth-seaorm -- -D warnings
      cargo test --locked -p better-auth-core optional_runtime_fields_preserve_absence_then_explicit_null
      cargo test --locked -p better-auth-cli -p better-auth-seaorm-macros
      cargo test --locked --features axum,seaorm2,redis-cache --test session_additional_fields_tests --test wallet_additional_fields_tests
      ./scripts/consumer-check.sh
      ;;
    fullstack) cargo check --locked --manifest-path examples/fullstack/backend/Cargo.toml ;;
    quick-start) bun scripts/quick-start-check.ts ;;
    alignment) ./scripts/alignment-check.sh --skip-build ;;
    client-configuration)
      cargo test --locked --test client_compat_tests -- \
        --ignored --nocapture --exact --test-threads=1 configuration_client_compat
      ;;
    plugin-fields)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm -- -D warnings
      cargo clippy --locked --features axum,seaorm2,redis-cache --test plugin_output_capabilities_tests --test api_key_additional_fields_tests -- -D warnings
      cargo test --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm --lib -- api_key jwt
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test api_key_additional_fields_tests --test passkey_additional_fields_tests \
        --test two_factor_additional_fields_tests --test device_additional_fields_tests \
        --test jwk_additional_fields_tests --test wallet_additional_fields_tests \
        --test plugin_output_capabilities_tests --test sql_user_extra_output_tests \
        --test api_key_metadata_tests --test api_key_metadata_timing_tests --test jwt_transaction_tests
      cargo test --locked --features axum,seaorm2,redis-cache --test plugin_model_fields_tests -- api_key:: api_key_cache:: device_ownership::
      bun --no-install test \
        ./compat-tests/reference-server/contracts/api-key-field-policies.test.ts \
        ./compat-tests/reference-server/contracts/api-key-fields.test.ts \
        ./compat-tests/reference-server/contracts/api-key-live-fields.test.ts \
        ./compat-tests/reference-server/contracts/plugin-output-capabilities.test.ts \
        ./compat-tests/reference-server/contracts/api-key-expiration.test.ts \
        ./compat-tests/reference-server/contracts/api-key-cache-sort.test.ts \
        ./compat-tests/reference-server/contracts/api-key-cache-batch.test.ts \
        ./compat-tests/reference-server/api-key-metadata.test.ts \
        ./compat-tests/reference-server/api-key-metadata-pages.test.ts
      ;;
    schema-joins)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-core -p better-auth-seaorm -- -D warnings
      cargo clippy --locked --features axum,seaorm2,redis-cache --test schema_join_reference_tests --test schema_join_reference_conflict_tests -- -D warnings
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test schema_join_reference_tests --test join_binding_tests \
        --test schema_join_reference_conflict_tests --test schema_preflight_tests \
        --test fallback_join_tests --test native_core_join_tests \
        --test native_memory_join_tests --test account_owner_batch_tests
      bun --no-install test ./compat-tests/reference-server/contracts/schema-join-reference.test.ts ./compat-tests/reference-server/contracts/schema-join-reference-conflict.test.ts
      ;;
    passkey)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm -- -D warnings
      cargo test --locked -p better-auth-core -p better-auth-api --lib passkey
      cargo test --locked --features axum,seaorm2,redis-cache --test plugin_model_fields_tests --test plugin_list_limits_tests --test compat_passkey_tests --test passkey_additional_fields_tests --test two_factor_additional_fields_tests
      bun --no-install test \
        ./compat-tests/reference-server/contracts/passkey-aaguid-fields.test.ts \
        ./compat-tests/reference-server/contracts/passkey-live-fields.test.ts \
        ./compat-tests/reference-server/contracts/passkey-fields.test.ts
      COMPAT_TEST_PROFILE=native-passkey cargo test --locked --test client_compat_tests -- \
        --ignored --nocapture --exact --test-threads=1 phase8_client_compat configuration_client_compat
      ;;
    two-factor)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm -- -D warnings
      cargo test --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm --lib two_factor
      cargo test --locked --features axum,seaorm2,redis-cache --test observability_tests --test two_factor_cookie_duration_tests --test two_factor_additional_fields_tests
      bun --no-install test ./compat-tests/reference-server/contracts/two-factor-fields.test.ts
      COMPAT_TEST_PROFILE=native-two-factor cargo test --locked --test client_compat_tests -- \
        --ignored --nocapture --exact --test-threads=1 phase11_client_compat phase12_client_compat configuration_client_compat
      ;;
    device-validation)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-core -p better-auth-api -- -D warnings
      cargo test --locked -p better-auth-core -p better-auth-api --lib -- \
        plugin::tests::async_body_dispatch:: \
        openapi::tests:: \
        plugins::device_authorization::tests:: \
        plugins::two_factor::tests::
      cargo test --locked --test device_request_validation_tests --test device_grant_tests \
        --test device_grant_metadata_tests --test device_request_schema_tests \
        --test openapi_property_order_tests --test openapi_endpoint_key_order_tests \
        --test openapi_rate_limit_model_tests \
        --test device_issuance_tests --test native_endpoint_tests
      cargo test --locked --features axum,seaorm2,redis-cache --test plugin_model_fields_tests -- device_redemption:: device_ownership::
      bun --no-install test \
        ./compat-tests/reference-server/contracts/device-request-validation.test.ts \
        ./compat-tests/reference-server/contracts/device-grant.test.ts \
        ./compat-tests/reference-server/contracts/device-grant-metadata.test.ts \
        ./compat-tests/reference-server/contracts/device-request-schema.test.ts \
        ./compat-tests/reference-server/contracts/device-ownership.test.ts \
        ./compat-tests/reference-server/contracts/openapi-property-order.test.ts \
        ./compat-tests/reference-server/contracts/openapi-endpoint-key-order.test.ts \
        ./compat-tests/reference-server/contracts/openapi-rate-limit-model.test.ts \
        ./compat-tests/reference-server/contracts/device-issuance.test.ts
      ;;
    provider-options)
      cargo clippy --locked -p better-auth-api --features axum -- -D warnings
      cargo test --locked -p better-auth-api --features axum --lib -- \
        plugins::oauth::google_client_ids_tests:: \
        plugins::oauth::verifier_context_tests:: \
        plugins::oauth::gitlab_issuer_tests:: \
        plugins::oauth::microsoft_tests:: \
        plugins::oauth::apple_tests:: \
        plugins::oauth::apple_flow_tests:: \
        plugins::oauth::tiktok_tests:: \
        plugins::oauth::providers::twitch::tests:: \
        plugins::oauth::signin::override_tests:: \
        plugins::oauth::generic_profile::result_tests::
      cargo test --locked -p better-auth-api --features axum \
        --test account_oauth_tests --test oauth_session_revocation_tests
      cargo test --locked --test social_refresh_context_tests
      cargo test --locked --test telemetry_options_tests
      cargo check --locked --manifest-path compat-tests/rust-server/Cargo.toml
      bun --no-install test \
        ./compat-tests/reference-server/contracts/google-client-ids.test.ts \
        ./compat-tests/reference-server/contracts/gitlab-issuer.test.ts \
        ./compat-tests/reference-server/contracts/social-microsoft.test.ts \
        ./compat-tests/reference-server/contracts/apple.test.ts \
        ./compat-tests/reference-server/contracts/tiktok.test.ts \
        ./compat-tests/reference-server/contracts/twitch-provider.test.ts \
        ./compat-tests/reference-server/contracts/oauth-profile-override.test.ts \
        ./compat-tests/reference-server/contracts/social-refresh-context.test.ts \
        ./compat-tests/reference-server/contracts/social-verifier-context.test.ts \
        ./compat-tests/reference-server/contracts/telemetry-options.test.ts \
        ./compat-tests/reference-server/contracts/generic-profile-results.test.ts
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
