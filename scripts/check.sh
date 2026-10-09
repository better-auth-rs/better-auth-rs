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
    workspace-tests)
      cargo build --workspace --locked --tests --profile test --features axum,seaorm2,redis-cache --keep-going
      cargo test --workspace --locked --features axum,seaorm2,redis-cache --no-fail-fast
      ;;
    rustls) cargo check -p better-auth --locked --no-default-features --features rustls,axum,seaorm2,redis-cache ;;
    rustdoc) RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps --features axum,seaorm2,redis-cache ;;
    consumer)
      cargo clippy --locked -p better-auth-core -p better-auth-cli -p better-auth-seaorm-macros -p better-auth-seaorm -- -D warnings
      cargo test --locked -p better-auth-core optional_runtime_fields_preserve_absence_then_explicit_null
      cargo test --locked -p better-auth-cli -p better-auth-seaorm-macros
      cargo test --locked --features axum,seaorm2,redis-cache --test session_additional_fields_tests --test wallet_additional_fields_tests
      ./scripts/consumer-check.sh
      ;;
    consumer-schema) ./scripts/consumer-check.sh ;;
    fullstack) cargo check --locked --manifest-path examples/fullstack/backend/Cargo.toml ;;
    quick-start) bun scripts/quick-start-check.ts ;;
    alignment) ./scripts/alignment-check.sh --skip-build ;;
    reference-contracts) ./scripts/alignment-check.sh --reference-only ;;
    client-configuration)
      cargo clippy --locked --test client_compat_tests -- -D warnings
      cargo test --locked --test client_compat_tests -- \
        --ignored --nocapture --exact --test-threads=1 configuration_failure_aggregation configuration_client_compat
      ;;
    credential-timing)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-api --lib -- -D warnings
      cargo clippy --locked --features axum,seaorm2,redis-cache --test plugin_model_fields_tests -- -D warnings
      cargo test --locked -p better-auth-api --lib -- \
        plugins::one_time_token::tests:: plugins::device_authorization::tests::
      cargo test --locked --features axum,seaorm2,redis-cache --test plugin_model_fields_tests -- \
        device_redemption:: device_consumption::
      bun --no-install test \
        ./compat-tests/reference-server/contracts/one-time-token-expiry.test.ts \
        ./compat-tests/reference-server/contracts/device-polling.test.ts \
        ./compat-tests/reference-server/contracts/device-redemption.test.ts \
        ./compat-tests/reference-server/contracts/device-interval.test.ts
      ;;
    cookie-attributes)
      cargo fmt --all -- --check
      bun --no-install test \
        ./compat-tests/reference-server/contracts/cookie-attribute-mutation.test.ts \
        ./compat-tests/reference-server/contracts/cookie-partitioned.test.ts \
        ./compat-tests/reference-server/contracts/cookie-http-errors.test.ts \
        ./compat-tests/reference-server/contracts/cookie-expires.test.ts \
        ./compat-tests/reference-server/contracts/cookie-cleanup.test.ts \
        ./compat-tests/reference-server/contracts/cookie-cache-cleanup.test.ts \
        ./compat-tests/reference-server/contracts/cookie-lifetime.test.ts \
        ./compat-tests/reference-server/contracts/cookie-session-precision.test.ts
      cargo clippy --locked -p better-auth-core -p better-auth-api --lib -- -D warnings
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test cookie_attribute_mutation_tests --test cookie_http_errors_tests \
        --test cookie_expires_tests --test cookie_cleanup_tests \
        --test cookie_lifetime_tests --test cookie_session_precision_tests -- -D warnings
      cargo test --locked -p better-auth-core --lib utils::cookie_utils::
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test cookie_attribute_mutation_tests --test cookie_http_errors_tests \
        --test cookie_expires_tests --test cookie_cleanup_tests \
        --test cookie_lifetime_tests --test cookie_session_precision_tests
      ;;
    memory-sorting)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-core --lib -- -D warnings
      cargo test --locked -p better-auth-core --lib -- \
        store::ephemeral::api_keys::tests::sorting:: \
        store::ephemeral::organization::query_tests:: \
        field_value::tests::
      cargo test --locked -p better-auth-api --lib plugins::api_key::tests::list_tests::
      bun --no-install test \
        ./compat-tests/reference-server/contracts/memory-sort.test.ts \
        ./compat-tests/reference-server/contracts/memory-name-coercion.test.ts \
        ./compat-tests/reference-server/contracts/member-sort-stability.test.ts \
        ./compat-tests/reference-server/contracts/api-key-number-sort.test.ts
      ;;
    plugin-display-values)
      cargo fmt --all -- --check
      bun --no-install test \
        ./compat-tests/reference-server/contracts/api-key-number-name.test.ts \
        ./compat-tests/reference-server/contracts/api-key-number-name-order.test.ts \
        ./compat-tests/reference-server/contracts/memory-name-coercion.test.ts \
        ./compat-tests/reference-server/contracts/passkey-shared-display.test.ts
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-cli -p better-auth-seaorm -p better-auth-seaorm-macros -- -D warnings
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test api_key_number_name_tests --test passkey_additional_fields_tests \
        --test plugin_display_json_tests --test plugin_model_fields_tests -- -D warnings
      cargo test --locked -p better-auth-cli -p better-auth-seaorm-macros
      cargo test --locked -p better-auth-core --lib store::ephemeral::api_keys::tests::sorting
      cargo test --locked -p better-auth-api --lib plugins::api_key::
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test api_key_number_name_tests --test passkey_additional_fields_tests \
        --test plugin_display_json_tests --test plugin_model_fields_tests
      ./scripts/consumer-check.sh --test api_key_number_name --test passkey_shared_display
      ;;
    plugin-display-json)
      cargo fmt --all -- --check
      bun --no-install test \
        ./compat-tests/reference-server/contracts/plugin-display-json.test.ts \
        ./compat-tests/reference-server/contracts/plugin-display-presence.test.ts
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-cli -p better-auth-seaorm -p better-auth-seaorm-macros -- -D warnings
      cargo clippy --locked --features axum,seaorm2,redis-cache --test plugin_display_json_tests --test plugin_model_fields_tests --test server_api_tests -- -D warnings
      cargo test --locked -p better-auth-cli plugin_display_field_tests
      cargo test --locked -p better-auth-core --lib -- plugin_display_json_tests factory_tests passkey store::ephemeral::api_keys::tests::
      cargo test --locked -p better-auth-api --lib plugins::api_key::
      cargo test --locked --features axum,seaorm2,redis-cache --test plugin_display_json_tests --test server_api_tests
      cargo test --locked --features axum,seaorm2,redis-cache --test plugin_model_fields_tests passkey_update_ids
      ./scripts/consumer-check.sh --test generated_plugin_catalog plugin_display_json -- --include-ignored
      ;;
    plugin-fields)
      cargo fmt --all -- --check
      # Collect independent failures while retaining a failing stage status.
      local plugin_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/plugin-display-presence.test.ts \
        ./compat-tests/reference-server/contracts/plugin-display-json.test.ts \
        ./compat-tests/reference-server/contracts/api-key-field-policies.test.ts \
        ./compat-tests/reference-server/contracts/api-key-fields.test.ts \
        ./compat-tests/reference-server/contracts/api-key-date-usage.test.ts \
        ./compat-tests/reference-server/consumer-contracts/api-key-date-usage.test.ts \
        ./compat-tests/reference-server/consumer-contracts/mysql-create-readback.test.ts \
        ./compat-tests/reference-server/contracts/native-plugin-replacements.test.ts \
        ./compat-tests/reference-server/contracts/native-atomic-update.test.ts \
        ./compat-tests/reference-server/contracts/passkey-projected-id.test.ts \
        ./compat-tests/reference-server/contracts/device-grant.test.ts \
        ./compat-tests/reference-server/contracts/device-redemption.test.ts \
        ./compat-tests/reference-server/consumer-contracts/device-grant-sql.test.ts \
        ./compat-tests/reference-server/contracts/api-key-name-mapping.test.ts \
        ./compat-tests/reference-server/contracts/api-key-live-fields.test.ts \
        ./compat-tests/reference-server/contracts/plugin-output-capabilities.test.ts \
        ./compat-tests/reference-server/contracts/api-key-expiration.test.ts \
        ./compat-tests/reference-server/contracts/api-key-cache-sort.test.ts \
        ./compat-tests/reference-server/contracts/organization-query-limits.test.ts \
        ./compat-tests/reference-server/contracts/member-json-filter.test.ts \
        ./compat-tests/reference-server/contracts/api-key-cache-batch.test.ts \
        ./compat-tests/reference-server/api-key-metadata.test.ts \
        ./compat-tests/reference-server/api-key-metadata-pages.test.ts || plugin_status=1
      cargo clippy --locked --keep-going -p better-auth-core -p better-auth-api -p better-auth-seaorm -p better-auth-cli -- -D warnings || plugin_status=1
      cargo clippy --locked --keep-going --features axum,seaorm2,redis-cache --test plugin_output_capabilities_tests --test async_field_transform_tests --test api_key_additional_fields_tests --test device_grant_tests --test organization_member_json_filter_reference_tests --test auth_entity_plugin_alias_tests --test plugin_model_fields_tests -- -D warnings || plugin_status=1
      cargo test --locked -p better-auth-cli schema_config || plugin_status=1
      cargo check --locked --manifest-path compat-tests/rust-server/Cargo.toml || plugin_status=1
      for package in better-auth-core better-auth-api better-auth-seaorm; do
        cargo test --locked --no-fail-fast -p "$package" --lib -- api_key passkey device two_factor session_token_delete native_cookie store::session_create::tests:: store::cache::tests:: store::secondary:: utils::date::tests:: id_slot_tests::plugin_credentials query::dynamic_value_tests utils::json::runtime wire::api_key_view::tests:: jwt jwk wallet siwe user_fields::record::tests:: ordinary_object_primitive_conversion_checks_only_the_selected_method member_queries_use_typed_storage_before_output_transforms store::updates:: store::record_bindings::tests:: field_value::serde::tests:: store::value_filter::tests:: schema_value::tests:: || plugin_status=1
      done
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test async_field_transform_tests --test api_key_additional_fields_tests --test passkey_additional_fields_tests \
        --test device_grant_tests --test device_runtime_transaction_tests --test device_where_tests \
        --test device_interval_tests --test device_issuance_tests \
        --test secondary_storage_hooks_tests --test session_create_payload_tests \
        --test session_initial_defaults_tests --test nullable_user_update_tests \
        --test organization_member_json_filter_reference_tests \
        --test two_factor_additional_fields_tests --test totp_period_nan_tests --test observability_tests --test device_additional_fields_tests \
        --test jwk_additional_fields_tests --test wallet_additional_fields_tests \
        --test auth_entity_plugin_alias_tests \
        --test plugin_output_capabilities_tests --test sql_user_extra_output_tests \
        --test api_key_metadata_tests --test api_key_metadata_timing_tests --test jwt_transaction_tests || plugin_status=1
      cargo test --locked --features axum,seaorm2,redis-cache --test plugin_model_fields_tests -- api_key:: api_key_cache:: passkey aaguid:: native_registration:: device_ownership:: device_redemption:: presence:: presence_cache:: core::native_replacements_initialize_while_unsupported_model_roles_fail || plugin_status=1
      ./scripts/consumer-check.sh --test generated_plugin_catalog -- --include-ignored api_key_additional_fields native_plugin_replacements device plugin_display_json || plugin_status=1
      return "$plugin_status"
      ;;
    native-create)
      cargo fmt --all -- --check
      local create_status=0
      cargo clippy --workspace --locked --features axum,seaorm2,redis-cache -- -D warnings || create_status=1
      # Compile all callers once before commands that would repeat the same compilation failure.
      if cargo check --workspace --locked --tests --features axum,seaorm2,redis-cache --keep-going; then
        cargo test --locked --no-fail-fast -p better-auth-core -p better-auth-api -p better-auth-seaorm --lib -- \
          session verification database_hooks lifecycle transaction create_readback user_fields user_query wire:: \
          user_column_defaults user_runtime_input_tests protected_function_tests field_value:: record_bindings::function_tests types_plugin::device::tests \
          user_view_preserves_adapter_order_through_cache_and_visibility \
          plugins::jwt:: plugins::api_key:: plugins::passkey:: plugins::organization:: plugins::test_utils:: \
          plugins::custom_session:: plugins::one_time_token:: plugins::multi_session:: plugins::anonymous:: \
          plugins::user_admission:: \
          plugins::admin:: plugins::email_verification:: plugins::email_password:: plugins::phone_number:: \
          plugins::two_factor:: plugins::user_management:: plugins::oauth:: || create_status=1
        cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
          --test database_hooks_tests --test database_lifecycle_tests --test database_hook_updates_tests \
          --test session_create_payload_tests --test session_initial_defaults_tests --test session_id_policy_tests \
          --test custom_session_fields_tests --test secondary_storage_hooks_tests \
          --test transaction_effect_order_tests --test transaction_hook_context_tests \
          --test organization_native_team_tests --test organization_query_limits_tests \
          --test test_utils_tests --test legacy_schema_integration_tests \
          --test user_runtime_output_tests --test user_runtime_cache_tests \
          --test user_runtime_input_tests --test user_account_raw_column_tests \
          --test user_input_policy_tests --test protected_function_tests \
          --test user_verification_fields_tests --test user_record_values_tests \
          --test account_owner_batch_tests --test account_identity_tests --test account_native_selector_tests \
          --test account_user_selected_relations_reference_tests \
          --test native_core_join_tests --test native_memory_join_tests --test session_user_join_reference_tests \
          --test memory_user_live_reads_tests --test api_key_number_name_tests \
          --test plugin_display_json_tests --test plugin_model_fields_tests \
          --test nullable_user_update_tests --test sql_user_string_output_tests --test sql_user_extra_output_tests \
          --test username_runtime_tests --test email_normalization_tests --test user_native_delete_tests \
          --test email_verification_duration_tests --test email_verification_payload_tests \
          --test lifecycle_notification_tests || create_status=1
        cargo test --locked --features axum,seaorm2,redis-cache --test mysql_create_readback_tests -- --ignored || create_status=1
        cargo test --locked --features axum,seaorm2,redis-cache --test user_account_raw_column_tests -- --ignored || create_status=1
        cargo test --locked -p better-auth-cli --test generate || create_status=1
        ./scripts/consumer-check.sh --lib --test session_native_values --test user_session_fields || create_status=1
        if cargo build --locked --manifest-path compat-tests/rust-server/Cargo.toml; then
          COMPAT_TEST_PROFILE=passkey-first,passkey-options,email-otp,email-otp-options,magic-link,signup-verification,admin-options,crypto-database,crypto-cookie,identity-context \
            cargo test --locked --test client_compat_tests -- --ignored --nocapture --exact --test-threads=1 \
            configuration_client_compat phase1_client_compat phase2_client_compat phase3_client_compat || create_status=1
        else
          create_status=1
        fi
      else
        create_status=1
      fi
      bun --no-install test ./compat-tests/reference-server/consumer-contracts/mysql-create-readback.test.ts || create_status=1
      bun --no-install test ./compat-tests/reference-server/contracts/user-runtime-output.test.ts \
        ./compat-tests/reference-server/contracts/user-runtime-cache.test.ts \
        ./compat-tests/reference-server/contracts/user-runtime-input.test.ts \
        ./compat-tests/reference-server/contracts/user-admission-input.test.ts \
        ./compat-tests/reference-server/contracts/user-input-policy.test.ts \
        ./compat-tests/reference-server/contracts/phone-signup-input.test.ts \
        ./compat-tests/reference-server/contracts/protected-function.test.ts \
        ./compat-tests/reference-server/contracts/protected-function-server.test.ts \
        ./compat-tests/reference-server/contracts/user-verification-cleanup.test.ts \
        ./compat-tests/reference-server/contracts/user-synthetic-output.test.ts \
        ./compat-tests/reference-server/contracts/api-key-actor-reference.test.ts \
        ./compat-tests/reference-server/contracts/api-key-create-gate.test.ts \
        ./compat-tests/reference-server/contracts/api-key-permissions-input.test.ts \
        ./compat-tests/reference-server/contracts/passkey-user-id.test.ts \
        ./compat-tests/reference-server/contracts/user-account-raw-column.test.ts \
        ./compat-tests/reference-server/contracts/account-owner-batch.test.ts \
        ./compat-tests/reference-server/contracts/account-duplicates.test.ts \
        ./compat-tests/reference-server/contracts/account-user-selected-relations.test.ts \
        ./compat-tests/reference-server/contracts/native-core-joins.test.ts \
        ./compat-tests/reference-server/contracts/memory-user-live-reads.test.ts \
        ./compat-tests/reference-server/contracts/sql-user-string-output.test.ts \
        ./compat-tests/reference-server/contracts/sql-user-extra-output.test.ts || create_status=1
      return "$create_status"
      ;;
    api-key-cache)
      cargo fmt --all -- --check
      local cache_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/api-key-cache-batch.test.ts \
        ./compat-tests/reference-server/contracts/api-key-cache-sort.test.ts || cache_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api --lib -- -D warnings || cache_status=1
      cargo test --locked -p better-auth-core --lib -- \
        utils::json::runtime:: field_value:: schema_value:: wire::api_key_view::tests:: || cache_status=1
      cargo test --locked -p better-auth-api --lib -- \
        plugins::api_key:: plugins::jwt:: || cache_status=1
      return "$cache_status"
      ;;
    runtime-values)
      bun --no-install test \
        ./compat-tests/reference-server/contracts/plugin-display-presence.test.ts \
        ./compat-tests/reference-server/contracts/account-verification-serial-primary.test.ts \
        ./compat-tests/reference-server/contracts/session-live-output.test.ts \
        ./compat-tests/reference-server/contracts/adapter-id-slot.test.ts
      cargo clippy --locked --keep-going --features axum,seaorm2,redis-cache \
        --test custom_session_fields_tests --test organization_native_fields_tests \
        --test device_runtime_transaction_tests --test device_where_tests \
        --test auth_entity_extra_fields_tests --test legacy_schema_integration_tests \
        --test plugin_model_fields_tests --test user_record_values_tests \
        --test organization_additional_fields_tests --test plugin_runtime_tests \
        --example postgres_usage -- -D warnings
      cargo test --locked -p better-auth-core --lib -- field_value:: \
        id_slot \
        store::ephemeral::serial_primary_tests:: \
        store::ephemeral::api_keys::tests:: store::ephemeral::two_factor::tests:: \
        store::ephemeral::sessions::live_output_tests:: \
        store::ephemeral::invitation_accept::tests:: \
        store::ephemeral::fields::builtin_policies_transform_typed_records_once_and_preserve_adapter_id \
        types::tests::nullable_user_updates_preserve_omission_null_and_values
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test custom_session_fields_tests --test organization_native_fields_tests \
        --test device_runtime_transaction_tests --test native_endpoint_tests --test test_utils_tests \
        --test architecture_guard_tests --test auth_entity_extra_fields_tests \
        --test legacy_schema_integration_tests --test plugin_model_fields_tests \
        --test user_record_values_tests --test organization_additional_fields_tests \
        --test plugin_runtime_tests --test user_id_generation_order_tests
      cargo test --locked --features axum,seaorm2,redis-cache --test device_where_tests -- \
        --exact memory_device_where_matches_upstream_rows_callbacks_and_consumption
      ;;
    serial-primary)
      bun --no-install test \
        ./compat-tests/reference-server/contracts/user-serial-create-order.test.ts \
        ./compat-tests/reference-server/contracts/account-verification-serial-primary.test.ts \
        ./compat-tests/reference-server/contracts/session-jwk-wallet-rate-limit-serial.test.ts
      cargo clippy --locked -p better-auth-core -- -D warnings
      cargo test --locked -p better-auth-core --lib -- \
        store::ephemeral::serial_primary_tests:: store::ephemeral::user_serial_tests:: \
        store::ephemeral::rows::tests:: store::ephemeral::sessions::live_output_tests:: \
        store::ephemeral::invitation_accept::tests::
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test memory_serial_reference_tests --test organization_serial_reference_tests \
        --test native_core_join_tests --test native_memory_join_tests \
        --test jwt_transaction_tests --test session_additional_fields_tests \
        --test jwk_additional_fields_tests --test wallet_additional_fields_tests \
        --test rate_limit_database_tests
      ;;
    user-fields)
      cargo fmt --all -- --check
      bun --no-install test \
        ./compat-tests/reference-server/contracts/user-id-generation-order.test.ts \
        ./compat-tests/reference-server/contracts/user-serial-create-order.test.ts \
        ./compat-tests/reference-server/contracts/account-verification-serial-primary.test.ts \
        ./compat-tests/reference-server/contracts/adapter-id-slot.test.ts \
        ./compat-tests/reference-server/contracts/adapter-id-coercion.test.ts \
        ./compat-tests/reference-server/contracts/session-defaults.test.ts \
        ./compat-tests/reference-server/contracts/session-create-payload.test.ts \
        ./compat-tests/reference-server/contracts/memory-transaction-values.test.ts \
        ./compat-tests/reference-server/contracts/async-field-transforms.test.ts \
        ./compat-tests/reference-server/contracts/sql-user-extra-output.test.ts \
        ./compat-tests/reference-server/contracts/user-sort-field.test.ts
      cargo clippy --locked --keep-going -p better-auth-core -p better-auth-seaorm -- -D warnings
      cargo check --locked --manifest-path compat-tests/rust-server/Cargo.toml
      cargo clippy --locked --keep-going --features axum,seaorm2,redis-cache \
        --test user_id_generation_order_tests --test plugin_id_slot_tests --test session_id_policy_tests \
        --test join_binding_tests \
        --test session_initial_defaults_tests --test session_create_payload_tests --test legacy_schema_integration_tests \
        --test background_transaction_tests --test email_otp_override_transaction_tests \
        --test email_otp_scheduled_override_tests --test secondary_storage_hooks_tests \
        --test test_utils_tests -- -D warnings
      cargo test --locked --no-fail-fast -p better-auth-core -p better-auth-seaorm --lib -- user_fields:: reference_id::tests:: schema_history field_value:: id_slot store::ephemeral::user_serial_tests:: store::ephemeral::serial_primary_tests:: store::ephemeral::rows::tests:: store::ephemeral::sessions::live_output_tests:: session::view::tests::
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test user_id_generation_order_tests --test user_record_values_tests \
        --test async_field_transform_tests --test sql_user_extra_output_tests \
        --test user_sort_field_tests --test schema_join_reference_tests \
        --test memory_serial_reference_tests --test organization_serial_reference_tests \
        --test fallback_join_tests --test native_core_join_tests --test plugin_id_slot_tests \
        --test join_binding_tests \
        --test native_memory_join_tests --test account_owner_batch_tests --test session_id_policy_tests \
        --test session_initial_defaults_tests --test session_create_payload_tests \
        --test background_transaction_tests --test email_otp_override_transaction_tests \
        --test email_otp_scheduled_override_tests --test secondary_storage_hooks_tests --test test_utils_tests
      cargo test --locked --features axum,seaorm2,redis-cache --test session_id_policy_tests -- --ignored
      cargo test --locked --features axum,seaorm2,redis-cache --test legacy_schema_integration_tests -- serial_session_update_ids_reach_the_numeric_column_after_conversion legacy_numeric_session_rejects_invalid_user_id_before_constructor
      ./scripts/consumer-check.sh --test user_session_fields
      ;;
    secondary-user-refresh)
      cargo fmt --all -- --check
      bun --no-install test \
        ./compat-tests/reference-server/contracts/secondary-user-refresh.test.ts \
        ./compat-tests/reference-server/contracts/secondary-user-refresh-values.test.ts
      cargo clippy --locked -p better-auth-core -p better-auth-seaorm -- -D warnings
      cargo clippy --locked --features axum,seaorm2,redis-cache --test nullable_user_update_tests --test secondary_storage_hooks_tests --test background_transaction_tests -- -D warnings
      cargo test --locked -p better-auth-core --lib store::secondary::users::tests::
      cargo test --locked --features axum,seaorm2,redis-cache --test nullable_user_update_tests --test secondary_storage_hooks_tests --test background_transaction_tests
      ;;
    email-verification)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-api --lib -- -D warnings
      cargo clippy --locked --features seaorm2 \
        --test email_verification_duration_tests --test email_verification_payload_tests -- -D warnings
      cargo test --locked -p better-auth-api --lib -- plugins::email_verification plugins::user_management::tests::test_change_email
      cargo test --locked --features seaorm2 \
        --test email_verification_duration_tests --test email_verification_payload_tests
      bun --no-install test \
        ./compat-tests/reference-server/contracts/email-verification-duration.test.ts \
        ./compat-tests/reference-server/contracts/email-verification-payload.test.ts
      ;;
    telemetry)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-core --lib -- -D warnings
      cargo clippy --locked --test telemetry_options_tests --test telemetry_environment_tests -- -D warnings
      cargo test --locked -p better-auth-core --lib observability::telemetry::
      cargo test --locked --test telemetry_options_tests --test telemetry_environment_tests
      bun --no-install test ./compat-tests/reference-server/contracts/telemetry-*.test.ts
      ;;
    account-user-auth)
      cargo fmt --all -- --check
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test account_user_auth_boundary_reference_tests --test compat_consistency_tests \
        --test wire_compat_smoke_tests --test two_factor_cookie_duration_tests \
        --test plugin_model_fields_tests --test session_create_payload_tests \
        --test session_user_join_reference_tests --test custom_model_join_reference_tests \
        --test secondary_storage_hooks_tests --test background_transaction_tests \
        --test missing_user_transaction_tests -- -D warnings
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test account_user_auth_boundary_reference_tests --test compat_consistency_tests \
        --test wire_compat_smoke_tests --test two_factor_cookie_duration_tests \
        --test plugin_model_fields_tests --test session_create_payload_tests \
        --test session_user_join_reference_tests --test custom_model_join_reference_tests \
        --test secondary_storage_hooks_tests --test background_transaction_tests \
        --test missing_user_transaction_tests
      cargo test --locked -p better-auth-api --lib plugins::two_factor::
      cargo test --locked -p better-auth-core --lib -- plugin_runtime::fields::models::tests:: session::native::tests:: store::ephemeral::user_serial_tests:: store::ephemeral::sessions::live_output_tests:: store::ephemeral::id_slot_tests::sessions::
      bun --no-install test \
        ./compat-tests/reference-server/contracts/account-user-auth-boundary.test.ts \
        ./compat-tests/reference-server/contracts/account-user-auth-email.test.ts \
        ./compat-tests/reference-server/contracts/account-user-auth-secondary.test.ts \
        ./compat-tests/reference-server/contracts/session-user-join-reference.test.ts \
        ./compat-tests/reference-server/contracts/custom-model-join-reference.test.ts \
        ./compat-tests/reference-server/contracts/adapter-id-slot.test.ts
      ;;
    field-projection)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-core -- -D warnings
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test schema_preflight_tests --test async_field_transform_tests \
        --test transform_batch_tests --test account_owner_batch_tests \
        --test fallback_continuation_tests --test organization_join_continuation_tests
      cargo test --locked --features axum,seaorm2,redis-cache --test schema_preflight_tests -- \
        --ignored --exact mysql::live_mysql_preflight_tracks_migrations_defaults_and_auto_increment \
        live_postgres_preflight_tracks_migrations_defaults_and_search_path
      ;;
    schema-joins)
      cargo fmt --all -- --check
      cargo clippy --locked --keep-going -p better-auth-core -p better-auth-api -p better-auth-seaorm -- -D warnings
      cargo clippy --locked --keep-going --features axum,seaorm2,redis-cache --test schema_join_reference_tests --test account_user_selected_relations_reference_tests --test account_user_auth_boundary_reference_tests --test account_user_signin_snapshot_tests --test nullable_user_update_tests --test cookie_cleanup_tests --test cookie_expires_tests --test cookie_http_errors_tests --test schema_join_reference_conflict_tests --test organization_member_join_reference_tests --test organization_native_join_tests --test organization_serial_reference_tests -- -D warnings
      cargo test --locked --no-fail-fast -p better-auth-core -p better-auth-seaorm --lib -- store::joins:: store::ephemeral::user_serial_tests:: schema_history session::native::tests:: session::cookie_cache:: utils::cookie_utils::
      cargo test --locked --no-fail-fast -p better-auth-api --lib -- plugins::helpers::session_tests:: plugins::jwt::tests:: plugins::oauth::signin::
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test schema_join_reference_tests --test join_binding_tests \
        --test account_user_selected_relations_reference_tests --test account_user_auth_boundary_reference_tests --test account_user_signin_snapshot_tests \
        --test nullable_user_update_tests --test database_hook_updates_tests --test missing_user_transaction_tests \
        --test cookie_cleanup_tests --test cookie_expires_tests --test cookie_http_errors_tests \
        --test schema_join_reference_conflict_tests --test schema_preflight_tests \
        --test organization_member_join_reference_tests \
        --test organization_native_join_tests --test organization_serial_reference_tests \
        --test fallback_join_tests --test native_core_join_tests \
        --test native_memory_join_tests --test account_owner_batch_tests
      cargo test --locked --features axum,seaorm2,redis-cache --test organization_native_join_tests -- \
        --ignored --exact postgres::live_postgres_full_organization_joins_decode_all_typed_children
      bun --no-install test \
        ./compat-tests/reference-server/contracts/schema-join-reference.test.ts \
        ./compat-tests/reference-server/contracts/schema-join-reference-conflict.test.ts \
        ./compat-tests/reference-server/contracts/schema-join-reference-unknown.test.ts \
        ./compat-tests/reference-server/contracts/schema-join-reference-field.test.ts \
        ./compat-tests/reference-server/contracts/schema-join-reference-history.test.ts \
        ./compat-tests/reference-server/contracts/account-user-selected-relations.test.ts \
        ./compat-tests/reference-server/contracts/account-user-auth-boundary.test.ts \
        ./compat-tests/reference-server/contracts/account-user-auth-email.test.ts \
        ./compat-tests/reference-server/contracts/organization-member-join-reference.test.ts
      ;;
    passkey)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm -- -D warnings
      cargo test --locked -p better-auth-core -p better-auth-api --lib passkey
      cargo test --locked --features axum,seaorm2,redis-cache --test plugin_model_fields_tests --test plugin_list_limits_tests --test compat_passkey_tests --test passkey_additional_fields_tests --test two_factor_additional_fields_tests
      bun --no-install test \
        ./compat-tests/reference-server/contracts/passkey-aaguid-fields.test.ts \
        ./compat-tests/reference-server/contracts/passkey-live-fields.test.ts \
        ./compat-tests/reference-server/contracts/passkey-display-mapping.test.ts \
        ./compat-tests/reference-server/contracts/passkey-fields.test.ts
      COMPAT_TEST_PROFILE=native-passkey cargo test --locked --test client_compat_tests -- \
        --ignored --nocapture --exact --test-threads=1 phase8_client_compat configuration_client_compat
      ;;
    totp-period)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-api --lib -- -D warnings
      cargo clippy --locked --test totp_period_nan_tests -- -D warnings
      cargo test --locked -p better-auth-api --lib plugins::two_factor::
      cargo test --locked --test totp_period_nan_tests
      bun --no-install test ./compat-tests/reference-server/contracts/totp-period.test.ts ./compat-tests/reference-server/contracts/totp-period-nan.test.ts ./compat-tests/reference-server/contracts/totp-counter.test.ts
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
    device-storage)
      cargo fmt --all -- --check
      bun --no-install test \
        ./compat-tests/reference-server/contracts/device-grant.test.ts \
        ./compat-tests/reference-server/contracts/device-redemption.test.ts \
        ./compat-tests/reference-server/consumer-contracts/device-grant-sql.test.ts \
        ./compat-tests/reference-server/contracts/native-json-driver.test.ts \
        ./compat-tests/reference-server/consumer-contracts/native-json-driver.test.ts \
        ./compat-tests/reference-server/contracts/device-where.test.ts \
        ./compat-tests/reference-server/consumer-contracts/device-where.test.ts \
        ./compat-tests/reference-server/contracts/device-where-transactions.test.ts \
        ./compat-tests/reference-server/consumer-contracts/device-where-transactions.test.ts \
        ./compat-tests/reference-server/contracts/device-where-references.test.ts \
        ./compat-tests/reference-server/consumer-contracts/device-where-references.test.ts \
        ./compat-tests/reference-server/contracts/device-reference-sets.test.ts \
        ./compat-tests/reference-server/consumer-contracts/device-reference-sets.test.ts \
        ./compat-tests/reference-server/contracts/device-reference-values.test.ts \
        ./compat-tests/reference-server/consumer-contracts/device-reference-values.test.ts \
        ./compat-tests/reference-server/contracts/device-reference-defaults.test.ts \
        ./compat-tests/reference-server/consumer-contracts/device-reference-defaults.test.ts
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test device_grant_tests \
        --test device_where_tests --test sql_user_extra_output_tests \
        --test plugin_output_capabilities_tests --test native_json_driver_tests \
        --test plugin_model_fields_tests -- -D warnings
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test device_grant_tests \
        --test device_where_tests --test native_json_driver_tests -- --include-ignored --nocapture
      cargo test --locked --features axum,seaorm2,redis-cache --test plugin_model_fields_tests -- \
        device_ownership:: device_ownership_sets:: device_consumption:: device_redemption::
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test sql_user_extra_output_tests --test plugin_output_capabilities_tests
      ./scripts/consumer-check.sh --test generated_plugin_catalog device_grant -- --include-ignored
      ;;
    device-validation)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm -p better-auth-cli -- -D warnings
      cargo clippy --locked --features axum,seaorm2,redis-cache --test device_where_tests -- -D warnings
      cargo test --locked -p better-auth-cli empty_field_name_tests
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
      cargo test --locked --features axum,seaorm2,redis-cache --test plugin_model_fields_tests -- \
        device_redemption:: device_ownership:: device_ownership_sets:: device_consumption::
      cargo test --locked --features axum,seaorm2,redis-cache --test device_where_tests -- --include-ignored
      bun --no-install test \
        ./compat-tests/reference-server/contracts/device-where.test.ts \
        ./compat-tests/reference-server/consumer-contracts/device-where.test.ts \
        ./compat-tests/reference-server/contracts/device-where-transactions.test.ts \
        ./compat-tests/reference-server/consumer-contracts/device-where-transactions.test.ts \
        ./compat-tests/reference-server/contracts/device-request-validation.test.ts \
        ./compat-tests/reference-server/contracts/device-grant.test.ts \
        ./compat-tests/reference-server/contracts/device-grant-metadata.test.ts \
        ./compat-tests/reference-server/contracts/device-request-schema.test.ts \
        ./compat-tests/reference-server/contracts/device-ownership.test.ts \
        ./compat-tests/reference-server/contracts/device-ownership-set.test.ts \
        ./compat-tests/reference-server/contracts/openapi-property-order.test.ts \
        ./compat-tests/reference-server/contracts/openapi-endpoint-key-order.test.ts \
        ./compat-tests/reference-server/contracts/openapi-rate-limit-model.test.ts \
        ./compat-tests/reference-server/contracts/device-issuance.test.ts
      ;;
    oauth-proxy)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-api --features axum -- -D warnings
      cargo clippy --locked --features axum,seaorm2,redis-cache --test oauth_proxy_max_age_tests -- -D warnings
      cargo test --locked -p better-auth-api --features axum --lib plugins::oauth::proxy::
      cargo test --locked --features axum,seaorm2,redis-cache --test oauth_proxy_max_age_tests --test oauth_proxy_hooks_tests --test oauth_proxy_request_url_tests
      bun --no-install test ./compat-tests/reference-server/contracts/oauth-proxy-max-age.test.ts
      ;;
    oauth-duration)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-api --features axum -- -D warnings
      cargo clippy --locked --features axum,seaorm2,redis-cache --test oauth_token_duration_tests -- -D warnings
      cargo test --locked --features axum,seaorm2,redis-cache --test oauth_token_duration_tests
      cargo test --locked -p better-auth-api --features axum --lib plugins::oauth::provider_tokens::duration_tests::
      bun --no-install test ./compat-tests/reference-server/contracts/oauth-token-duration.test.ts
      ;;
    provider-options)
      cargo clippy --locked -p better-auth-api --features axum -- -D warnings
      cargo clippy --locked --features axum,seaorm2,redis-cache --test oauth_token_duration_tests -- -D warnings
      cargo test --locked -p better-auth-api --features axum --lib -- \
        plugins::oauth::google_client_ids_tests:: \
        plugins::oauth::verifier_context_tests:: \
        plugins::oauth::gitlab_issuer_tests:: \
        plugins::oauth::microsoft_tests:: \
        plugins::oauth::apple_tests:: \
        plugins::oauth::apple_flow_tests:: \
        plugins::oauth::tiktok_tests:: \
        plugins::oauth::provider_tokens:: \
        plugins::oauth::providers::twitch::tests:: \
        plugins::oauth::signin::override_tests:: \
        plugins::oauth::generic_profile::result_tests::
      cargo test --locked -p better-auth-api --features axum \
        --test account_oauth_tests --test oauth_session_revocation_tests
      cargo test --locked --test social_refresh_context_tests
      cargo test --locked --features axum,seaorm2,redis-cache --test oauth_token_duration_tests
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
        ./compat-tests/reference-server/contracts/oauth-token-duration.test.ts \
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
