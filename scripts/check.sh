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
      cargo test --locked -p better-auth-seaorm --lib store::api_keys::cleanup_tests:: -- --ignored --test-threads=1
      cargo test --locked -p better-auth-seaorm --lib -- store::plugin_records::shared_column_contract_tests:: store::db_error::tests:: --ignored --test-threads=1
      ;;
    id-input)
      cargo fmt --all -- --check
      local id_status=0
      cargo clippy --locked -p better-auth-core -p better-auth-seaorm --lib -- -D warnings || id_status=1
      cargo test --locked -p better-auth-core --lib -- \
        plugin_runtime::fields::id_scope_tests:: id_slot_tests:: \
        store::ephemeral::history_tests:: store::ephemeral::operation_contract_tests:: \
        store::ephemeral::graph_clone_contract_tests:: || id_status=1
      cargo test --locked -p better-auth-seaorm --lib -- \
        store::user_verification_tests:: store::history_tests:: || id_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test session_id_policy_tests --test user_id_generation_order_tests \
        --test plugin_id_slot_tests --test id_generation_tests -- -D warnings || id_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test session_id_policy_tests --test user_id_generation_order_tests \
        --test plugin_id_slot_tests --test id_generation_tests || id_status=1
      return "$id_status"
      ;;
    sql-cleanup)
      cargo fmt --all -- --check
      local cleanup_status=0
      cargo clippy --locked -p better-auth-seaorm --tests -- -D warnings || cleanup_status=1
      cargo test --locked -p better-auth-seaorm --lib store::api_keys::cleanup_tests:: -- --include-ignored --test-threads=1 || cleanup_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache --test auth_entity_plugin_alias_tests -- -D warnings || cleanup_status=1
      cargo test --locked --features axum,seaorm2,redis-cache --test auth_entity_plugin_alias_tests || cleanup_status=1
      return "$cleanup_status"
      ;;
    shared-column)
      cargo fmt --all -- --check
      local column_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/shared-column-capture.test.ts \
        ./compat-tests/reference-server/contracts/shared-column-server-capture.test.ts \
        ./compat-tests/reference-server/contracts/siwe-native-errors.test.ts || column_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm -p better-auth --features axum,seaorm2,redis-cache --lib -- -D warnings || column_status=1
      cargo test --locked -p better-auth-core --features axum,redis-cache --lib -- shared_column_contract_tests:: error:: api_error:: middleware::csrf:: || column_status=1
      cargo test --locked -p better-auth-api --lib -- plugins::siwe:: plugins::device_authorization:: || column_status=1
      cargo test --locked -p better-auth-seaorm --lib -- shared_column_contract_tests:: store::db_error::tests:: --include-ignored --test-threads=1 || column_status=1
      cargo test --locked --features axum,seaorm2,redis-cache --test axum_session_tests --test axum_integration_tests || column_status=1
      return "$column_status"
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
    consumer-schema)
      if [[ -z "${CHECK_COMPAT_PROFILE:-}" ]]; then
        ./scripts/consumer-check.sh
      else
        if [[ ! "$CHECK_COMPAT_PROFILE" =~ ^generated_[[:alnum:]_]+(,generated_[[:alnum:]_]+)*$ ]]; then
          echo "Use comma-separated generated consumer target names." >&2
          return 1
        fi
        local target
        local -a targets selection
        IFS=',' read -r -a targets <<< "$CHECK_COMPAT_PROFILE"
        for target in "${targets[@]}"; do
          selection+=(--test "$target")
        done
        ./scripts/consumer-check.sh "${selection[@]}" -- --include-ignored
      fi
      ;;
    fullstack) cargo check --locked --manifest-path examples/fullstack/backend/Cargo.toml ;;
    quick-start) bun scripts/quick-start-check.ts ;;
    alignment) ./scripts/alignment-check.sh --skip-build ;;
    reference-contracts)
      if [[ -z "${CHECK_COMPAT_PROFILE:-}" ]]; then
        ./scripts/alignment-check.sh --reference-only
      else
        local contract
        local contract_pattern='[[:alnum:]][[:alnum:]_.-]*\.test\.(ts|mjs)'
        if [[ ! "$CHECK_COMPAT_PROFILE" =~ ^${contract_pattern}(,${contract_pattern})*$ ]]; then
          echo "Use comma-separated .test.ts or .test.mjs contract filenames." >&2
          return 1
        fi
        local -a contracts paths
        IFS=',' read -r -a contracts <<< "$CHECK_COMPAT_PROFILE"
        for contract in "${contracts[@]}"; do
          if [[ ! -f "compat-tests/reference-server/contracts/$contract" ]]; then
            echo "Unknown upstream contract: $contract" >&2
            return 1
          fi
          paths+=("./compat-tests/reference-server/contracts/$contract")
        done
        bun --no-install test "${paths[@]}"
      fi
      ;;
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
    organization-team-delete)
      cargo fmt --all -- --check
      local team_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/error-construction.test.ts \
        ./compat-tests/reference-server/contracts/organization-error-construction.test.ts \
        ./compat-tests/reference-server/contracts/organization-live-consumption.test.ts \
        ./compat-tests/reference-server/contracts/organization-team-delete-context.test.ts \
        ./tests/fixtures/organization-native-teams-upstream.test.ts || team_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm -- -D warnings || team_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test plugin_model_fields_tests --test organization_native_team_tests \
        --test organization_list_relations_tests -- -D warnings || team_status=1
      cargo test --locked -p better-auth-core --lib -- \
        store::ephemeral::teams::tests:: error::construction_tests:: || team_status=1
      cargo test --locked -p better-auth-api --lib plugins::organization:: || team_status=1
      cargo test --locked -p better-auth-seaorm --lib organization_schema::tests:: || team_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test plugin_model_fields_tests -- organization::team_delete_context:: \
        organization::organization_live_sources::consumption:: \
        organization::team_member::route_projection:: || team_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test organization_native_team_tests || team_status=1
      return "$team_status"
      ;;
    organization-transactions)
      cargo fmt --all -- --check
      local organization_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/organization-invitation-session-hooks.test.ts \
        ./compat-tests/reference-server/contracts/organization-invitation-cookie-transaction.test.ts \
        ./compat-tests/reference-server/contracts/organization-full-fallback.test.ts \
        ./compat-tests/reference-server/contracts/organization-plugin-fields.test.ts || organization_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm -- -D warnings || organization_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache --test sql_relation_property_tests -- -D warnings || organization_status=1
      cargo test --locked --no-fail-fast -p better-auth-core -p better-auth-seaorm --lib || organization_status=1
      cargo test --locked -p better-auth-api --lib plugins::organization:: || organization_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test organization_native_fields_tests --test organization_invitation_fields_tests \
        --test organization_native_team_tests --test organization_native_join_tests \
        --test sql_relation_property_tests || organization_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test plugin_model_fields_tests -- organization:: || organization_status=1
      return "$organization_status"
      ;;
    organization-members)
      cargo fmt --all -- --check
      local organization_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/organization-member-point-reads.test.ts \
        ./compat-tests/reference-server/contracts/organization-member-native-routes.test.ts \
        ./compat-tests/reference-server/contracts/organization-member-hooks.test.ts \
        ./compat-tests/reference-server/contracts/organization-member-crud-sources.test.ts \
        ./compat-tests/reference-server/contracts/organization-member-join-reference.test.ts \
        ./compat-tests/reference-server/contracts/organization-member-singular-existing.test.ts \
        ./compat-tests/reference-server/contracts/organization-direct-order.test.ts || organization_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm -- -D warnings || organization_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache --test plugin_model_fields_tests -- -D warnings || organization_status=1
      cargo test --locked -p better-auth-api --lib plugins::organization:: || organization_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test organization_member_join_reference_tests --test organization_native_fields_tests \
        --test organization_field_alias_tests --test organization_async_field_tests \
        --test organization_query_limits_tests || organization_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test plugin_model_fields_tests -- organization:: organization_order:: || organization_status=1
      return "$organization_status"
      ;;
    organization-details)
      cargo fmt --all -- --check
      local organization_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/organization-detail-dependencies.test.ts \
        ./compat-tests/reference-server/contracts/organization-full-fallback.test.ts \
        ./compat-tests/reference-server/contracts/sql-relation-property.test.ts \
        ./compat-tests/reference-server/contracts/organization-list-relations.test.ts || organization_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm -- -D warnings || organization_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache --test sql_relation_property_tests -- -D warnings || organization_status=1
      cargo test --locked --no-fail-fast -p better-auth-core -p better-auth-seaorm --lib -- \
        store::joins:: store::ephemeral::organization_joins:: \
        store::ephemeral::organization_parent_tests:: store::ephemeral::user_serial_tests:: \
        store::core_query_binding_tests:: || organization_status=1
      cargo test --locked -p better-auth-api --lib plugins::organization:: || organization_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test organization_native_join_tests --test organization_serial_reference_tests \
        --test sql_relation_property_tests --test organization_list_relations_tests \
        --test organization_list_tests --test organization_member_join_reference_tests \
        --test organization_native_fields_tests --test compat_organization_tests || organization_status=1
      return "$organization_status"
      ;;
    organization-fields)
      cargo fmt --all -- --check
      local organization_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/organization-member-point-reads.test.ts \
        ./compat-tests/reference-server/contracts/organization-member-native-routes.test.ts \
        ./compat-tests/reference-server/contracts/organization-member-hooks.test.ts \
        ./compat-tests/reference-server/contracts/organization-member-crud-sources.test.ts \
        ./compat-tests/reference-server/contracts/organization-live-sources.test.ts \
        ./compat-tests/reference-server/contracts/organization-live-consumption.test.ts \
        ./compat-tests/reference-server/contracts/organization-live-business.test.ts \
        ./compat-tests/reference-server/contracts/organization-id-predicates.test.ts \
        ./compat-tests/reference-server/contracts/organization-invitation-session-hooks.test.ts \
        ./compat-tests/reference-server/contracts/organization-invitation-cookie-transaction.test.ts \
        ./compat-tests/reference-server/contracts/organization-full-fallback.test.ts \
        ./tests/fixtures/organization-join-continuation-upstream.test.ts \
        ./compat-tests/reference-server/contracts/organization-id-input.test.ts \
        ./compat-tests/reference-server/contracts/organization-query-limits.test.ts \
        ./compat-tests/reference-server/contracts/organization-physical-fields.test.ts \
        ./compat-tests/reference-server/contracts/organization-plugin-fields.test.ts \
        ./compat-tests/reference-server/contracts/model-alias-order.test.ts \
        ./compat-tests/reference-server/contracts/team-details-null-selector.test.ts \
        ./compat-tests/reference-server/contracts/native-join-property-collision.test.ts \
        ./compat-tests/reference-server/contracts/organization-detail-dependencies.test.ts \
        ./compat-tests/reference-server/contracts/organization-list-relations.test.ts \
        ./compat-tests/reference-server/contracts/sql-relation-property.test.ts \
        ./compat-tests/reference-server/contracts/relation-object-mutation.test.ts \
        ./compat-tests/reference-server/contracts/organization-member-singular-existing.test.ts \
        ./compat-tests/reference-server/contracts/organization-serial-references.test.ts \
        ./compat-tests/reference-server/contracts/organization-direct-order.test.ts \
        ./compat-tests/reference-server/contracts/account-id-input.test.ts \
        ./compat-tests/reference-server/contracts/account-owner-batch.test.ts \
        ./compat-tests/reference-server/contracts/account-live-output.test.ts \
        ./compat-tests/reference-server/contracts/memory-account-live-page.test.ts \
        ./compat-tests/reference-server/contracts/session-live-output.test.ts \
        ./compat-tests/reference-server/contracts/verification-field-queries.test.ts \
        ./compat-tests/reference-server/contracts/verification-live-output.test.ts \
        ./compat-tests/reference-server/contracts/user-runtime-output.test.ts \
        ./compat-tests/reference-server/contracts/memory-user-live-reads.test.ts \
        ./compat-tests/reference-server/contracts/query-binding-order.test.ts \
        ./compat-tests/reference-server/contracts/member-organization-role-catalog.test.ts \
        ./compat-tests/reference-server/contracts/invitation-catalog.test.ts \
        ./compat-tests/reference-server/contracts/team-catalog.test.ts || organization_status=1
      bun --no-install test ./compat-tests/reference-server/consumer-contracts/team-member-catalog.test.ts --test-name-pattern sqlite || organization_status=1
      cargo clippy --workspace --locked --features axum,seaorm2,redis-cache -- -D warnings || organization_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test organization_id_input_tests --test account_id_input_tests \
        --test verification_field_queries_tests --test plugin_model_fields_tests --test sql_relation_property_tests --test relation_object_mutation_tests --test model_alias_order_tests \
        --test organization_list_relations_tests --test organization_list_tests --test fallback_continuation_tests -- -D warnings || organization_status=1
      cargo test --locked --no-fail-fast -p better-auth-core -p better-auth-seaorm --lib || organization_status=1
      cargo test --locked -p better-auth-api --lib -- \
        plugins::organization:: \
        plugins::passkey::credential_tests::reopen::admission_authentication_tests:: \
        plugins::passkey::credential_tests::reopen::native_boundary_tests:: \
        plugins::passkey::credential_tests::reopen::user_id_tests:: \
        plugins::session_management::native_query_tests:: || organization_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test organization_id_input_tests --test organization_native_fields_tests \
        --test organization_builtin_policy_tests --test organization_invitation_fields_tests \
        --test organization_invitation_presence_tests --test organization_native_team_tests \
        --test organization_additional_fields_tests --test organization_native_tests \
        --test organization_native_join_tests --test organization_query_limits_tests \
        --test organization_field_alias_tests --test organization_async_field_tests \
        --test organization_join_continuation_tests --test organization_serial_reference_tests \
        --test organization_list_relations_tests --test organization_list_tests --test fallback_continuation_tests \
        --test sql_relation_property_tests --test relation_object_mutation_tests --test organization_member_join_reference_tests --test session_field_queries_tests \
        --test account_id_input_tests --test account_owner_batch_tests --test model_alias_order_tests \
        --test account_live_output_tests --test memory_account_live_page_tests \
        --test verification_field_queries_tests --test verification_live_output_tests \
        --test user_runtime_output_tests \
        --test memory_user_live_reads_tests \
        --test account_user_auth_boundary_reference_tests \
        --test legacy_schema_integration_tests || organization_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test plugin_model_fields_tests -- organization:: organization_order:: || organization_status=1
      cargo test --locked -p better-auth-seaorm-macros || organization_status=1
      cargo test --locked -p better-auth-cli --test generate || organization_status=1
      ./scripts/consumer-check.sh --lib --test 'generated_core_*' --test session_native_values --test user_session_fields --test 'generated_plugin_*' || organization_status=1
      return "$organization_status"
      ;;
    oauth-profile)
      cargo fmt --all -- --check
      local profile_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/oauth-native-profile.test.ts \
        ./compat-tests/reference-server/contracts/oauth-native-session.test.ts \
        ./compat-tests/reference-server/contracts/generic-profile-results.test.ts \
        ./compat-tests/reference-server/contracts/social-http-providers.test.ts \
        ./compat-tests/reference-server/contracts/social-native-defaults.test.mjs \
        ./compat-tests/reference-server/contracts/social-http-envelope.test.mjs \
        ./compat-tests/reference-server/contracts/google-profile.test.ts \
        ./compat-tests/reference-server/contracts/google-client-ids.test.ts \
        ./compat-tests/reference-server/contracts/github-email-presence.test.ts \
        ./compat-tests/reference-server/contracts/google-github-native.test.mjs \
        ./compat-tests/reference-server/contracts/social-profile-errors.test.ts \
        ./compat-tests/reference-server/contracts/vk.test.ts \
        ./compat-tests/reference-server/contracts/tiktok.test.ts \
        ./compat-tests/reference-server/contracts/salesforce.test.ts \
        ./compat-tests/reference-server/contracts/oauth-profile-override.test.ts || profile_status=1
      cargo clippy --locked -p better-auth-api --features axum --lib -- -D warnings || profile_status=1
      cargo test --locked -p better-auth-api --features axum --lib -- \
        plugins::oauth:: plugins::one_tap:: plugins::user_admission:: || profile_status=1
      cargo test --locked -p better-auth-api --features axum --no-fail-fast \
        --test account_oauth_tests --test oauth_session_revocation_tests || profile_status=1
      cargo test --locked -p better-auth-core --lib -- error:: field_value:: observability::logger:: \
        user_fields::input_binding_tests:: store::ephemeral::initial_storage_tests:: \
        plugin::tests::route_paths:: || profile_status=1
      cargo test --locked --features axum,seaorm2,redis-cache --no-fail-fast \
        --test account_user_auth_boundary_reference_tests --test account_native_selector_tests \
        --test social_refresh_context_tests --test oauth_profile_presence_tests \
        --test oauth_proxy_hooks_tests --test oauth_proxy_request_url_tests \
        --test oauth_proxy_max_age_tests || profile_status=1
      return "$profile_status"
      ;;
    memory-joins)
      cargo fmt --all -- --check
      local join_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/memory-native-join-grouping.test.ts \
        ./compat-tests/reference-server/contracts/account-user-selected-relations.test.ts \
        ./compat-tests/reference-server/contracts/native-core-joins.test.ts \
        ./compat-tests/reference-server/contracts/session-user-join-reference.test.ts || join_status=1
      cargo clippy --locked -p better-auth-core --lib -- -D warnings || join_status=1
      cargo test --locked -p better-auth-core --lib -- \
        store::ephemeral:: user_fields::batch:: store::joins:: || join_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test account_native_selector_tests --test native_core_join_tests \
        --test session_user_join_reference_tests || join_status=1
      return "$join_status"
      ;;
    memory-query)
      cargo fmt --all -- --check
      local query_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/device-where.test.ts \
        ./compat-tests/reference-server/contracts/device-reference-values.test.ts \
        ./compat-tests/reference-server/contracts/device-reference-defaults.test.ts \
        ./compat-tests/reference-server/contracts/organization-query-limits.test.ts \
        ./compat-tests/reference-server/contracts/organization-member-query-scheduling.test.ts \
        ./compat-tests/reference-server/contracts/organization-team-delete-context.test.ts \
        ./compat-tests/reference-server/contracts/organization-physical-fields.test.ts \
        ./compat-tests/reference-server/contracts/query-binding-order.test.ts \
        ./compat-tests/reference-server/contracts/core-query-id-alias.test.ts \
        ./compat-tests/reference-server/contracts/core-query-id-sort.test.ts \
        ./compat-tests/reference-server/contracts/api-key-cleanup-fields.test.ts \
        ./compat-tests/reference-server/contracts/organization-query-id-alias.test.ts \
        ./compat-tests/reference-server/contracts/organization-query-id-alias-boundaries.test.ts \
        ./compat-tests/reference-server/contracts/invitation-claim-status.test.ts \
        ./compat-tests/reference-server/contracts/invitation-claim-selector-values.test.ts \
        ./compat-tests/reference-server/contracts/plugin-model-fields.test.ts \
        ./compat-tests/reference-server/contracts/user-runtime-input.test.ts \
        ./compat-tests/reference-server/contracts/user-runtime-output.test.ts \
        ./compat-tests/reference-server/contracts/memory-user-live-reads.test.ts \
        ./compat-tests/reference-server/contracts/secondary-user-refresh.test.ts \
        ./compat-tests/reference-server/contracts/secondary-user-refresh-values.test.ts || query_status=1
      cargo clippy --workspace --locked --features axum,seaorm2,redis-cache -- -D warnings || query_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test plugin_model_fields_tests --test query_binding_order_tests \
        --test nullable_user_update_tests --test telemetry_options_tests -- -D warnings || query_status=1
      cargo test --locked -p better-auth-core --features redis-cache --lib -- \
        store::ephemeral:: user_query:: store::joins:: request_runtime:: store::secondary:: field_value:: query:: \
        user_fields::record:: store::session_create:: session::cookie_cache:: || query_status=1
      cargo test --locked -p better-auth-api --lib plugins::api_key::verification::validator_error_tests || query_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test device_runtime_transaction_tests --test device_where_tests \
        --test organization_query_limits_tests --test organization_native_fields_tests \
        --test organization_serial_reference_tests --test query_binding_order_tests \
        --test plugin_model_fields_tests --test user_runtime_input_tests \
        --test user_record_values_tests --test memory_user_live_reads_tests \
        --test nullable_user_update_tests --test telemetry_options_tests || query_status=1
      return "$query_status"
      ;;
    memory-sorting)
      cargo fmt --all -- --check
      cargo clippy --locked -p better-auth-core -p better-auth-api --lib -- -D warnings
      cargo test --locked -p better-auth-core --lib -- \
        store::ephemeral::api_keys::tests::sorting:: \
        store::ephemeral::organization::query_tests:: \
        field_value::tests:: native_sort_ \
        store::ephemeral::native_storage_tests:: store::ephemeral::rows:: \
        store::ephemeral::table::tests:: store::ephemeral::transactions::tests:: \
        store::ephemeral::graph_clone_contract_tests:: store::ephemeral::operation_contract_tests::
      cargo test --locked -p better-auth-api --lib -- plugins::api_key::tests::list_tests:: native_sort_
      bun --no-install test \
        ./compat-tests/reference-server/contracts/native-sort-consumers-capture.test.ts \
        ./compat-tests/reference-server/contracts/native-sort-data-capture.test.ts \
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
      ./scripts/consumer-check.sh --test generated_plugin_display_json plugin_display_json -- --include-ignored
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
        ./compat-tests/reference-server/contracts/plugin-typed-metadata.test.ts \
        ./compat-tests/reference-server/contracts/native-atomic-update.test.ts \
        ./compat-tests/reference-server/contracts/passkey-projected-id.test.ts \
        ./compat-tests/reference-server/contracts/passkey-shared-display.test.ts \
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
      cargo clippy --locked --keep-going --features axum,seaorm2,redis-cache --test plugin_output_capabilities_tests --test async_field_transform_tests --test api_key_additional_fields_tests --test passkey_additional_fields_tests --test device_grant_tests --test organization_member_json_filter_reference_tests --test auth_entity_plugin_alias_tests --test plugin_model_fields_tests -- -D warnings || plugin_status=1
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
      ./scripts/consumer-check.sh --test generated_plugin_api_key --test generated_plugin_device --test generated_plugin_display_json --test 'generated_plugin_native_*' -- --include-ignored api_key_additional_fields native_plugin_replacements device plugin_display_json || plugin_status=1
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
          plugin::tests::response_headers:: plugin::tests::response_status:: plugin::tests::response_values:: types::tests::auth_response_json update_session_rejections_keep_native_api_errors_and_http_status \
          store::ephemeral::organization store::ephemeral::memory_json_tests:: serial_primary_tests::organization:: \
          user_column_defaults user_runtime_input_tests user_serial_tests api_key_start::tests protected_function_tests field_value:: record_bindings:: value_filter::core_query_tests:: value_filter::tests:: id_filter::tests:: members::tests:: device_code_consume::tests:: types_plugin::device::tests \
          member_delete:: serial_primary_tests::team_members:: native_team_mutations native_invitation_acceptance organization_role organization_fields:: organization_models:: cookie_utils::native_cookie_tests:: \
          user_view_preserves_adapter_order_through_cache_and_visibility \
          plugins::jwt:: plugins::api_key:: plugins::passkey:: plugins::organization:: plugins::test_utils:: \
          plugins::custom_session:: plugins::one_time_token:: plugins::multi_session:: plugins::anonymous:: plugins::siwe:: \
          plugins::user_admission:: \
          plugins::admin:: plugins::email_verification:: plugins::email_otp:: plugins::email_password:: plugins::phone_number:: \
          plugins::two_factor:: plugins::user_management:: plugins::oauth:: || create_status=1
        cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
          --test database_hooks_tests --test database_lifecycle_tests --test database_hook_updates_tests \
          --test session_create_payload_tests --test session_initial_defaults_tests --test session_id_policy_tests --test session_field_queries_tests \
          --test custom_session_fields_tests --test secondary_storage_hooks_tests \
          --test transaction_effect_order_tests --test transaction_hook_context_tests \
          --test organization_native_team_tests --test organization_query_limits_tests \
          --test organization_native_fields_tests --test organization_additional_fields_tests \
          --test organization_native_join_tests --test organization_serial_reference_tests \
          --test organization_duration_tests --test organization_native_tests --test remaining_notification_tests \
          --test http_routing_tests --test native_endpoint_tests --test cookie_http_errors_tests \
          --test test_utils_tests --test legacy_schema_integration_tests \
          --test user_runtime_output_tests --test user_runtime_cache_tests \
          --test user_runtime_input_tests --test user_account_raw_column_tests \
          --test user_input_policy_tests --test protected_function_tests \
          --test user_verification_fields_tests --test user_record_values_tests \
          --test account_owner_batch_tests --test account_identity_tests --test account_native_selector_tests --test account_batch_update_tests --test account_live_output_tests \
          --test id_memory_tests --test account_id_input_tests \
          --test account_verification_update_fields_tests --test verification_field_queries_tests --test verification_live_output_tests --test query_binding_order_tests \
          --test verification_transaction_delete_tests \
          --test account_user_selected_relations_reference_tests \
          --test native_core_join_tests --test native_memory_join_tests --test session_user_join_reference_tests \
          --test memory_user_live_reads_tests --test api_key_number_name_tests \
          --test plugin_display_json_tests --test plugin_model_fields_tests \
          --test nullable_user_update_tests --test sql_user_string_output_tests --test sql_user_extra_output_tests \
          --test username_runtime_tests --test email_normalization_tests --test user_native_delete_tests --test user_delete_transaction_tests \
          --test email_verification_duration_tests --test email_verification_payload_tests --test email_verification_claims_tests \
          --test lifecycle_notification_tests || create_status=1
        cargo test --locked --features axum,seaorm2,redis-cache --test mysql_create_readback_tests -- --ignored || create_status=1
        cargo test --locked --features axum,seaorm2,redis-cache --test user_account_raw_column_tests -- --ignored || create_status=1
        cargo test --locked --features axum,seaorm2,redis-cache --test account_verification_update_fields_tests -- --ignored || create_status=1
        cargo test --locked --features axum,seaorm2,redis-cache --test verification_transaction_delete_tests -- --ignored || create_status=1
        cargo test --locked --features axum,seaorm2,redis-cache --test user_delete_transaction_tests -- --ignored || create_status=1
        cargo test --locked --features axum,seaorm2,redis-cache --test query_binding_order_tests -- --ignored || create_status=1
        cargo test --locked -p better-auth-cli --test generate || create_status=1
        ./scripts/consumer-check.sh --lib --test 'generated_core_*' --test session_native_values --test user_session_fields || create_status=1
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
      bun --no-install test ./compat-tests/reference-server/consumer-contracts/mysql-create-readback.test.ts \
        ./compat-tests/reference-server/consumer-contracts/update-fields-server.test.ts \
        ./compat-tests/reference-server/consumer-contracts/organization-role-empty-in.test.ts \
        ./compat-tests/reference-server/consumer-contracts/verification-consume-hooks-server.test.ts || create_status=1
      bun --no-install test ./compat-tests/reference-server/contracts/email-verification-claims.test.ts \
        ./compat-tests/reference-server/contracts/email-verification-payload.test.ts \
        ./compat-tests/reference-server/contracts/sqlite-utf16-binding.test.ts \
        ./compat-tests/reference-server/contracts/user-runtime-output.test.ts \
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
        ./compat-tests/reference-server/contracts/account-live-output.test.ts \
        ./compat-tests/reference-server/contracts/account-id-input.test.ts \
        ./compat-tests/reference-server/contracts/account-verification-update-fields.test.ts \
        ./compat-tests/reference-server/contracts/verification-field-queries.test.ts \
        ./compat-tests/reference-server/contracts/verification-live-output.test.ts \
        ./compat-tests/reference-server/contracts/query-binding-order.test.ts \
        ./compat-tests/reference-server/contracts/verification-consume-hooks.test.ts \
        ./compat-tests/reference-server/contracts/endpoint-content-type.test.ts \
        ./compat-tests/reference-server/contracts/siwe-native-errors.test.ts \
        ./compat-tests/reference-server/contracts/organization-physical-fields.test.ts \
        ./compat-tests/reference-server/contracts/organization-query-limits.test.ts \
        ./compat-tests/reference-server/contracts/session-management-native.test.ts \
        ./compat-tests/reference-server/contracts/session-field-queries.test.ts \
        ./compat-tests/reference-server/contracts/account-duplicates.test.ts \
        ./compat-tests/reference-server/contracts/account-user-selected-relations.test.ts \
        ./compat-tests/reference-server/contracts/native-core-joins.test.ts \
        ./compat-tests/reference-server/contracts/memory-user-live-reads.test.ts \
        ./compat-tests/reference-server/contracts/sql-user-string-output.test.ts \
        ./compat-tests/reference-server/contracts/sql-user-extra-output.test.ts || create_status=1
      return "$create_status"
      ;;
    jwt)
      cargo fmt --all -- --check
      local jwt_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/error-construction.test.ts \
        ./compat-tests/reference-server/contracts/raw-api-errors.test.ts \
        ./compat-tests/reference-server/contracts/native-json.test.ts \
        ./compat-tests/reference-server/contracts/jwk-native-date-methods.test.ts \
        ./compat-tests/reference-server/contracts/jwt-native-callbacks.test.ts \
        ./compat-tests/reference-server/contracts/jwt-native-options.test.ts \
        ./compat-tests/reference-server/contracts/jwt-native-resolved-key-null.test.ts \
        ./compat-tests/reference-server/contracts/native-sort-consumers-capture.test.ts \
        ./compat-tests/reference-server/contracts/native-sort-data-capture.test.ts || jwt_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api --lib -- -D warnings || jwt_status=1
      cargo test --locked -p better-auth-core --lib -- error:: field_value:: session:: plugin::tests::native_session_hooks:: || jwt_status=1
      cargo test --locked -p better-auth-api --lib -- plugins::jwt:: plugins::json_body:: || jwt_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test jwt_transaction_tests --test jwk_additional_fields_tests \
        --test jwt_native_resolved_key_null_tests \
        --test native_endpoint_tests -- -D warnings || jwt_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test jwt_transaction_tests --test jwk_additional_fields_tests \
        --test jwt_native_resolved_key_null_tests \
        --test native_endpoint_tests || jwt_status=1
      return "$jwt_status"
      ;;
    api-key-cache)
      cargo fmt --all -- --check
      local cache_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/api-key-cache-key-order-capture.test.ts \
        ./compat-tests/reference-server/contracts/api-key-ttl-clock.test.ts \
        ./compat-tests/reference-server/contracts/password-native-boundary-capture.test.ts \
        ./compat-tests/reference-server/contracts/password-query-order-capture.test.ts \
        ./compat-tests/reference-server/contracts/password-session-boundary-capture.test.ts \
        ./compat-tests/reference-server/contracts/selected-user-property-capture.test.ts \
        ./compat-tests/reference-server/contracts/native-sort-consumers-capture.test.ts \
        ./compat-tests/reference-server/contracts/native-sort-data-capture.test.ts \
        ./compat-tests/reference-server/contracts/api-key-date-methods-capture.test.ts \
        ./compat-tests/reference-server/contracts/api-key-date-identity.test.ts \
        ./compat-tests/reference-server/contracts/api-key-session-reference.test.ts \
        ./compat-tests/reference-server/contracts/jwk-native-date-methods.test.ts \
        ./compat-tests/reference-server/contracts/passkey-update-boundary.test.ts \
        ./compat-tests/reference-server/contracts/passkey-projected-id.test.ts \
        ./compat-tests/reference-server/contracts/api-key-usage-miss.test.ts \
        ./compat-tests/reference-server/contracts/api-key-usage-success-capture.test.ts \
        ./compat-tests/reference-server/contracts/api-key-delete-expired.test.ts \
        ./compat-tests/reference-server/contracts/api-key-cache-batch.test.ts \
        ./compat-tests/reference-server/contracts/api-key-cache-sort.test.ts \
        ./compat-tests/reference-server/contracts/secondary-user-refresh.test.ts \
        ./compat-tests/reference-server/contracts/secondary-user-refresh-values.test.ts \
        ./compat-tests/reference-server/contracts/secondary-storage-invocation.test.ts \
        ./compat-tests/reference-server/contracts/secondary-storage-failure.test.ts \
        ./compat-tests/reference-server/contracts/device-session-invocation.test.ts \
        ./compat-tests/reference-server/contracts/api-key-reference-native-capture.test.ts \
        ./compat-tests/reference-server/contracts/session-secondary-native-capture.test.ts \
        ./compat-tests/reference-server/contracts/safe-json-native-capture.test.ts \
        ./compat-tests/reference-server/contracts/oauth-logout-native-capture.test.ts \
        ./compat-tests/reference-server/contracts/secondary-native-write-undefined-capture.test.ts \
        ./compat-tests/reference-server/contracts/verification-consume-native-capture.test.ts \
        ./compat-tests/reference-server/contracts/verification-native-read-write-capture.test.ts \
        ./compat-tests/reference-server/contracts/json-parse-native-capture.test.ts \
        ./compat-tests/reference-server/contracts/verification-otp-consumer-native-capture.test.ts \
        ./compat-tests/reference-server/contracts/verification-auth-consumer-native-capture.test.ts || cache_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api --features better-auth-core/redis-cache --lib -- -D warnings || cache_status=1
      cargo clippy --locked -p better-auth-seaorm -p better-auth-cli -- -D warnings || cache_status=1
      cargo test --locked -p better-auth-cli schema_config || cache_status=1
      cargo test --locked -p better-auth-seaorm-macros --lib || cache_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache --test api_key_delete_expired_tests -- -D warnings || cache_status=1
      cargo test --locked -p better-auth-core --features redis-cache --lib -- \
        request_runtime::concurrent:: background::tests:: plugin::tests::auth_context_clock_survives_clone_and_native_dispatch utils::password:: utils::json::runtime:: utils::json::syntax:: field_value:: schema_value:: store::cache:: store::secondary:: store::ephemeral::api_keys:: store::ephemeral::shared_column_contract_tests:: native_sort_ passkey wire::api_key_view::tests:: \
        store::ephemeral::native_storage_tests:: store::ephemeral::rows:: \
        store::ephemeral::table::tests:: store::ephemeral::transactions::tests:: \
        store::ephemeral::graph_clone_contract_tests:: store::ephemeral::operation_contract_tests:: || cache_status=1
      cargo test --locked -p better-auth-api --lib -- \
        plugins::api_key:: plugins::jwt:: plugins::passkey:: plugins::oauth:: plugins::email_otp:: plugins::phone_number:: plugins::two_factor:: plugins::password_management:: plugins::email_password:: plugins::username:: plugins::user_management:: plugins::have_i_been_pwned:: plugins::device_authorization::native_tests selected_user_property_ || cache_status=1
      cargo test --locked -p better-auth-seaorm --lib -- \
        store::plugin_records::tests:: store::plugin_records::shared_column_contract_tests:: \
        store::plugin_rows::legacy_private_tests:: \
        store::shared_column_tests:: store::record_write::tests:: \
        store::api_keys::record_tests:: store::passkeys::record_tests:: \
        store::organization_models::tests:: store::user_verification_tests:: \
        store::history_tests:: || cache_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test secondary_storage_hooks_tests --test session_initial_defaults_tests \
        --test api_key_delete_expired_tests --test api_key_additional_fields_tests \
        --test passkey_additional_fields_tests --test async_field_transform_tests \
        --test session_id_policy_tests --test query_binding_order_tests || cache_status=1
      cargo check --locked --manifest-path compat-tests/rust-server/Cargo.toml || cache_status=1
      return "$cache_status"
      ;;
    native-errors)
      cargo fmt --all -- --check
      local errors_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/raw-api-errors.test.ts \
        ./compat-tests/reference-server/contracts/error-construction.test.ts \
        ./compat-tests/reference-server/contracts/device-request-validation.test.ts \
        ./compat-tests/reference-server/contracts/user-input-policy.test.ts \
        ./compat-tests/reference-server/contracts/admin-error-construction.test.ts \
        ./compat-tests/reference-server/contracts/update-user-native-session.test.ts \
        ./compat-tests/reference-server/contracts/username-session-consumption.test.ts \
        ./compat-tests/reference-server/contracts/endpoint-content-type.test.ts \
        ./compat-tests/reference-server/contracts/siwe-native-errors.test.ts \
        ./compat-tests/reference-server/contracts/one-time-token-expiry.test.ts \
        ./compat-tests/reference-server/contracts/organization-error-construction.test.ts \
        ./compat-tests/reference-server/contracts/organization-live-business.test.ts || errors_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm --lib -- -D warnings || errors_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test plugin_model_fields_tests --test native_endpoint_tests \
        --test required_headers_tests --test device_request_validation_tests \
        --test organization_body_schema_tests --test user_input_policy_tests --test protected_function_tests \
        --test admin_error_construction_tests -- -D warnings || errors_status=1
      cargo test --locked -p better-auth-core --lib -- \
        error:: session:: query:: http_body:: user_fields::organization::tests:: \
        plugin::tests::raw_api_errors:: plugin::tests::async_body_dispatch:: \
        plugin::tests::response_status:: plugin::tests::response_values:: \
        store::ephemeral::member_delete:: store::joins::organization:: || errors_status=1
      cargo test --locked -p better-auth-api --features axum --lib || errors_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test plugin_model_fields_tests -- organization_errors_preserve_constructor_provenance \
        organization_role_business_consumes_ team_routes_preserve_scope_public_clone_and_page_guards || errors_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test native_endpoint_tests --test admin_error_construction_tests --test organization_native_tests \
        --test required_headers_tests --test device_request_validation_tests \
        --test organization_body_schema_tests --test user_input_policy_tests --test protected_function_tests \
        --test organization_query_limits_tests --test username_runtime_tests || errors_status=1
      return "$errors_status"
      ;;
    logger)
      cargo fmt --all -- --check
      local logger_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/logger-color-depth.test.ts \
        ./compat-tests/reference-server/contracts/logger-live-options.test.ts \
        ./compat-tests/reference-server/contracts/logger-background-ownership-capture.test.ts \
        ./compat-tests/reference-server/contracts/background-success-values-capture.test.ts \
        ./compat-tests/reference-server/contracts/email-otp-override-values-capture.test.ts \
        ./compat-tests/reference-server/contracts/api-key-usage-miss.test.ts \
        ./compat-tests/reference-server/contracts/api-key-usage-success-capture.test.ts \
        ./compat-tests/reference-server/contracts/api-key-delete-expired.test.ts \
        ./compat-tests/reference-server/contracts/api-key-cleanup-fields.test.ts \
        ./compat-tests/reference-server/contracts/api-key-cleanup-fields-sql-capture.test.ts \
        ./compat-tests/reference-server/contracts/on-api-error-detached.test.ts \
        ./compat-tests/reference-server/contracts/telemetry-detached.test.ts \
        ./compat-tests/reference-server/contracts/secondary-logger-scope.test.ts \
        ./compat-tests/reference-server/contracts/http-error-logging.test.ts \
        ./compat-tests/reference-server/contracts/http-api-error-logging.test.ts \
        ./compat-tests/reference-server/contracts/observability.test.ts || logger_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm --features axum --lib -- -D warnings || logger_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test http_api_error_logging_tests --test observability_tests \
        --test http_conversion_ownership_tests --test logger_telemetry_ownership_tests \
        --test captcha_logger_scope_tests \
        --test axum_session_tests -- -D warnings || logger_status=1
      cargo test --locked -p better-auth-core --features axum --lib -- \
        observability::logger:: error::http_tests:: error::logger_boundary_tests:: \
        background::tests:: utils::json:: \
        store::secondary::sessions::logging_tests:: store::secondary::users::tests:: \
        api_key_cleanup_uses_shared_field_bindings \
        plugin::tests::raw_api_errors:: || logger_status=1
      cargo test --locked -p better-auth-api --features axum --lib -- \
        plugins::user_admission_tests:: plugins::api_key:: \
        plugins::oauth::providers::paypal:: plugins::oauth::popup:: \
        plugins::email_otp:: || logger_status=1
      cargo test --locked -p better-auth-seaorm --lib store::api_keys::cleanup_tests:: -- --include-ignored --test-threads=1 || logger_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test http_api_error_logging_tests --test observability_tests \
        --test http_conversion_ownership_tests --test logger_telemetry_ownership_tests \
        --test captcha_logger_scope_tests \
        --test axum_session_tests --test native_endpoint_tests \
        --test background_notification_tests --test background_otp_notification_tests \
        --test background_transaction_tests --test lifecycle_notification_tests \
        --test remaining_notification_tests --test rate_cleanup_background_tests \
        --test email_otp_scheduled_override_tests \
        --test api_key_delete_expired_tests --test api_key_metadata_tests \
        --test api_key_metadata_timing_tests \
        --test request_runtime_mutation_tests || logger_status=1
      cargo check --locked --manifest-path compat-tests/rust-server/Cargo.toml || logger_status=1
      return "$logger_status"
      ;;
    native-json)
      cargo fmt --all -- --check
      local json_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/native-json.test.ts \
        ./compat-tests/reference-server/contracts/native-named-properties.test.ts \
        ./compat-tests/reference-server/contracts/native-coercion-properties.test.ts \
        ./compat-tests/reference-server/contracts/invitation-claim-selector-values.test.ts \
        ./compat-tests/reference-server/contracts/raw-api-errors.test.ts \
        ./compat-tests/reference-server/contracts/error-construction.test.ts \
        ./compat-tests/reference-server/contracts/endpoint-content-type.test.ts \
        ./compat-tests/reference-server/contracts/http-body-classification.test.ts \
        ./compat-tests/reference-server/contracts/http-json-wrapper.test.ts \
        ./compat-tests/reference-server/contracts/http-error-logging.test.ts \
        ./compat-tests/reference-server/contracts/http-api-error-logging.test.ts \
        ./compat-tests/reference-server/contracts/logger-color-depth.test.ts \
        ./compat-tests/reference-server/contracts/logger-live-options.test.ts \
        ./compat-tests/reference-server/contracts/logger-background-ownership-capture.test.ts \
        ./compat-tests/reference-server/contracts/background-success-values-capture.test.ts \
        ./compat-tests/reference-server/contracts/email-otp-override-values-capture.test.ts \
        ./compat-tests/reference-server/contracts/on-api-error-detached.test.ts \
        ./compat-tests/reference-server/contracts/telemetry-detached.test.ts \
        ./compat-tests/reference-server/contracts/secondary-logger-scope.test.ts \
        ./compat-tests/reference-server/contracts/observability.test.ts \
        ./compat-tests/reference-server/contracts/native-body-context.test.ts \
        ./compat-tests/reference-server/contracts/hook-matcher-input.test.ts \
        ./compat-tests/reference-server/contracts/api-key-field-policies.test.ts \
        ./compat-tests/reference-server/contracts/organization-output-boundary.test.ts \
        ./compat-tests/reference-server/contracts/request-runtime-mutation.test.ts \
        ./compat-tests/reference-server/contracts/request-runtime-url-routing.test.ts \
        ./compat-tests/reference-server/contracts/oauth-native-projection.test.ts \
        ./compat-tests/reference-server/contracts/oauth-proxy-native-input.test.ts \
        ./compat-tests/reference-server/contracts/oauth-proxy-runtime-url.test.ts \
        ./compat-tests/reference-server/contracts/oauth-native-token.test.ts \
        ./compat-tests/reference-server/contracts/oauth-proxy-callback.test.ts \
        ./compat-tests/reference-server/contracts/oauth-proxy-native-result.test.ts || json_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api --lib -- -D warnings || json_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api --features axum \
        --tests -- -D warnings || json_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test plugin_model_fields_tests --test native_endpoint_tests --test server_api_tests \
        --test organization_body_schema_tests --test request_query_tests --test required_headers_tests \
        --test api_key_number_name_tests --test api_key_additional_fields_tests \
        --test oauth_token_duration_tests --test oauth_proxy_hooks_tests \
        --test oauth_proxy_request_url_tests --test request_runtime_mutation_tests \
        --test dynamic_runtime_tests --test http_api_error_logging_tests -- -D warnings || json_status=1
      cargo test --locked -p better-auth-core --lib -- \
        error:: field_value:: schema_value:: session:: endpoint_input:: http_body:: utils::defu:: utils::jwt:: utils::jwe:: utils::url:: wire:: \
        request_runtime:: query:: plugin::tests::async_body_dispatch:: \
        store::ephemeral::id_slot_tests::organization_query_alias_tests::selector_values:: \
        observability::logger:: observability::telemetry:: \
        store::secondary::sessions::logging_tests:: store::secondary::users::tests:: \
        plugin::tests::raw_api_errors:: \
        plugin::tests::response_values:: plugin::tests::response_headers:: \
        plugin::tests::response_status:: response_body::http_tests:: types::response:: \
        types::request_headers:: || json_status=1
      cargo test --locked -p better-auth-api --features axum --lib -- \
        plugins::jwt:: plugins::organization:: plugins::api_key:: plugins::anonymous:: plugins::phone_number:: plugins::oauth:: plugins::custom_session:: \
        plugins::passkey:: plugins::siwe:: \
        plugins::admin:: plugins::email_password:: plugins::username:: plugins::password_management:: || json_status=1
      cargo test --locked -p better-auth-api --features axum \
        --test account_oauth_tests || json_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test plugin_model_fields_tests -- response_to_json:: api_key::updates:: \
        organization::organization_live_business::output_boundary:: || json_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test native_endpoint_tests --test server_api_tests \
        --test organization_body_schema_tests --test request_query_tests --test required_headers_tests \
        --test api_key_number_name_tests --test oauth_token_duration_tests \
        --test oauth_proxy_hooks_tests --test oauth_proxy_request_url_tests \
        --test request_runtime_mutation_tests --test dynamic_runtime_tests \
        --test http_api_error_logging_tests || json_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test api_key_additional_fields_tests -- typed_metadata:: || json_status=1
      cargo check --locked --manifest-path compat-tests/rust-server/Cargo.toml || json_status=1
      return "$json_status"
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
    atomic-updates)
      cargo fmt --all -- --check
      local atomic_status=0
      local atomic_tests=(
        --test query_binding_order_tests --test api_key_additional_fields_tests
        --test two_factor_additional_fields_tests --test device_runtime_transaction_tests
        --test device_additional_fields_tests --test organization_native_team_tests
        --test rate_limit_database_tests --test observability_tests
      )
      cargo clippy --locked -p better-auth-seaorm -- -D warnings || atomic_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        "${atomic_tests[@]}" --test plugin_model_fields_tests -- -D warnings || atomic_status=1
      cargo test --locked -p better-auth-seaorm --lib -- \
        store::record_write::tests:: store::record_bindings:: store::updates:: \
        team_capacity device_code_consume async_capacity_output_failure \
        store::session_delete::token_tests:: || atomic_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        "${atomic_tests[@]}" || atomic_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test query_binding_order_tests increment_phases:: -- --ignored || atomic_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test plugin_model_fields_tests -- \
        organization::team_member organization::team_transaction device_ownership:: device_redemption:: || atomic_status=1
      bun --no-install test \
        ./compat-tests/reference-server/contracts/query-binding-order.test.ts \
        ./compat-tests/reference-server/consumer-contracts/increment-binding-phases.test.ts \
        ./compat-tests/reference-server/consumer-contracts/rate-limit-server-runtime.test.ts \
        ./compat-tests/reference-server/contracts/native-atomic-update.test.ts \
        ./compat-tests/reference-server/contracts/api-key-date-usage.test.ts \
        ./compat-tests/reference-server/consumer-contracts/api-key-date-usage.test.ts || atomic_status=1
      return "$atomic_status"
      ;;
    oauth-signin-order)
      cargo fmt --all -- --check
      local signin_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/account-user-auth-order.test.ts \
        ./compat-tests/reference-server/contracts/account-user-auth-link.test.ts || signin_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test account_user_auth_boundary_reference_tests --test account_native_selector_tests \
        --test observability_tests -- -D warnings || signin_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test account_user_auth_boundary_reference_tests --test account_native_selector_tests || signin_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test observability_tests -- spans_preserve_dispatch_order_parentage_and_original_outcomes || signin_status=1
      cargo test --locked -p better-auth-api --lib -- \
        plugins::oauth:: plugins::anonymous:: plugins::user_admission::provider_tests:: || signin_status=1
      cargo test --locked -p better-auth-core --lib -- \
        types_account:: field_value:: schema_value:: || signin_status=1
      return "$signin_status"
      ;;
    account-user-auth)
      cargo fmt --all -- --check
      local account_status=0
      local account_tests=(
        --test account_user_auth_boundary_reference_tests --test compat_consistency_tests
        --test wire_compat_smoke_tests --test two_factor_cookie_duration_tests
        --test plugin_model_fields_tests --test session_create_payload_tests
        --test session_user_join_reference_tests --test custom_model_join_reference_tests
        --test secondary_storage_hooks_tests --test background_transaction_tests
        --test missing_user_transaction_tests --test axum_session_tests
        --test paypal_provider_tests --test wechat_provider_tests
        --test social_http_provider_tests --test social_refresh_context_tests
        --test integration_tests --test plugin_schema_tests --test user_verification_fields_tests
        --test user_display_query_tests --test user_scalar_column_query_tests
        --test user_sort_field_tests --test user_null_query_tests --test device_where_tests
        --test query_binding_order_tests --test native_core_join_tests --test sparse_native_join_tests
        --test two_factor_additional_fields_tests --test wallet_additional_fields_tests
        --test passkey_additional_fields_tests --test schema_preflight_tests
        --test api_key_additional_fields_tests --test device_additional_fields_tests
        --test observability_tests
        --test organization_builtin_policy_tests --test rate_limit_database_tests
      )
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        "${account_tests[@]}" -- -D warnings || account_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        "${account_tests[@]}" || account_status=1
      cargo test --locked -p better-auth-api --lib -- \
        plugins::two_factor:: plugins::oauth:: plugins::anonymous:: || account_status=1
      cargo test --locked -p better-auth-api \
        --test account_oauth_tests --test oauth_session_revocation_tests || account_status=1
      cargo test --locked --features axum,seaorm2,redis-cache \
        --test required_headers_tests --test organization_native_team_tests || account_status=1
      cargo test --locked -p better-auth-core --lib -- \
        types_account:: plugin_runtime::fields::models::tests:: plugin_runtime::fields::rate_limit_tests:: session::native::tests:: \
        store::ephemeral::user_serial_tests:: store::ephemeral::sessions::live_output_tests:: \
        store::ephemeral::id_slot_tests::sessions:: request_runtime::concurrent:: || account_status=1
      cargo test --locked -p better-auth-seaorm --lib -- \
        store::record_bindings::function_tests store::value_filter::predicate::tests:: \
        store::device_code_consume::tests:: store::record_write::tests:: store::updates::tests:: \
        async_capacity_output_failure_rolls_back_the_seat_and_membership \
        team_capacity_deduplication_and_scoped_cleanup || account_status=1
      bun --no-install test \
        ./compat-tests/reference-server/contracts/account-user-auth-boundary.test.ts \
        ./compat-tests/reference-server/contracts/account-user-auth-email.test.ts \
        ./compat-tests/reference-server/contracts/account-user-auth-secondary.test.ts \
        ./compat-tests/reference-server/contracts/account-user-auth-order.test.ts \
        ./compat-tests/reference-server/contracts/account-user-auth-link.test.ts \
        ./compat-tests/reference-server/contracts/session-user-join-reference.test.ts \
        ./compat-tests/reference-server/contracts/custom-model-join-reference.test.ts \
        ./compat-tests/reference-server/contracts/adapter-id-slot.test.ts \
        ./compat-tests/reference-server/contracts/user-display-query.test.ts \
        ./compat-tests/reference-server/contracts/user-scalar-column-query.test.ts \
        ./compat-tests/reference-server/contracts/sparse-native-joins.test.ts \
        ./compat-tests/reference-server/contracts/query-binding-order.test.ts \
        ./compat-tests/reference-server/contracts/api-key-date-usage.test.ts \
        ./compat-tests/reference-server/contracts/paypal.test.ts \
        ./compat-tests/reference-server/contracts/wechat.test.ts \
        ./compat-tests/reference-server/contracts/social-http-providers.test.ts \
        ./compat-tests/reference-server/contracts/social-refresh-context.test.ts \
        ./compat-tests/reference-server/contracts/generic-profile-results.test.ts || account_status=1
      return "$account_status"
      ;;
    field-projection)
      cargo fmt --all -- --check
      local projection_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/schema-preflight-native-mapping.test.ts \
        ./compat-tests/reference-server/contracts/projection-error-lifecycle.test.ts \
        ./compat-tests/reference-server/contracts/team-projection-error-lifecycle.test.ts \
        ./compat-tests/reference-server/contracts/async-field-transforms.test.ts \
        ./compat-tests/reference-server/contracts/memory-user-live-reads.test.ts \
        ./compat-tests/reference-server/contracts/session-live-output.test.ts \
        ./compat-tests/reference-server/contracts/account-owner-batch.test.ts \
        ./compat-tests/reference-server/contracts/session-user-join-reference.test.ts \
        ./compat-tests/reference-server/contracts/organization-list-relations.test.ts \
        ./tests/fixtures/fallback-continuation-upstream.test.ts \
        ./tests/fixtures/organization-native-joins-upstream.test.ts \
        ./tests/fixtures/organization-join-continuation-upstream.test.ts || projection_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-seaorm -- -D warnings || projection_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test schema_preflight_tests --test query_binding_order_tests --test telemetry_options_tests \
        --test async_field_transform_tests --test account_owner_batch_tests \
        --test session_user_join_reference_tests --test organization_join_continuation_tests \
        --test fallback_continuation_tests --test organization_native_join_tests \
        --test organization_list_relations_tests --test relation_object_mutation_tests \
        -- -D warnings || projection_status=1
      cargo test --locked -p better-auth-core --lib -- \
        request_runtime::concurrent::tests:: organization_fields::tests:: user_fields:: \
        field_value::function::tests:: store::ephemeral::rows::object_tests:: \
        store::ephemeral::invitation_accept::tests:: \
        store::ephemeral::sessions::live_output_tests:: store::ephemeral::sessions::native_owner_tests:: \
        store::ephemeral::organization_joins:: store::secondary:: || projection_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test schema_preflight_tests --test query_binding_order_tests --test telemetry_options_tests \
        --test async_field_transform_tests \
        --test transform_batch_tests --test account_owner_batch_tests \
        --test session_user_join_reference_tests --test native_memory_join_tests \
        --test session_id_policy_tests --test session_create_payload_tests --test session_initial_defaults_tests \
        --test secondary_storage_hooks_tests --test transaction_hook_context_tests \
        --test transaction_effect_order_tests --test background_transaction_tests \
        --test fallback_continuation_tests --test organization_join_continuation_tests \
        --test organization_native_join_tests --test organization_list_relations_tests \
        --test relation_object_mutation_tests || projection_status=1
      cargo test --locked --features axum,seaorm2,redis-cache --test plugin_model_fields_tests -- \
        organization::team_member::joins:: organization::team_member::duplicate_ids:: \
        organization::team_member::details:: \
        organization::team_member::invitation_response::team_transaction:: || projection_status=1
      cargo test --locked --features axum,seaorm2,redis-cache --test schema_preflight_tests -- \
        --ignored --exact mysql::live_mysql_preflight_tracks_migrations_defaults_and_auto_increment \
        live_postgres_preflight_tracks_migrations_defaults_and_search_path || projection_status=1
      return "$projection_status"
      ;;
    schema-joins)
      local schema_join_status=0
      local declaration_targets=(
        --test openapi_model_presence_tests --test openapi_model_key_order_tests
        --test openapi_registered_fields_tests --test openapi_declaration_order_tests
        --test openapi_property_order_tests --test openapi_endpoint_key_order_tests
        --test openapi_rate_limit_model_tests --test openapi_verification_model_tests
        --test openapi_jwks_tests --test device_request_schema_tests
        --test user_account_raw_column_tests --test mysql_create_readback_tests
        --test sparse_native_join_tests --test passkey_additional_fields_tests
        --test plugin_model_fields_tests --test two_factor_additional_fields_tests
        --test legacy_schema_integration_tests
      )
      bun --no-install test \
        ./compat-tests/reference-server/contracts/schema-join-reference.test.ts \
        ./compat-tests/reference-server/contracts/sparse-native-joins.test.ts \
        ./compat-tests/reference-server/contracts/passkey-shared-display.test.ts \
        ./compat-tests/reference-server/contracts/two-factor-fields.test.ts \
        ./compat-tests/reference-server/contracts/model-alias-order.test.ts \
        ./compat-tests/reference-server/contracts/effective-organization-declarations.test.ts \
        ./compat-tests/reference-server/contracts/custom-model-join-reference.test.ts \
        ./compat-tests/reference-server/contracts/schema-join-reference-conflict.test.ts \
        ./compat-tests/reference-server/contracts/schema-join-reference-unknown.test.ts \
        ./compat-tests/reference-server/contracts/schema-join-reference-field.test.ts \
        ./compat-tests/reference-server/contracts/schema-join-reference-history.test.ts \
        ./compat-tests/reference-server/contracts/account-user-selected-relations.test.ts \
        ./compat-tests/reference-server/contracts/account-user-auth-boundary.test.ts \
        ./compat-tests/reference-server/contracts/account-user-auth-email.test.ts \
        ./compat-tests/reference-server/contracts/organization-member-join-reference.test.ts \
        ./compat-tests/reference-server/contracts/organization-member-singular-existing.test.ts \
        ./compat-tests/reference-server/contracts/organization-detail-dependencies.test.ts \
        ./compat-tests/reference-server/contracts/organization-list-relations.test.ts \
        ./compat-tests/reference-server/contracts/sql-relation-property.test.ts \
        ./compat-tests/reference-server/contracts/relation-object-mutation.test.ts \
        ./compat-tests/reference-server/contracts/openapi-model-presence.test.ts \
        ./compat-tests/reference-server/contracts/openapi-model-key-order.test.ts \
        ./compat-tests/reference-server/contracts/openapi-registered-fields.test.ts \
        ./compat-tests/reference-server/contracts/openapi-declaration-order.test.ts \
        ./compat-tests/reference-server/contracts/openapi-property-order.test.ts \
        ./compat-tests/reference-server/contracts/openapi-endpoint-key-order.test.ts \
        ./compat-tests/reference-server/contracts/openapi-rate-limit-model.test.ts \
        ./compat-tests/reference-server/contracts/openapi-verification-model.test.ts \
        ./compat-tests/reference-server/contracts/openapi-jwks.test.ts \
        ./compat-tests/reference-server/contracts/device-request-schema.test.ts \
        ./compat-tests/reference-server/contracts/user-account-raw-column.test.ts \
        ./compat-tests/reference-server/consumer-contracts/mysql-create-readback.test.ts || schema_join_status=1
      cargo fmt --all -- --check || schema_join_status=1
      cargo clippy --locked --keep-going -p better-auth-core -p better-auth-api -p better-auth-seaorm -- -D warnings || schema_join_status=1
      cargo clippy --locked --keep-going --features axum,seaorm2,redis-cache --test schema_join_reference_tests --test schema_preflight_tests --test effective_organization_declarations_tests --test model_alias_order_tests --test custom_model_join_reference_tests --test account_user_selected_relations_reference_tests --test account_user_auth_boundary_reference_tests --test account_user_signin_snapshot_tests --test nullable_user_update_tests --test cookie_cleanup_tests --test cookie_expires_tests --test cookie_http_errors_tests --test schema_join_reference_conflict_tests --test sql_relation_property_tests --test relation_object_mutation_tests --test organization_member_join_reference_tests --test organization_native_join_tests --test organization_serial_reference_tests --test organization_list_relations_tests "${declaration_targets[@]}" -- -D warnings || schema_join_status=1
      cargo test --locked --no-fail-fast -p better-auth-core -p better-auth-seaorm --lib -- entity::record_fields::tests:: store::record_write::tests:: openapi::tests:: field_value:: schema_value:: user_fields::record:: store::joins:: store::plugin_rows::native_snapshot_tests:: store::plugin_rows::legacy_private_tests:: store::ephemeral::rows::object_tests:: store::ephemeral::user_serial_tests:: serial_organization_lifecycle_binds_numbers_and_projects_public_ids memory_organization_deletion_preserves_teams_and_roles store::ephemeral::organization_joins::detail_dependencies_tests:: plugin_runtime::fields:: organization_fields:: reference_id::tests:: store::schema_preflight::roster_tests:: store::plugin_records::tests:: store::api_keys:: store::updates:: store::two_factor::record_tests:: store::passkeys::record_tests:: schema_history session::native::tests:: session::cookie_cache:: utils::cookie_utils:: || schema_join_status=1
      cargo test --locked --no-fail-fast -p better-auth-api --lib -- plugins::passkey:: plugins::helpers::session_tests:: plugins::jwt::tests:: plugins::oauth::signin:: || schema_join_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test schema_join_reference_tests --test join_binding_tests \
        --test model_alias_order_tests --test custom_model_join_reference_tests \
        --test effective_organization_declarations_tests \
        --test account_user_selected_relations_reference_tests --test account_user_auth_boundary_reference_tests --test account_user_signin_snapshot_tests \
        --test nullable_user_update_tests --test database_hook_updates_tests --test missing_user_transaction_tests \
        --test cookie_cleanup_tests --test cookie_expires_tests --test cookie_http_errors_tests \
        --test schema_join_reference_conflict_tests --test schema_preflight_tests \
        --test sql_relation_property_tests --test relation_object_mutation_tests --test organization_member_join_reference_tests \
        --test organization_native_join_tests --test organization_serial_reference_tests \
        --test organization_list_relations_tests \
        --test fallback_join_tests --test native_core_join_tests \
        --test native_memory_join_tests --test account_owner_batch_tests \
        "${declaration_targets[@]}" || schema_join_status=1
      cargo test --locked --features axum,seaorm2,redis-cache --test organization_native_join_tests -- \
        --ignored --exact postgres::live_postgres_full_organization_joins_decode_all_typed_children || schema_join_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test user_account_raw_column_tests --test mysql_create_readback_tests -- \
        --ignored || schema_join_status=1
      return "$schema_join_status"
      ;;
    passkey)
      cargo fmt --all -- --check
      local passkey_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/passkey-aaguid-fields.test.ts \
        ./compat-tests/reference-server/contracts/passkey-live-fields.test.ts \
        ./compat-tests/reference-server/contracts/passkey-display-mapping.test.ts \
        ./compat-tests/reference-server/contracts/passkey-fields.test.ts \
        ./compat-tests/reference-server/contracts/passkey-projected-id.test.ts \
        ./compat-tests/reference-server/contracts/passkey-update-boundary.test.ts \
        ./compat-tests/reference-server/contracts/passkey-native-errors-capture.test.ts || passkey_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm --lib -- -D warnings || passkey_status=1
      cargo test --locked --no-fail-fast -p better-auth-core -p better-auth-api -p better-auth-seaorm --lib -- \
        passkey plugins::helpers::session_tests:: || passkey_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache --test plugin_model_fields_tests --test plugin_list_limits_tests --test compat_passkey_tests --test passkey_additional_fields_tests --test two_factor_additional_fields_tests || passkey_status=1
      COMPAT_TEST_PROFILE=native-passkey cargo test --locked --test client_compat_tests -- \
        --ignored --nocapture --exact --test-threads=1 phase8_client_compat configuration_client_compat || passkey_status=1
      return "$passkey_status"
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
      local two_factor_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/two-factor-fields.test.ts \
        ./compat-tests/reference-server/contracts/two-factor-backup-code-native-capture.test.ts \
        ./compat-tests/reference-server/contracts/two-factor-backup-code-encoding-capture.test.ts \
        ./compat-tests/reference-server/contracts/two-factor-backup-generation-capture.test.ts || two_factor_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api -p better-auth-seaorm --lib -- -D warnings || two_factor_status=1
      cargo test --locked --no-fail-fast -p better-auth-core -p better-auth-api -p better-auth-seaorm --lib two_factor || two_factor_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test observability_tests --test two_factor_cookie_duration_tests --test two_factor_additional_fields_tests || two_factor_status=1
      COMPAT_TEST_PROFILE=native-two-factor cargo test --locked --test client_compat_tests -- \
        --ignored --nocapture --exact --test-threads=1 phase11_client_compat phase12_client_compat configuration_client_compat || two_factor_status=1
      return "$two_factor_status"
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
        ./compat-tests/reference-server/contracts/device-reference-declarations.test.ts \
        ./compat-tests/reference-server/contracts/device-ownership-references.test.ts \
        ./compat-tests/reference-server/contracts/device-query-id-state.test.ts \
        ./compat-tests/reference-server/contracts/adapter-query-id-alias.test.ts \
        ./compat-tests/reference-server/contracts/plugin-query-id-alias.test.ts \
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
      cargo clippy --locked -p better-auth-core --lib -- -D warnings
      cargo test --locked -p better-auth-core --lib -- store::ephemeral::jwks::id_slot_tests::
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
      ./scripts/consumer-check.sh --test generated_plugin_device device_grant -- --include-ignored
      ;;
    rate-limit-declarations)
      cargo fmt --all -- --check
      local rate_limit_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/rate-limit-http.test.ts \
        ./compat-tests/reference-server/contracts/rate-limit-declaration-priority.test.ts \
        ./compat-tests/reference-server/contracts/openapi-rate-limit-model.test.ts \
        ./compat-tests/reference-server/contracts/telemetry-rate-limit-model.test.ts \
        ./compat-tests/reference-server/contracts/session-jwk-wallet-rate-limit-serial.test.ts \
        ./compat-tests/reference-server/consumer-contracts/rate-limit-server-catalog.test.ts \
        ./compat-tests/reference-server/consumer-contracts/rate-limit-server-runtime.test.ts || rate_limit_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-seaorm -- -D warnings || rate_limit_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test rate_limit_database_tests --test rate_limit_options_tests --test rate_cleanup_background_tests \
        --test openapi_rate_limit_model_tests --test telemetry_options_tests -- -D warnings || rate_limit_status=1
      cargo test --locked -p better-auth-core --lib -- \
        plugin_runtime::fields:: middleware::rate_limit:: \
        store::ephemeral::serial_primary_tests::session_plugins:: \
        store::ephemeral::transactions:: || rate_limit_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test rate_limit_database_tests --test rate_limit_options_tests --test rate_cleanup_background_tests \
        --test openapi_rate_limit_model_tests --test telemetry_options_tests || rate_limit_status=1
      ./scripts/consumer-check.sh --lib --test generated_core_declarations --test generated_server_keys -- \
        rate_limit --include-ignored || rate_limit_status=1
      return "$rate_limit_status"
      ;;
    validation-errors)
      cargo fmt --all -- --check
      local validation_status=0
      bun --no-install test \
        ./compat-tests/reference-server/contracts/error-construction.test.ts \
        ./compat-tests/reference-server/contracts/device-request-validation.test.ts \
        ./compat-tests/reference-server/contracts/user-input-policy.test.ts || validation_status=1
      cargo clippy --locked -p better-auth-core -p better-auth-api -- -D warnings || validation_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache \
        --test required_headers_tests --test device_request_validation_tests \
        --test organization_body_schema_tests --test user_input_policy_tests --test protected_function_tests -- -D warnings || validation_status=1
      cargo test --locked -p better-auth-core --lib -- \
        error:: query:: http_body:: user_fields::organization::tests:: plugin::tests::async_body_dispatch:: \
        plugin::tests::response_status:: plugin::tests::response_values:: || validation_status=1
      cargo test --locked -p better-auth-api --lib -- \
        plugins::oauth::signin::error_tests:: || validation_status=1
      cargo test --locked --no-fail-fast --features axum,seaorm2,redis-cache \
        --test required_headers_tests --test device_request_validation_tests \
        --test organization_body_schema_tests --test user_input_policy_tests --test protected_function_tests || validation_status=1
      return "$validation_status"
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
      local provider_status=0
      cargo clippy --locked -p better-auth-api --features axum -- -D warnings || provider_status=1
      cargo clippy --locked --features axum,seaorm2,redis-cache --test oauth_token_duration_tests -- -D warnings || provider_status=1
      cargo test --locked -p better-auth-api --features axum --lib -- \
        plugins::oauth::google_client_ids_tests:: \
        plugins::oauth::verifier_context_tests:: \
        plugins::oauth::gitlab_issuer_tests:: \
        plugins::oauth::microsoft_tests:: \
        plugins::oauth::apple_tests:: \
        plugins::oauth::apple_flow_tests:: \
        plugins::oauth::tiktok_tests:: \
        plugins::oauth::provider_tokens:: \
        plugins::oauth::state::raw_state_tests:: \
        plugins::oauth::providers::twitch::tests:: \
        plugins::oauth::signin::override_tests:: \
        plugins::oauth::generic_profile::result_tests:: || provider_status=1
      cargo test --locked -p better-auth-api --features axum \
        --no-fail-fast --test account_oauth_tests --test oauth_session_revocation_tests || provider_status=1
      cargo test --locked --test social_refresh_context_tests || provider_status=1
      cargo test --locked --features axum,seaorm2,redis-cache --test oauth_token_duration_tests || provider_status=1
      cargo test --locked --test telemetry_options_tests || provider_status=1
      cargo check --locked --manifest-path compat-tests/rust-server/Cargo.toml || provider_status=1
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
        ./compat-tests/reference-server/contracts/generic-profile-results.test.ts || provider_status=1
      return "$provider_status"
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
