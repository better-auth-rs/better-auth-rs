#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
schema_dir=$(mktemp -d)
trap 'rm -rf "$schema_dir"' EXIT

cargo build --locked -p better-auth-cli --bin better-auth-rs --message-format=json-render-diagnostics > "$schema_dir/cli-artifacts.jsonl"
consumer_cli=$(python3 - "$schema_dir/cli-artifacts.jsonl" <<'PY'
import json
from pathlib import Path
import sys

manifest = str(Path("crates/cli/Cargo.toml").resolve())
executables = []
with Path(sys.argv[1]).open() as artifacts:
    for line in artifacts:
        message = json.loads(line)
        if (message.get("reason") == "compiler-artifact"
                and message["manifest_path"] == manifest
                and message["target"]["name"] == "better-auth-rs"
                and "bin" in message["target"]["kind"]
                and message["executable"] is not None):
            executables.append(message["executable"])
if len(executables) != 1:
    raise SystemExit("Cargo must report exactly one better-auth-rs executable")
print(executables[0])
PY
)

"$consumer_cli" generate --plugins all --output "$schema_dir/auth_schema.rs"
export BETTER_AUTH_GENERATED_SCHEMA="$schema_dir/auth_schema.rs"
"$consumer_cli" generate --plugins organization --schema-config compat-tests/schema-consumer/organization-schema.json --output "$schema_dir/organization_schema.rs"
export BETTER_AUTH_ORGANIZATION_SCHEMA="$schema_dir/organization_schema.rs"
"$consumer_cli" generate --plugins organization --database sqlite --schema-config compat-tests/schema-consumer/sqlite-json-schema.json --output "$schema_dir/sqlite_json_schema.rs"
export BETTER_AUTH_SQLITE_JSON_SCHEMA="$schema_dir/sqlite_json_schema.rs"
"$consumer_cli" generate --plugins all --schema-config compat-tests/schema-consumer/plugin-schema.json --output "$schema_dir/plugin_schema.rs"
export BETTER_AUTH_PLUGIN_SCHEMA="$schema_dir/plugin_schema.rs"
"$consumer_cli" generate --plugins jwt --schema-config compat-tests/schema-consumer/jwk-fields-schema.json --output "$schema_dir/jwk_fields_schema.rs"
export BETTER_AUTH_JWK_FIELDS_SCHEMA="$schema_dir/jwk_fields_schema.rs"
"$consumer_cli" generate --plugins siwe --schema-config compat-tests/schema-consumer/wallet-fields-schema.json --output "$schema_dir/wallet_fields_schema.rs"
export BETTER_AUTH_WALLET_FIELDS_SCHEMA="$schema_dir/wallet_fields_schema.rs"
"$consumer_cli" generate --plugins organization --schema-config compat-tests/schema-consumer/dynamic-schema.json --output "$schema_dir/dynamic_schema.rs"
export BETTER_AUTH_DYNAMIC_SCHEMA="$schema_dir/dynamic_schema.rs"
"$consumer_cli" generate --plugins organization --schema-config compat-tests/schema-consumer/field-attributes-schema.json --output "$schema_dir/field_attributes_schema.rs"
export BETTER_AUTH_FIELD_ATTRIBUTES_SCHEMA="$schema_dir/field_attributes_schema.rs"
"$consumer_cli" generate --rate-limit-database --schema-config compat-tests/schema-consumer/rate-limit-schema.json --output "$schema_dir/rate_limit_schema.rs"
export BETTER_AUTH_RATE_LIMIT_SCHEMA="$schema_dir/rate_limit_schema.rs"
"$consumer_cli" generate --schema-config compat-tests/schema-consumer/account-verification-schema.json --output "$schema_dir/account_verification_schema.rs"
export BETTER_AUTH_ACCOUNT_VERIFICATION_SCHEMA="$schema_dir/account_verification_schema.rs"
"$consumer_cli" generate --schema-config compat-tests/schema-consumer/user-session-fields-schema.json --output "$schema_dir/user_session_fields_schema.rs"
export BETTER_AUTH_USER_SESSION_FIELDS_SCHEMA="$schema_dir/user_session_fields_schema.rs"
python3 - "$schema_dir" <<'PY'
import json
import pathlib
import sys

fixture = json.loads(pathlib.Path("tests/fixtures/telemetry-model-declarations-1.7.6.json").read_text())
for name, case in fixture.items():
    (pathlib.Path(sys.argv[1]) / f"declarations_{name}.json").write_text(json.dumps(case["options"]))
rate_limits = json.loads(pathlib.Path("tests/fixtures/telemetry-rate-limit-model-1.7.6.json").read_text())
for name, case in rate_limits.items():
    (pathlib.Path(sys.argv[1]) / f"rate_model_{name}.json").write_text(json.dumps(case["options"]))
verification_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/verification-catalog-config.json").read_text())
for name, configuration in verification_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"verification_catalog_{name}.json").write_text(json.dumps(configuration))
jwk_rate_limit_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/jwk-rate-limit-catalog-config.json").read_text())
for name, configuration in jwk_rate_limit_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"jwk_rate_limit_catalog_{name}.json").write_text(json.dumps(configuration))
user_account_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/user-account-catalog-config.json").read_text())
for name, configuration in user_account_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"user_account_catalog_{name}.json").write_text(json.dumps(configuration))
session_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/session-catalog-config.json").read_text())
for name, configuration in session_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"session_catalog_{name}.json").write_text(json.dumps(configuration))
member_organization_role_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/member-organization-role-catalog-config.json").read_text())
for name, configuration in member_organization_role_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"member_organization_role_catalog_{name}.json").write_text(json.dumps(configuration))
team_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/team-catalog-config.json").read_text())
for name, configuration in team_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"team_catalog_{name}.json").write_text(json.dumps(configuration))
invitation_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/invitation-catalog-config.json").read_text())
for name, configuration in invitation_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"invitation_catalog_{name}.json").write_text(json.dumps(configuration))
PY
for case in default legacy customLong; do
  "$consumer_cli" generate --database sqlite --schema-config "$schema_dir/verification_catalog_${case}.json" --output "$schema_dir/verification_catalog_${case}.rs"
done
export BETTER_AUTH_VERIFICATION_CATALOG_DEFAULT_SCHEMA="$schema_dir/verification_catalog_default.rs"
export BETTER_AUTH_VERIFICATION_CATALOG_LEGACY_SCHEMA="$schema_dir/verification_catalog_legacy.rs"
export BETTER_AUTH_VERIFICATION_CATALOG_CUSTOM_SCHEMA="$schema_dir/verification_catalog_customLong.rs"
for case in default legacy custom; do
  "$consumer_cli" generate --plugins jwt --rate-limit-database --database sqlite --schema-config "$schema_dir/jwk_rate_limit_catalog_${case}.json" --output "$schema_dir/jwk_rate_limit_catalog_${case}.rs"
done
export BETTER_AUTH_JWK_RATE_LIMIT_CATALOG_DEFAULT_SCHEMA="$schema_dir/jwk_rate_limit_catalog_default.rs"
export BETTER_AUTH_JWK_RATE_LIMIT_CATALOG_LEGACY_SCHEMA="$schema_dir/jwk_rate_limit_catalog_legacy.rs"
export BETTER_AUTH_JWK_RATE_LIMIT_CATALOG_CUSTOM_SCHEMA="$schema_dir/jwk_rate_limit_catalog_custom.rs"
for case in default legacy custom; do
  "$consumer_cli" generate --database sqlite --schema-config "$schema_dir/user_account_catalog_${case}.json" --output "$schema_dir/user_account_catalog_${case}.rs"
done
export BETTER_AUTH_USER_ACCOUNT_CATALOG_DEFAULT_SCHEMA="$schema_dir/user_account_catalog_default.rs"
export BETTER_AUTH_USER_ACCOUNT_CATALOG_LEGACY_SCHEMA="$schema_dir/user_account_catalog_legacy.rs"
export BETTER_AUTH_USER_ACCOUNT_CATALOG_CUSTOM_SCHEMA="$schema_dir/user_account_catalog_custom.rs"
for case in default legacy custom; do
  "$consumer_cli" generate --database sqlite --schema-config "$schema_dir/session_catalog_${case}.json" --output "$schema_dir/session_catalog_${case}.rs"
done
export BETTER_AUTH_SESSION_CATALOG_DEFAULT_SCHEMA="$schema_dir/session_catalog_default.rs"
export BETTER_AUTH_SESSION_CATALOG_LEGACY_SCHEMA="$schema_dir/session_catalog_legacy.rs"
export BETTER_AUTH_SESSION_CATALOG_CUSTOM_SCHEMA="$schema_dir/session_catalog_custom.rs"
for case in default legacy custom; do
  "$consumer_cli" generate --plugins organization --database sqlite --schema-config "$schema_dir/member_organization_role_catalog_${case}.json" --output "$schema_dir/member_organization_role_catalog_${case}.rs"
done
export BETTER_AUTH_MEMBER_ORGANIZATION_ROLE_CATALOG_DEFAULT_SCHEMA="$schema_dir/member_organization_role_catalog_default.rs"
export BETTER_AUTH_MEMBER_ORGANIZATION_ROLE_CATALOG_LEGACY_SCHEMA="$schema_dir/member_organization_role_catalog_legacy.rs"
export BETTER_AUTH_MEMBER_ORGANIZATION_ROLE_CATALOG_CUSTOM_SCHEMA="$schema_dir/member_organization_role_catalog_custom.rs"
for case in default legacy custom; do
  "$consumer_cli" generate --plugins organization --database sqlite --schema-config "$schema_dir/team_catalog_${case}.json" --output "$schema_dir/team_catalog_${case}.rs"
done
export BETTER_AUTH_TEAM_CATALOG_DEFAULT_SCHEMA="$schema_dir/team_catalog_default.rs"
export BETTER_AUTH_TEAM_CATALOG_LEGACY_SCHEMA="$schema_dir/team_catalog_legacy.rs"
export BETTER_AUTH_TEAM_CATALOG_CUSTOM_SCHEMA="$schema_dir/team_catalog_custom.rs"
for case in default legacy custom; do
  "$consumer_cli" generate --plugins organization --database sqlite --schema-config "$schema_dir/invitation_catalog_${case}.json" --output "$schema_dir/invitation_catalog_${case}.rs"
done
export BETTER_AUTH_INVITATION_CATALOG_DEFAULT_SCHEMA="$schema_dir/invitation_catalog_default.rs"
export BETTER_AUTH_INVITATION_CATALOG_LEGACY_SCHEMA="$schema_dir/invitation_catalog_legacy.rs"
export BETTER_AUTH_INVITATION_CATALOG_CUSTOM_SCHEMA="$schema_dir/invitation_catalog_custom.rs"
for case in omitted empty explicitDefaults renamed; do
  "$consumer_cli" generate --schema-config "$schema_dir/declarations_${case}.json" --output "$schema_dir/declarations_${case}.rs"
done
export BETTER_AUTH_DECLARATIONS_OMITTED_SCHEMA="$schema_dir/declarations_omitted.rs"
export BETTER_AUTH_DECLARATIONS_EMPTY_SCHEMA="$schema_dir/declarations_empty.rs"
export BETTER_AUTH_DECLARATIONS_DEFAULTS_SCHEMA="$schema_dir/declarations_explicitDefaults.rs"
export BETTER_AUTH_DECLARATIONS_RENAMED_SCHEMA="$schema_dir/declarations_renamed.rs"
for case in omitted empty explicitDefaults renamed; do
  "$consumer_cli" generate --rate-limit-database --schema-config "$schema_dir/rate_model_${case}.json" --output "$schema_dir/rate_model_${case}.rs"
done
export BETTER_AUTH_RATE_MODEL_OMITTED_SCHEMA="$schema_dir/rate_model_omitted.rs"
export BETTER_AUTH_RATE_MODEL_EMPTY_SCHEMA="$schema_dir/rate_model_empty.rs"
export BETTER_AUTH_RATE_MODEL_DEFAULTS_SCHEMA="$schema_dir/rate_model_explicitDefaults.rs"
export BETTER_AUTH_RATE_MODEL_RENAMED_SCHEMA="$schema_dir/rate_model_renamed.rs"
for mode in serial uuid database; do
  "$consumer_cli" generate --plugins all --generate-id "$mode" --schema-config compat-tests/schema-consumer/id-schema.json --output "$schema_dir/${mode}_schema.rs"
done
export BETTER_AUTH_SERIAL_SCHEMA="$schema_dir/serial_schema.rs"
export BETTER_AUTH_UUID_SCHEMA="$schema_dir/uuid_schema.rs"
export BETTER_AUTH_DATABASE_SCHEMA="$schema_dir/database_schema.rs"
"$consumer_cli" generate --plugins all --generate-id uuid --database postgres --schema-config compat-tests/schema-consumer/id-schema.json --output "$schema_dir/postgres_uuid_schema.rs"
export BETTER_AUTH_POSTGRES_UUID_SCHEMA="$schema_dir/postgres_uuid_schema.rs"
"$consumer_cli" generate --plugins all --generate-id serial --database postgres --schema-config compat-tests/schema-consumer/id-schema.json --output "$schema_dir/postgres_serial_schema.rs"
export BETTER_AUTH_POSTGRES_SERIAL_SCHEMA="$schema_dir/postgres_serial_schema.rs"

# Stable include paths preserve Cargo fingerprints when generated contents are unchanged.
generated_dir="$PWD/compat-tests/schema-consumer/target/generated-schemas"
mkdir -p "$generated_dir"
for schema in "$schema_dir"/*.rs; do
  destination="$generated_dir/${schema##*/}"
  if [[ -f "$destination" ]]; then
    if cmp -s "$schema" "$destination"; then
      continue
    else
      comparison_status=$?
      if [[ $comparison_status -ne 1 ]]; then
        printf 'Cannot compare generated schema: %s\n' "$destination" >&2
        exit "$comparison_status"
      fi
    fi
  fi
  cp "$schema" "$destination"
done
for variable in "${!BETTER_AUTH_@}"; do
  schema_path="${!variable}"
  if [[ "$schema_path" == "$schema_dir/"*.rs ]]; then
    export "$variable=$generated_dir/${schema_path##*/}"
  fi
done

cargo fmt --manifest-path compat-tests/schema-consumer/Cargo.toml -- --check
if [[ $# -eq 0 ]]; then
  cargo clippy --locked --manifest-path compat-tests/schema-consumer/Cargo.toml --all-targets -- -D warnings
fi
# Forward Cargo arguments. Focused runs omit all-target Clippy and external runtime checks.
cargo test --locked --manifest-path compat-tests/schema-consumer/Cargo.toml "$@"
if [[ $# -eq 0 ]]; then
  cargo build --locked --manifest-path compat-tests/schema-consumer/Cargo.toml --example user_timestamp_interchange --message-format=json > "$schema_dir/user_timestamp_artifacts.jsonl"
  BETTER_AUTH_TIMESTAMP_ARTIFACTS="$schema_dir/user_timestamp_artifacts.jsonl" bun --no-install test ./compat-tests/reference-server/consumer-contracts/user-timestamp-interchange.test.ts
fi
if [[ $# -eq 0 && -n "${BETTER_AUTH_TEST_POSTGRES_URL:-}" ]]; then
  cargo test --locked --manifest-path compat-tests/schema-consumer/Cargo.toml tests::ids::live_postgres_generated_ids -- --ignored --exact
  cargo test --locked --features axum,seaorm2,redis-cache --test legacy_schema_integration_tests --test schema_preflight_tests --test plugin_model_fields_tests --test device_additional_fields_tests --test default_find_many_limit_tests --test native_core_join_tests --test organization_native_join_tests live_postgres -- --ignored
fi
