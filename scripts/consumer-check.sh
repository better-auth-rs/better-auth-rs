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

# Existing ID/reference consumers own the legacy API Key, DeviceCode, Passkey, and TwoFactor schemas; fresh schemas have separate contracts.
"$consumer_cli" generate --plugins all --api-key-legacy-schema --device-code-legacy-schema --passkey-legacy-schema --two-factor-legacy-schema --output "$schema_dir/auth_schema.rs"
export BETTER_AUTH_GENERATED_SCHEMA="$schema_dir/auth_schema.rs"
"$consumer_cli" generate --plugins organization --schema-config compat-tests/schema-consumer/organization-schema.json --output "$schema_dir/organization_schema.rs"
export BETTER_AUTH_ORGANIZATION_SCHEMA="$schema_dir/organization_schema.rs"
"$consumer_cli" generate --plugins organization --database sqlite --schema-config compat-tests/schema-consumer/sqlite-json-schema.json --output "$schema_dir/sqlite_json_schema.rs"
export BETTER_AUTH_SQLITE_JSON_SCHEMA="$schema_dir/sqlite_json_schema.rs"
"$consumer_cli" generate --plugins all --api-key-legacy-schema --device-code-legacy-schema --passkey-legacy-schema --two-factor-legacy-schema --schema-config compat-tests/schema-consumer/plugin-schema.json --output "$schema_dir/plugin_schema.rs"
export BETTER_AUTH_PLUGIN_SCHEMA="$schema_dir/plugin_schema.rs"
for required in required optional; do
  schema="$schema_dir/api_key_number_name_${required}.rs"
  "$consumer_cli" generate --plugins api-key --database sqlite --schema-config "compat-tests/schema-consumer/api-key-number-name-${required}-schema.json" --output "$schema"
  export "BETTER_AUTH_API_KEY_NUMBER_NAME_${required^^}_SCHEMA=$schema"
done
python3 - "$schema_dir" <<'PY_REPLACEMENTS'
import json
from pathlib import Path
import sys

fixture = json.loads(Path("tests/fixtures/native-plugin-replacements-sqlite-1.7.6.json").read_text())
for target in fixture["targets"]:
    if target["model"] not in ("apikey", "passkey", "deviceCode", "twoFactor", "jwks", "walletAddress"):
        continue
    fields = {
        target["field"]: {"type": target["type"], "required": False, "fieldName": target["column"]},
        "marker": {"type": "string", "required": False, "fieldName": "stored_marker"},
    }
    config = {target["model"]: {"modelName": target["table"], "additionalFields": fields}}
    (Path(sys.argv[1]) / ("native_replacement_" + target["name"] + ".json")).write_text(json.dumps(config))
PY_REPLACEMENTS
for configuration in "$schema_dir"/native_replacement_*.json; do
  target="${configuration##*/native_replacement_}"
  target="${target%.json}"
  plugin=api-key
  if [[ "$target" == passkey-* ]]; then
    plugin=passkey
  elif [[ "$target" == device-* ]]; then
    plugin=device-authorization
  elif [[ "$target" == two-factor-* ]]; then
    plugin=two-factor
  elif [[ "$target" == jwk-* ]]; then
    plugin=jwt
  elif [[ "$target" == wallet-* ]]; then
    plugin=siwe
  fi
  schema="$schema_dir/native_replacement_${target}.rs"
  "$consumer_cli" generate --plugins "$plugin" --database sqlite --schema-config "$configuration" --output "$schema"
  variable="BETTER_AUTH_NATIVE_REPLACEMENT_${target^^}_SCHEMA"
  export "${variable//-/_}=$schema"
done
for order in forward reversed; do
  schema="$schema_dir/passkey_shared_display_${order}.rs"
  "$consumer_cli" generate --plugins passkey --database sqlite --schema-config "compat-tests/schema-consumer/passkey-shared-display-${order}-schema.json" --output "$schema"
  export "BETTER_AUTH_PASSKEY_SHARED_DISPLAY_${order^^}_SCHEMA=$schema"
done
for backend in sqlite postgres mysql; do
  schema="$schema_dir/native_api_key_${backend}.rs"
  "$consumer_cli" generate --plugins api-key --database "$backend" --output "$schema"
  export "BETTER_AUTH_NATIVE_API_KEY_${backend^^}_SCHEMA=$schema"
  for display in api-key-name passkey-name passkey-aaguid; do
    plugin=passkey
    if [[ "$display" == api-key-name ]]; then
      plugin=api-key
    fi
    schema="$schema_dir/display_json_${backend}_${display//-/_}.rs"
    "$consumer_cli" generate --plugins "$plugin" --database "$backend" --schema-config "compat-tests/schema-consumer/plugin-display-json-${display}-schema.json" --output "$schema"
    variable="BETTER_AUTH_DISPLAY_JSON_${backend^^}_${display^^}_SCHEMA"
    export "${variable//-/_}=$schema"
  done
done
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
device_code_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/device-code-catalog-config.json").read_text())
for name, configuration in device_code_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"device_code_catalog_{name}.json").write_text(json.dumps(configuration))
wallet_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/wallet-address-catalog-config.json").read_text())
for name, configuration in wallet_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"wallet_catalog_{name}.json").write_text(json.dumps(configuration))
passkey_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/passkey-catalog-config.json").read_text())
for name, configuration in passkey_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"passkey_catalog_{name}.json").write_text(json.dumps(configuration))
two_factor_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/two-factor-catalog-config.json").read_text())
for name, configuration in two_factor_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"two_factor_catalog_{name}.json").write_text(json.dumps(configuration))
jwk_rate_limit_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/jwk-rate-limit-catalog-config.json").read_text())
for name, configuration in jwk_rate_limit_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"jwk_rate_limit_catalog_{name}.json").write_text(json.dumps(configuration))
for name in ("default", "custom"):
    configuration = jwk_rate_limit_catalog[name]
    jwks = {"jwks": configuration["jwks"]} if "jwks" in configuration else {}
    (pathlib.Path(sys.argv[1]) / f"jwk_server_{name}.json").write_text(json.dumps(jwks))
    rate_limit = {"rateLimit": configuration["rateLimit"]} if "rateLimit" in configuration else {}
    (pathlib.Path(sys.argv[1]) / f"rate_limit_server_{name}.json").write_text(json.dumps(rate_limit))
user_account_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/user-account-catalog-config.json").read_text())
for name, configuration in user_account_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"user_account_catalog_{name}.json").write_text(json.dumps(configuration))
session_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/session-catalog-config.json").read_text())
for name, configuration in session_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"session_catalog_{name}.json").write_text(json.dumps(configuration))
member_organization_role_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/member-organization-role-catalog-config.json").read_text())
for name, configuration in member_organization_role_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"member_organization_role_catalog_{name}.json").write_text(json.dumps(configuration))
configuration = member_organization_role_catalog["custom"]
member = {key: configuration[key] for key in ("user", "organization", "member") if key in configuration}
(pathlib.Path(sys.argv[1]) / "member_server_custom.json").write_text(json.dumps(member))
organization_role = {key: configuration[key] for key in ("user", "organization", "member", "organizationRole") if key in configuration}
(pathlib.Path(sys.argv[1]) / "organization_role_server_custom.json").write_text(json.dumps(organization_role))
team_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/team-catalog-config.json").read_text())
for name, configuration in team_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"team_catalog_{name}.json").write_text(json.dumps(configuration))
configuration = team_catalog["custom"]
team = {key: configuration[key] for key in ("user", "organization", "team") if key in configuration}
(pathlib.Path(sys.argv[1]) / "team_server_custom.json").write_text(json.dumps(team))
invitation_catalog = json.loads(pathlib.Path("compat-tests/schema-consumer/invitation-catalog-config.json").read_text())
for name, configuration in invitation_catalog.items():
    (pathlib.Path(sys.argv[1]) / f"invitation_catalog_{name}.json").write_text(json.dumps(configuration))
configuration = invitation_catalog["custom"]
invitation = {key: configuration[key] for key in ("user", "organization", "invitation") if key in configuration}
(pathlib.Path(sys.argv[1]) / "invitation_server_custom.json").write_text(json.dumps(invitation))
PY
for case in default legacy customLong; do
  "$consumer_cli" generate --database sqlite --schema-config "$schema_dir/verification_catalog_${case}.json" --output "$schema_dir/verification_catalog_${case}.rs"
done
export BETTER_AUTH_VERIFICATION_CATALOG_DEFAULT_SCHEMA="$schema_dir/verification_catalog_default.rs"
export BETTER_AUTH_VERIFICATION_CATALOG_LEGACY_SCHEMA="$schema_dir/verification_catalog_legacy.rs"
export BETTER_AUTH_VERIFICATION_CATALOG_CUSTOM_SCHEMA="$schema_dir/verification_catalog_customLong.rs"
for case in default legacy custom; do
  "$consumer_cli" generate --plugins device-authorization --database sqlite --schema-config "$schema_dir/device_code_catalog_${case}.json" --output "$schema_dir/device_code_sqlite_${case}.rs"
done
export BETTER_AUTH_DEVICE_CODE_SQLITE_DEFAULT_SCHEMA="$schema_dir/device_code_sqlite_default.rs"
export BETTER_AUTH_DEVICE_CODE_SQLITE_LEGACY_SCHEMA="$schema_dir/device_code_sqlite_legacy.rs"
export BETTER_AUTH_DEVICE_CODE_SQLITE_CUSTOM_SCHEMA="$schema_dir/device_code_sqlite_custom.rs"
"$consumer_cli" generate --plugins device-authorization --database sqlite --generate-id serial --output "$schema_dir/device_code_sqlite_serial.rs"
export BETTER_AUTH_DEVICE_CODE_SQLITE_SERIAL_SCHEMA="$schema_dir/device_code_sqlite_serial.rs"
for backend in postgres mysql; do
  for case in default custom; do
    "$consumer_cli" generate --plugins device-authorization --database "$backend" --schema-config "$schema_dir/device_code_catalog_${case}.json" --output "$schema_dir/device_code_${backend}_${case}.rs"
  done
done
export BETTER_AUTH_DEVICE_CODE_POSTGRES_DEFAULT_SCHEMA="$schema_dir/device_code_postgres_default.rs"
export BETTER_AUTH_DEVICE_CODE_POSTGRES_CUSTOM_SCHEMA="$schema_dir/device_code_postgres_custom.rs"
export BETTER_AUTH_DEVICE_CODE_MYSQL_DEFAULT_SCHEMA="$schema_dir/device_code_mysql_default.rs"
export BETTER_AUTH_DEVICE_CODE_MYSQL_CUSTOM_SCHEMA="$schema_dir/device_code_mysql_custom.rs"
for case in default legacy custom; do
  "$consumer_cli" generate --plugins siwe --database sqlite --schema-config "$schema_dir/wallet_catalog_${case}.json" --output "$schema_dir/wallet_sqlite_${case}.rs"
done
export BETTER_AUTH_WALLET_SQLITE_DEFAULT_SCHEMA="$schema_dir/wallet_sqlite_default.rs"
export BETTER_AUTH_WALLET_SQLITE_LEGACY_SCHEMA="$schema_dir/wallet_sqlite_legacy.rs"
export BETTER_AUTH_WALLET_SQLITE_CUSTOM_SCHEMA="$schema_dir/wallet_sqlite_custom.rs"
for backend in postgres mysql; do
  for case in default custom; do
    "$consumer_cli" generate --plugins siwe --database "$backend" --schema-config "$schema_dir/wallet_catalog_${case}.json" --output "$schema_dir/wallet_${backend}_${case}.rs"
  done
done
export BETTER_AUTH_WALLET_POSTGRES_DEFAULT_SCHEMA="$schema_dir/wallet_postgres_default.rs"
export BETTER_AUTH_WALLET_POSTGRES_CUSTOM_SCHEMA="$schema_dir/wallet_postgres_custom.rs"
export BETTER_AUTH_WALLET_MYSQL_DEFAULT_SCHEMA="$schema_dir/wallet_mysql_default.rs"
export BETTER_AUTH_WALLET_MYSQL_CUSTOM_SCHEMA="$schema_dir/wallet_mysql_custom.rs"
for case in default legacy custom; do
  "$consumer_cli" generate --plugins passkey --database sqlite --schema-config "$schema_dir/passkey_catalog_${case}.json" --output "$schema_dir/passkey_sqlite_${case}.rs"
done
export BETTER_AUTH_PASSKEY_SQLITE_DEFAULT_SCHEMA="$schema_dir/passkey_sqlite_default.rs"
export BETTER_AUTH_PASSKEY_SQLITE_LEGACY_SCHEMA="$schema_dir/passkey_sqlite_legacy.rs"
export BETTER_AUTH_PASSKEY_SQLITE_CUSTOM_SCHEMA="$schema_dir/passkey_sqlite_custom.rs"
for backend in postgres mysql; do
  for case in default custom; do
    "$consumer_cli" generate --plugins passkey --database "$backend" --schema-config "$schema_dir/passkey_catalog_${case}.json" --output "$schema_dir/passkey_${backend}_${case}.rs"
  done
done
export BETTER_AUTH_PASSKEY_POSTGRES_DEFAULT_SCHEMA="$schema_dir/passkey_postgres_default.rs"
export BETTER_AUTH_PASSKEY_POSTGRES_CUSTOM_SCHEMA="$schema_dir/passkey_postgres_custom.rs"
export BETTER_AUTH_PASSKEY_MYSQL_DEFAULT_SCHEMA="$schema_dir/passkey_mysql_default.rs"
export BETTER_AUTH_PASSKEY_MYSQL_CUSTOM_SCHEMA="$schema_dir/passkey_mysql_custom.rs"
for case in default legacy custom; do
  "$consumer_cli" generate --plugins two-factor --database sqlite --schema-config "$schema_dir/two_factor_catalog_${case}.json" --output "$schema_dir/two_factor_sqlite_${case}.rs"
done
export BETTER_AUTH_TWO_FACTOR_SQLITE_DEFAULT_SCHEMA="$schema_dir/two_factor_sqlite_default.rs"
export BETTER_AUTH_TWO_FACTOR_SQLITE_LEGACY_SCHEMA="$schema_dir/two_factor_sqlite_legacy.rs"
export BETTER_AUTH_TWO_FACTOR_SQLITE_CUSTOM_SCHEMA="$schema_dir/two_factor_sqlite_custom.rs"
for backend in postgres mysql; do
  for case in default custom; do
    "$consumer_cli" generate --plugins two-factor --database "$backend" --schema-config "$schema_dir/two_factor_catalog_${case}.json" --output "$schema_dir/two_factor_${backend}_${case}.rs"
  done
done
export BETTER_AUTH_TWO_FACTOR_POSTGRES_DEFAULT_SCHEMA="$schema_dir/two_factor_postgres_default.rs"
export BETTER_AUTH_TWO_FACTOR_POSTGRES_CUSTOM_SCHEMA="$schema_dir/two_factor_postgres_custom.rs"
export BETTER_AUTH_TWO_FACTOR_MYSQL_DEFAULT_SCHEMA="$schema_dir/two_factor_mysql_default.rs"
export BETTER_AUTH_TWO_FACTOR_MYSQL_CUSTOM_SCHEMA="$schema_dir/two_factor_mysql_custom.rs"
"$consumer_cli" generate --plugins two-factor --schema-config compat-tests/schema-consumer/two-factor-fields-schema.json --output "$schema_dir/two_factor_fields.rs"
export BETTER_AUTH_TWO_FACTOR_FIELDS_SCHEMA="$schema_dir/two_factor_fields.rs"
"$consumer_cli" generate --plugins passkey --schema-config compat-tests/schema-consumer/passkey-fields-schema.json --output "$schema_dir/passkey_fields.rs"
export BETTER_AUTH_PASSKEY_FIELDS_SCHEMA="$schema_dir/passkey_fields.rs"
for backend in sqlite postgres mysql; do
  schema="$schema_dir/api_key_fields_${backend}.rs"
  "$consumer_cli" generate --plugins api-key --database "$backend" --schema-config compat-tests/schema-consumer/api-key-fields-schema.json --output "$schema"
  export "BETTER_AUTH_API_KEY_FIELDS_${backend^^}_SCHEMA=$schema"
  schema="$schema_dir/device_grant_${backend}.rs"
  "$consumer_cli" generate --plugins device-authorization --database "$backend" --schema-config compat-tests/schema-consumer/device-grant-schema.json --output "$schema"
  export "BETTER_AUTH_DEVICE_GRANT_${backend^^}_SCHEMA=$schema"
done
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
  "$consumer_cli" generate --plugins all --api-key-legacy-schema --device-code-legacy-schema --passkey-legacy-schema --two-factor-legacy-schema --generate-id "$mode" --schema-config compat-tests/schema-consumer/id-schema.json --output "$schema_dir/${mode}_schema.rs"
done
export BETTER_AUTH_SERIAL_SCHEMA="$schema_dir/serial_schema.rs"
export BETTER_AUTH_UUID_SCHEMA="$schema_dir/uuid_schema.rs"
export BETTER_AUTH_DATABASE_SCHEMA="$schema_dir/database_schema.rs"
"$consumer_cli" generate --plugins all --api-key-legacy-schema --device-code-legacy-schema --passkey-legacy-schema --two-factor-legacy-schema --generate-id uuid --database postgres --schema-config compat-tests/schema-consumer/id-schema.json --output "$schema_dir/postgres_uuid_schema.rs"
export BETTER_AUTH_POSTGRES_UUID_SCHEMA="$schema_dir/postgres_uuid_schema.rs"
"$consumer_cli" generate --plugins all --api-key-legacy-schema --device-code-legacy-schema --passkey-legacy-schema --two-factor-legacy-schema --generate-id serial --database postgres --schema-config compat-tests/schema-consumer/id-schema.json --output "$schema_dir/postgres_serial_schema.rs"
export BETTER_AUTH_POSTGRES_SERIAL_SCHEMA="$schema_dir/postgres_serial_schema.rs"

for backend in postgres mysql; do
  "$consumer_cli" generate --database "$backend" --output "$schema_dir/server_${backend}_catalog_schema.rs"
  "$consumer_cli" generate --database "$backend" --schema-config "$schema_dir/verification_catalog_legacy.json" --output "$schema_dir/verification_server_${backend}_legacy_schema.rs"
done
export BETTER_AUTH_SERVER_POSTGRES_CATALOG_SCHEMA="$schema_dir/server_postgres_catalog_schema.rs"
export BETTER_AUTH_SERVER_MYSQL_CATALOG_SCHEMA="$schema_dir/server_mysql_catalog_schema.rs"
export BETTER_AUTH_VERIFICATION_SERVER_POSTGRES_LEGACY_SCHEMA="$schema_dir/verification_server_postgres_legacy_schema.rs"
export BETTER_AUTH_VERIFICATION_SERVER_MYSQL_LEGACY_SCHEMA="$schema_dir/verification_server_mysql_legacy_schema.rs"

for backend in postgres mysql; do
  for case in default custom; do
    "$consumer_cli" generate --plugins jwt --database "$backend" --schema-config "$schema_dir/jwk_server_${case}.json" --output "$schema_dir/jwk_server_${backend}_${case}_schema.rs"
  done
done
export BETTER_AUTH_JWK_SERVER_POSTGRES_DEFAULT_SCHEMA="$schema_dir/jwk_server_postgres_default_schema.rs"
export BETTER_AUTH_JWK_SERVER_POSTGRES_CUSTOM_SCHEMA="$schema_dir/jwk_server_postgres_custom_schema.rs"
export BETTER_AUTH_JWK_SERVER_MYSQL_DEFAULT_SCHEMA="$schema_dir/jwk_server_mysql_default_schema.rs"
export BETTER_AUTH_JWK_SERVER_MYSQL_CUSTOM_SCHEMA="$schema_dir/jwk_server_mysql_custom_schema.rs"

for backend in postgres mysql; do
  for case in default custom; do
    "$consumer_cli" generate --rate-limit-database --database "$backend" --schema-config "$schema_dir/rate_limit_server_${case}.json" --output "$schema_dir/rate_limit_server_${backend}_${case}_schema.rs"
  done
done
export BETTER_AUTH_RATE_LIMIT_SERVER_POSTGRES_DEFAULT_SCHEMA="$schema_dir/rate_limit_server_postgres_default_schema.rs"
export BETTER_AUTH_RATE_LIMIT_SERVER_POSTGRES_CUSTOM_SCHEMA="$schema_dir/rate_limit_server_postgres_custom_schema.rs"
export BETTER_AUTH_RATE_LIMIT_SERVER_MYSQL_DEFAULT_SCHEMA="$schema_dir/rate_limit_server_mysql_default_schema.rs"
export BETTER_AUTH_RATE_LIMIT_SERVER_MYSQL_CUSTOM_SCHEMA="$schema_dir/rate_limit_server_mysql_custom_schema.rs"

for backend in postgres mysql; do
  "$consumer_cli" generate --plugins organization --database "$backend" --output "$schema_dir/organization_server_${backend}_default_schema.rs"
  for model in member organization_role team invitation; do
    "$consumer_cli" generate --plugins organization --database "$backend" --schema-config "$schema_dir/${model}_server_custom.json" --output "$schema_dir/${model}_server_${backend}_custom_schema.rs"
  done
done
for backend in postgres mysql; do
  "$consumer_cli" generate --database "$backend" --schema-config "$schema_dir/session_catalog_custom.json" --output "$schema_dir/session_server_${backend}_custom_schema.rs"
done
export BETTER_AUTH_SESSION_SERVER_POSTGRES_CUSTOM_SCHEMA="$schema_dir/session_server_postgres_custom_schema.rs"
export BETTER_AUTH_SESSION_SERVER_MYSQL_CUSTOM_SCHEMA="$schema_dir/session_server_mysql_custom_schema.rs"
export BETTER_AUTH_ORGANIZATION_SERVER_POSTGRES_DEFAULT_SCHEMA="$schema_dir/organization_server_postgres_default_schema.rs"
export BETTER_AUTH_ORGANIZATION_SERVER_MYSQL_DEFAULT_SCHEMA="$schema_dir/organization_server_mysql_default_schema.rs"
export BETTER_AUTH_MEMBER_SERVER_POSTGRES_CUSTOM_SCHEMA="$schema_dir/member_server_postgres_custom_schema.rs"
export BETTER_AUTH_MEMBER_SERVER_MYSQL_CUSTOM_SCHEMA="$schema_dir/member_server_mysql_custom_schema.rs"
export BETTER_AUTH_ORGANIZATION_ROLE_SERVER_POSTGRES_CUSTOM_SCHEMA="$schema_dir/organization_role_server_postgres_custom_schema.rs"
export BETTER_AUTH_ORGANIZATION_ROLE_SERVER_MYSQL_CUSTOM_SCHEMA="$schema_dir/organization_role_server_mysql_custom_schema.rs"
export BETTER_AUTH_TEAM_SERVER_POSTGRES_CUSTOM_SCHEMA="$schema_dir/team_server_postgres_custom_schema.rs"
export BETTER_AUTH_TEAM_SERVER_MYSQL_CUSTOM_SCHEMA="$schema_dir/team_server_mysql_custom_schema.rs"
export BETTER_AUTH_INVITATION_SERVER_POSTGRES_CUSTOM_SCHEMA="$schema_dir/invitation_server_postgres_custom_schema.rs"
export BETTER_AUTH_INVITATION_SERVER_MYSQL_CUSTOM_SCHEMA="$schema_dir/invitation_server_mysql_custom_schema.rs"

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
elif [[ "$1" == --test ]]; then
  cargo clippy --locked --manifest-path compat-tests/schema-consumer/Cargo.toml --test "$2" -- -D warnings
fi
# Focused runs lint the selected test target and omit external runtime checks.
# Compile generated test targets one at a time to bound aggregate rustc memory.
cargo test --locked --jobs 1 --no-fail-fast --manifest-path compat-tests/schema-consumer/Cargo.toml "$@"
if [[ $# -eq 0 ]]; then
  cargo build --locked --manifest-path compat-tests/schema-consumer/Cargo.toml --example user_timestamp_interchange --message-format=json > "$schema_dir/user_timestamp_artifacts.jsonl"
  BETTER_AUTH_TIMESTAMP_ARTIFACTS="$schema_dir/user_timestamp_artifacts.jsonl" bun --no-install test ./compat-tests/reference-server/consumer-contracts/user-timestamp-interchange.test.ts
  bun --no-install test ./compat-tests/reference-server/consumer-contracts/device-code-catalog.test.ts --test-name-pattern sqlite
  bun --no-install test ./compat-tests/reference-server/consumer-contracts/wallet-address-catalog.test.ts --test-name-pattern sqlite
  bun --no-install test ./compat-tests/reference-server/consumer-contracts/passkey-catalog.test.ts --test-name-pattern sqlite
  bun --no-install test ./compat-tests/reference-server/consumer-contracts/two-factor-catalog.test.ts --test-name-pattern sqlite
  bun --no-install test ./compat-tests/reference-server/consumer-contracts/device-grant-sql.test.ts --test-name-pattern sqlite
  bun --no-install test ./compat-tests/reference-server/consumer-contracts/organization-role-empty-in.test.ts --test-name-pattern sqlite
fi
server_catalog_tests=(
  ./compat-tests/reference-server/consumer-contracts/api-key-date-usage.test.ts
  ./compat-tests/reference-server/consumer-contracts/mysql-create-readback.test.ts
  ./compat-tests/reference-server/consumer-contracts/update-fields-server.test.ts
  ./compat-tests/reference-server/consumer-contracts/verification-consume-hooks-server.test.ts
  ./compat-tests/reference-server/consumer-contracts/device-grant-sql.test.ts
  ./compat-tests/reference-server/consumer-contracts/device-where.test.ts \
  ./compat-tests/reference-server/consumer-contracts/device-where-transactions.test.ts
  ./compat-tests/reference-server/consumer-contracts/device-where-references.test.ts
  ./compat-tests/reference-server/consumer-contracts/device-reference-sets.test.ts
  ./compat-tests/reference-server/consumer-contracts/device-reference-values.test.ts
  ./compat-tests/reference-server/consumer-contracts/device-reference-defaults.test.ts
  ./compat-tests/reference-server/consumer-contracts/native-json-driver.test.ts
  ./compat-tests/reference-server/consumer-contracts/device-code-catalog.test.ts
  ./compat-tests/reference-server/consumer-contracts/wallet-address-catalog.test.ts
  ./compat-tests/reference-server/consumer-contracts/passkey-catalog.test.ts
  ./compat-tests/reference-server/consumer-contracts/two-factor-catalog.test.ts
  ./compat-tests/reference-server/consumer-contracts/server-catalog.test.ts
  ./compat-tests/reference-server/consumer-contracts/session-server.test.ts
  ./compat-tests/reference-server/consumer-contracts/verification-server-catalog.test.ts
  ./compat-tests/reference-server/consumer-contracts/jwk-server-catalog.test.ts
  ./compat-tests/reference-server/consumer-contracts/rate-limit-server-catalog.test.ts
  ./compat-tests/reference-server/consumer-contracts/rate-limit-server-runtime.test.ts
  ./compat-tests/reference-server/consumer-contracts/member-server-catalog.test.ts
  ./compat-tests/reference-server/consumer-contracts/organization-role-server.test.ts
  ./compat-tests/reference-server/consumer-contracts/organization-role-empty-in.test.ts
  ./compat-tests/reference-server/consumer-contracts/team-invitation-server.test.ts
)
if [[ $# -eq 0 && -n "${BETTER_AUTH_TEST_POSTGRES_URL:-}" ]]; then
  cargo test --locked --manifest-path compat-tests/schema-consumer/Cargo.toml --test generated_plugin_catalog -- --ignored live_postgres_plugin_display_json live_postgres_api_key_usage_dates_match_complete_pinned_operations live_postgres_device_grant_and_redemption_match_upstream
  bun --no-install test "${server_catalog_tests[@]}" --test-name-pattern postgres
  cargo test --locked --manifest-path compat-tests/schema-consumer/Cargo.toml -- --ignored --exact tests::ids::live_postgres_generated_ids tests::server_catalog::live_postgres_user_account_catalog_matches_upstream tests::device_code_catalog::live_postgres_device_code_catalog_matches_upstream tests::wallet_catalog::live_postgres_wallet_catalog_and_storage_match_upstream tests::passkey_catalog::live_postgres_passkey_catalog_and_native_storage tests::two_factor_catalog::live_postgres_two_factor_catalog_and_native_storage tests::session_server::live_postgres_session_storage_matches_upstream tests::verification_server_catalog::live_postgres_verification_catalog_matches_upstream tests::jwk_server_catalog::live_postgres_jwk_catalog_matches_upstream tests::rate_limit_server_catalog::live_postgres_rate_limit_catalog_matches_upstream tests::rate_limit_server_catalog::live_postgres_rate_limit_counter_matches_upstream tests::member_server_catalog::live_postgres_member_catalog_matches_upstream tests::organization_role_server::live_postgres_organization_role_storage_matches_upstream tests::team_invitation_server::live_postgres_team_invitation_storage_matches_upstream
  cargo test --locked --features axum,seaorm2,redis-cache --test legacy_schema_integration_tests --test schema_preflight_tests --test plugin_model_fields_tests --test device_additional_fields_tests --test device_where_tests --test native_json_driver_tests --test default_find_many_limit_tests --test native_core_join_tests --test organization_native_join_tests --test session_id_policy_tests --test account_verification_update_fields_tests --test user_account_raw_column_tests --test verification_transaction_delete_tests --test query_binding_order_tests live_postgres -- --ignored
fi
if [[ $# -eq 0 && -n "${BETTER_AUTH_TEST_MYSQL_URL:-}" ]]; then
  cargo test --locked --manifest-path compat-tests/schema-consumer/Cargo.toml --test generated_plugin_catalog -- --ignored live_mysql_plugin_display_json live_mysql_api_key_usage_dates_match_complete_pinned_operations live_mysql_device_grant_and_redemption_match_upstream
  bun --no-install test "${server_catalog_tests[@]}" --test-name-pattern mysql
  cargo test --locked --manifest-path compat-tests/schema-consumer/Cargo.toml -- --ignored --exact tests::server_catalog::live_mysql_user_account_catalog_matches_upstream tests::device_code_catalog::live_mysql_device_code_catalog_matches_upstream tests::wallet_catalog::live_mysql_wallet_catalog_and_storage_match_upstream tests::passkey_catalog::live_mysql_passkey_catalog_and_native_storage tests::two_factor_catalog::live_mysql_two_factor_catalog_and_native_storage tests::session_server::live_mysql_session_storage_matches_upstream tests::verification_server_catalog::live_mysql_verification_catalog_matches_upstream tests::jwk_server_catalog::live_mysql_jwk_catalog_matches_upstream tests::rate_limit_server_catalog::live_mysql_rate_limit_catalog_matches_upstream tests::rate_limit_server_catalog::live_mysql_rate_limit_counter_matches_upstream tests::member_server_catalog::live_mysql_member_catalog_matches_upstream tests::organization_role_server::live_mysql_organization_role_storage_matches_upstream tests::team_invitation_server::live_mysql_team_invitation_storage_matches_upstream
  cargo test --locked --features axum,seaorm2,redis-cache --test schema_preflight_tests mysql::live_mysql_preflight_tracks_migrations_defaults_and_auto_increment -- --ignored --exact
  cargo test --locked --features axum,seaorm2,redis-cache --test device_where_tests --test native_json_driver_tests --test session_id_policy_tests --test account_verification_update_fields_tests --test user_account_raw_column_tests --test verification_transaction_delete_tests --test query_binding_order_tests live_mysql_ -- --ignored
  cargo test --locked --features axum,seaorm2,redis-cache --test mysql_create_readback_tests -- --ignored
fi
