#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
schema_dir=$(mktemp -d)
trap 'rm -rf "$schema_dir"' EXIT

cargo run --locked -p better-auth-cli -- generate --plugins all --output "$schema_dir/auth_schema.rs"
export BETTER_AUTH_GENERATED_SCHEMA="$schema_dir/auth_schema.rs"
cargo run --locked -p better-auth-cli -- generate --plugins organization --schema-config compat-tests/schema-consumer/organization-schema.json --output "$schema_dir/organization_schema.rs"
export BETTER_AUTH_ORGANIZATION_SCHEMA="$schema_dir/organization_schema.rs"
cargo run --locked -p better-auth-cli -- generate --plugins all --schema-config compat-tests/schema-consumer/plugin-schema.json --output "$schema_dir/plugin_schema.rs"
export BETTER_AUTH_PLUGIN_SCHEMA="$schema_dir/plugin_schema.rs"
cargo run --locked -p better-auth-cli -- generate --plugins organization --schema-config compat-tests/schema-consumer/dynamic-schema.json --output "$schema_dir/dynamic_schema.rs"
export BETTER_AUTH_DYNAMIC_SCHEMA="$schema_dir/dynamic_schema.rs"
cargo run --locked -p better-auth-cli -- generate --plugins organization --schema-config compat-tests/schema-consumer/field-attributes-schema.json --output "$schema_dir/field_attributes_schema.rs"
export BETTER_AUTH_FIELD_ATTRIBUTES_SCHEMA="$schema_dir/field_attributes_schema.rs"
cargo run --locked -p better-auth-cli -- generate --rate-limit-database --schema-config compat-tests/schema-consumer/rate-limit-schema.json --output "$schema_dir/rate_limit_schema.rs"
export BETTER_AUTH_RATE_LIMIT_SCHEMA="$schema_dir/rate_limit_schema.rs"
cargo run --locked -p better-auth-cli -- generate --schema-config compat-tests/schema-consumer/account-verification-schema.json --output "$schema_dir/account_verification_schema.rs"
export BETTER_AUTH_ACCOUNT_VERIFICATION_SCHEMA="$schema_dir/account_verification_schema.rs"
cargo fmt --manifest-path compat-tests/schema-consumer/Cargo.toml -- --check
cargo clippy --locked --manifest-path compat-tests/schema-consumer/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path compat-tests/schema-consumer/Cargo.toml
