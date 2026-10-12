#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
: "${RUNNER_TEMP:?Run this script in GitHub Actions through devenv}"
: "${DATABASE_URL:?Set the PostgreSQL CI service URL}"
protocol_output="${1:?Specify the protocol test artifact directory}"
mkdir -p "$protocol_output/graphs"
protocol_root=$(mktemp -d "$RUNNER_TEMP/postgres-protocol.XXXXXX")
printf '%s\n' "$protocol_root" > "$protocol_output/test-root.txt"
protocol_patches=()
for protocol_package in sqlx-postgres sqlx-mysql sea-query sea-query-sqlx sea-orm; do
  mkdir -p "$protocol_root/$protocol_package"
  cp -R "vendor/$protocol_package/." "$protocol_root/$protocol_package/"
  # Seed each independent package with the validated application dependency versions.
  cp Cargo.lock "$protocol_root/$protocol_package/Cargo.lock"
  protocol_patches+=(--config "patch.crates-io.$protocol_package.path=\"$protocol_root/$protocol_package\"")
done

protocol_packages=(sqlx-postgres sea-query sea-query-sqlx)
protocol_features=(
  'sqlx/runtime-tokio'
  'tests-cfg,hashable-value,with-json,backend-postgres,backend-mysql,backend-sqlite'
  'sqlx-postgres,sqlx-mysql,sqlx-sqlite,sqlx-any,postgres-array,with-bigdecimal,with-chrono,with-time,with-uuid,with-rust_decimal,with-json,with-ipnetwork,with-mac_address,postgres-vector'
)
for protocol_index in "${!protocol_packages[@]}"; do
  protocol_package="${protocol_packages[$protocol_index]}"
  protocol_manifest="$protocol_root/$protocol_package/Cargo.toml"
  # Cargo replaces application root edges with the selected package's test edges.
  cargo metadata --manifest-path "$protocol_manifest" "${protocol_patches[@]}" \
    --features "${protocol_features[$protocol_index]}" --format-version 1 > /dev/null
  cargo metadata --manifest-path "$protocol_manifest" "${protocol_patches[@]}" --locked \
    --features "${protocol_features[$protocol_index]}" --format-version 1 \
    > "$protocol_output/graphs/$protocol_package.json"
done

python3 - "$protocol_root" "$protocol_output" <<'PY'
import json
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
output = Path(sys.argv[2])
versions = {
    "sqlx-postgres": "0.8.6",
    "sqlx-mysql": "0.8.6",
    "sea-query": "1.0.0-rc.31",
    "sea-query-sqlx": "0.8.0-rc.14",
    "sea-orm": "2.0.0-rc.37",
}
for name, version in versions.items():
    manifest = tomllib.loads((root / name / "Cargo.toml").read_text())
    assert (manifest["package"]["name"], manifest["package"]["version"]) == (name, version)
for package_name, required in {
    "sqlx-postgres": ["sqlx-postgres"],
    "sea-query": ["sea-query"],
    "sea-query-sqlx": ["sqlx-postgres", "sea-query", "sea-query-sqlx"],
}.items():
    graph = json.loads((output / "graphs" / f"{package_name}.json").read_text())
    for name in required:
        matches = [package for package in graph["packages"] if package["name"] == name]
        assert len(matches) == 1, (package_name, name, matches)
        selected = matches[0]
        assert selected["version"] == versions[name], (package_name, selected)
        assert selected["source"] is None, (package_name, selected)
        assert Path(selected["manifest_path"]).resolve() == root / name / "Cargo.toml"
    for selected in graph["packages"]:
        if selected["name"] == "sqlx" or selected["name"].startswith("sqlx-"):
            assert selected["version"] == "0.8.6", (package_name, selected)
        if selected["name"] in versions:
            assert selected["version"] == versions[selected["name"]], (package_name, selected)
            assert selected["source"] is None, (package_name, selected)
PY

protocol_status=0
for protocol_index in "${!protocol_packages[@]}"; do
  protocol_package="${protocol_packages[$protocol_index]}"
  cargo test --manifest-path "$protocol_root/$protocol_package/Cargo.toml" \
    "${protocol_patches[@]}" --locked --target-dir "$protocol_root/target" \
    --features "${protocol_features[$protocol_index]}" --lib \
    2>&1 | tee "$protocol_output/$protocol_package-unit.log" || protocol_status=1
done
cargo test --manifest-path "$protocol_root/sqlx-postgres/Cargo.toml" \
  "${protocol_patches[@]}" --locked --target-dir "$protocol_root/target" \
  --features "${protocol_features[0]}" --lib \
  -- connection::executor::protocol_tests --ignored \
  2>&1 | tee "$protocol_output/sqlx-postgres-live.log" || protocol_status=1

if (( protocol_status != 0 )); then
  exit "$protocol_status"
fi

python3 - "$protocol_output" <<'PY'
import re
import sys
from pathlib import Path

output = Path(sys.argv[1])
logs = {
    name: (output / name).read_text()
    for name in (
        "sqlx-postgres-unit.log", "sea-query-unit.log",
        "sea-query-sqlx-unit.log", "sqlx-postgres-live.log",
    )
}
assert re.search(
    r"test error::tests::original_error_response_fields_and_length_are_retained\s+\.\.\. ok",
    logs["sqlx-postgres-unit.log"],
), "The existing driver metadata regression must run"
for name, prefix, expected in (
    ("sea-query-unit.log", "prepare::protocol_tests::", 8),
    ("sea-query-sqlx-unit.log", "sqlx_postgres::tests::", 7),
    ("sqlx-postgres-live.log", "connection::executor::protocol_tests::", 4),
):
    completed = re.findall(r"^test " + re.escape(prefix) + r".* \.\.\. ok$", logs[name], re.M)
    assert len(completed) == expected, (name, expected, completed)
for backend in ("sqlx_mysql", "sqlx_sqlite", "sqlx_any"):
    assert re.search(
        rf"^test {backend}::rejects_postgres_protocol_values.* \.\.\. ok$",
        logs["sea-query-sqlx-unit.log"], re.M,
    ), f"The {backend} protocol rejection regression must run"
PY
