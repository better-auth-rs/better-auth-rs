#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
: "${RUNNER_TEMP:?Run this script in GitHub Actions through devenv}"
: "${DATABASE_URL:?Set the MySQL CI service URL}"
mysql_output="${1:?Specify the MySQL driver test artifact directory}"
mkdir -p "$mysql_output"
mysql_root=$(mktemp -d "$RUNNER_TEMP/mysql-errors.XXXXXX")
mysql_patches=()
for mysql_package in sqlx-mysql sqlx-postgres sea-query sea-query-sqlx sea-orm; do
  mkdir -p "$mysql_root/$mysql_package"
  cp -R "vendor/$mysql_package/." "$mysql_root/$mysql_package/"
  cp Cargo.lock "$mysql_root/$mysql_package/Cargo.lock"
  mysql_patches+=(--config "patch.crates-io.$mysql_package.path=\"$mysql_root/$mysql_package\"")
done
export BETTER_AUTH_TEST_MYSQL_URL="$DATABASE_URL"
export CARGO_TERM_COLOR=never
mysql_seaorm_features='runtime-tokio-rustls,sqlx-mysql,sqlx-postgres,sqlx-sqlite,macros,with-chrono,with-json,with-uuid,with-bigdecimal'
printf '%s\n' "$mysql_root" > "$mysql_output/test-root.txt"

cargo metadata --manifest-path "$mysql_root/sqlx-mysql/Cargo.toml" "${mysql_patches[@]}" \
  --features sqlx/runtime-tokio --format-version 1 > /dev/null
cargo metadata --manifest-path "$mysql_root/sqlx-mysql/Cargo.toml" "${mysql_patches[@]}" --locked \
  --features sqlx/runtime-tokio --format-version 1 > "$mysql_output/dependency-graph.json"
cargo metadata --manifest-path "$mysql_root/sea-orm/Cargo.toml" "${mysql_patches[@]}" \
  --features "$mysql_seaorm_features" --format-version 1 > /dev/null
cargo metadata --manifest-path "$mysql_root/sea-orm/Cargo.toml" "${mysql_patches[@]}" --locked \
  --features "$mysql_seaorm_features" --format-version 1 > "$mysql_output/sea-orm-graph.json"
python3 - "$mysql_root" "$mysql_output" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2])
versions = {
    "sqlx-mysql": "0.8.6", "sqlx-postgres": "0.8.6",
    "sea-query": "1.0.0-rc.31", "sea-query-sqlx": "0.8.0-rc.14", "sea-orm": "2.0.0-rc.37",
}
for file, required in (
    ("dependency-graph.json", ["sqlx-mysql"]),
    ("sea-orm-graph.json", ["sqlx-mysql", "sqlx-postgres", "sea-query", "sea-query-sqlx", "sea-orm"]),
):
    graph = json.loads((output / file).read_text())
    for name in required:
        matches = [package for package in graph["packages"] if package["name"] == name]
        assert len(matches) == 1, (file, name, matches)
        selected = matches[0]
        assert selected["version"] == versions[name] and selected["source"] is None, selected
        assert Path(selected["manifest_path"]).resolve() == root / name / "Cargo.toml"
    for package in graph["packages"]:
        name = package["name"]
        if name == "sqlx" or name.startswith("sqlx-"):
            assert package["version"] == "0.8.6", package
        if name in versions:
            assert package["version"] == versions[name] and package["source"] is None, package
PY

cargo test --manifest-path "$mysql_root/sqlx-mysql/Cargo.toml" "${mysql_patches[@]}" --locked \
  --target-dir "$mysql_root/target" --features sqlx/runtime-tokio --lib \
  2>&1 | tee "$mysql_output/unit.log"
cargo test --manifest-path "$mysql_root/sqlx-mysql/Cargo.toml" "${mysql_patches[@]}" --locked \
  --target-dir "$mysql_root/target" --features sqlx/runtime-tokio --lib \
  connection::stream::error_transport_live_tests -- --ignored --test-threads=1 \
  2>&1 | tee "$mysql_output/live.log"
cargo test --manifest-path "$mysql_root/sea-orm/Cargo.toml" "${mysql_patches[@]}" --locked \
  --target-dir "$mysql_root/target" --features "$mysql_seaorm_features" --lib \
  driver::sqlx_mysql::text_command_tests:: -- --ignored --test-threads=1 \
  2>&1 | tee "$mysql_output/sea-orm-live.log"
python3 - "$mysql_output" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
for file, module, count in (
    ("unit.log", "connection::stream::error_transport_tests", 20),
    ("unit.log", "connection::stream::text_command_tests", 6),
    ("live.log", "connection::stream::error_transport_live_tests", 3),
    ("sea-orm-live.log", "driver::sqlx_mysql::text_command_tests", 3),
):
    source = (root / file).read_text()
    pattern = rf"^test {re.escape(module)}::.* \.\.\. ok$"
    matches = re.findall(pattern, source, re.M)
    assert len(matches) == count, (file, count, matches)
PY
