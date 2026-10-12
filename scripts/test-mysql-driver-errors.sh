#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
: "${RUNNER_TEMP:?Run this script in GitHub Actions through devenv}"
: "${DATABASE_URL:?Set the MySQL CI service URL}"
mysql_output="${1:?Specify the MySQL driver test artifact directory}"
mkdir -p "$mysql_output"
mysql_root=$(mktemp -d "$RUNNER_TEMP/mysql-errors.XXXXXX")
cp -R vendor/sqlx-mysql/. "$mysql_root/"
cp Cargo.lock "$mysql_root/Cargo.lock"
printf '%s\n' "$mysql_root" > "$mysql_output/test-root.txt"
mysql_patch="patch.crates-io.sqlx-mysql.path=\"$mysql_root\""

cargo metadata --manifest-path "$mysql_root/Cargo.toml" --config "$mysql_patch" \
  --features sqlx/runtime-tokio --format-version 1 > /dev/null
cargo metadata --manifest-path "$mysql_root/Cargo.toml" --config "$mysql_patch" --locked \
  --features sqlx/runtime-tokio --format-version 1 > "$mysql_output/dependency-graph.json"
python3 - "$mysql_root" "$mysql_output/dependency-graph.json" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
graph = json.loads(Path(sys.argv[2]).read_text())
matches = [package for package in graph["packages"] if package["name"] == "sqlx-mysql"]
assert len(matches) == 1
assert matches[0]["source"] is None
assert Path(matches[0]["manifest_path"]).resolve() == root / "Cargo.toml"
for package in graph["packages"]:
    if package["name"] == "sqlx" or package["name"].startswith("sqlx-"):
        assert package["version"] == "0.8.6", package
PY

cargo test --manifest-path "$mysql_root/Cargo.toml" --config "$mysql_patch" --locked \
  --target-dir "$mysql_root/target" --features sqlx/runtime-tokio --lib \
  2>&1 | tee "$mysql_output/unit.log"
cargo test --manifest-path "$mysql_root/Cargo.toml" --config "$mysql_patch" --locked \
  --target-dir "$mysql_root/target" --features sqlx/runtime-tokio --lib \
  connection::stream::error_transport_live_tests -- --ignored --test-threads=1 \
  2>&1 | tee "$mysql_output/live.log"
python3 - "$mysql_output" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
for file, module, count in (
    ("unit.log", "error_transport_tests", 20),
    ("live.log", "error_transport_live_tests", 3),
):
    source = (root / file).read_text()
    pattern = rf"^test connection::stream::{module}::.* \.\.\. ok$"
    matches = re.findall(pattern, source, re.M)
    assert len(matches) == count, (file, count, matches)
PY
