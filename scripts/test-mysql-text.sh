#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
: "${RUNNER_TEMP:?Run this script in GitHub Actions through devenv}"
text_output="${1:?Specify the MySQL text contract artifact directory}"
mkdir -p "$text_output"
text_root=$(mktemp -d "$RUNNER_TEMP/mysql-text.XXXXXX")
printf '%s\n' "$text_root" > "$text_output/test-root.txt"
cp -R vendor/sea-query "$text_root/sea-query"
cp Cargo.lock "$text_root/sea-query/Cargo.lock"
text_patch=(--config "patch.crates-io.sea-query.path=\"$text_root/sea-query\"")
text_features='tests-cfg,hashable-value,with-json,backend-postgres,backend-mysql,backend-sqlite'
export BETTER_AUTH_MYSQL_TEXT_FIXTURE="$PWD/tests/fixtures/mysql-text-1.7.6.json"
export TZ=UTC
export CARGO_TERM_COLOR=never
cp "$BETTER_AUTH_MYSQL_TEXT_FIXTURE" "$text_output/"
cp tests/fixtures/mysql-text-1.7.6.provenance.json "$text_output/"

# Cargo must resolve the standalone package's test dependencies outside the application workspace.
cargo metadata --manifest-path "$text_root/sea-query/Cargo.toml" "${text_patch[@]}" \
  --features "$text_features" --format-version 1 > /dev/null
cargo metadata --manifest-path "$text_root/sea-query/Cargo.toml" "${text_patch[@]}" --locked \
  --features "$text_features" --format-version 1 > "$text_output/sea-query-graph.json"
python3 - "$text_output" "$text_root" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

output, root = map(Path, sys.argv[1:])
graph = json.loads((output / "sea-query-graph.json").read_text())
packages = [package for package in graph["packages"] if package["name"] == "sea-query"]
assert len(packages) == 1, packages
package = packages[0]
assert package["version"] == "1.0.0-rc.31" and package["source"] is None, package
assert Path(package["manifest_path"]).resolve() == root / "sea-query/Cargo.toml"
fixture = (output / "mysql-text-1.7.6.json").read_bytes()
provenance = json.loads((output / "mysql-text-1.7.6.provenance.json").read_text())
assert hashlib.sha256(fixture).hexdigest() == provenance["fixture"]["sha256"]
PY

text_status=0
cargo test --manifest-path "$text_root/sea-query/Cargo.toml" "${text_patch[@]}" --locked \
  --target-dir "$text_root/target" --features "$text_features" --tests \
  2>&1 | tee "$text_output/sea-query-original.log" || text_status=1
cargo test --manifest-path "$text_root/sea-query/Cargo.toml" "${text_patch[@]}" --locked \
  --target-dir "$text_root/target" --features "$text_features" --lib \
  -- backend::mysql::kysely::tests::pinned_mysql_compiler_templates_and_parameters --exact --ignored \
  2>&1 | tee "$text_output/compiler.log" || text_status=1
cargo clippy --locked -p better-auth-seaorm --lib -- -D warnings \
  2>&1 | tee "$text_output/clippy.log" || text_status=1
cargo test --locked -p better-auth-seaorm --lib \
  -- store::mysql_text::tests::pinned_mysql_text_parameters_and_native_callbacks --exact --ignored \
  2>&1 | tee "$text_output/formatter.log" || text_status=1

if (( text_status != 0 )); then
  exit "$text_status"
fi
python3 - "$text_output" <<'PY'
import re
import sys
from pathlib import Path

output = Path(sys.argv[1])
for file, name in (
    ("compiler.log", "backend::mysql::kysely::tests::pinned_mysql_compiler_templates_and_parameters"),
    ("formatter.log", "store::mysql_text::tests::pinned_mysql_text_parameters_and_native_callbacks"),
):
    log = (output / file).read_text()
    assert re.search(r"^test " + re.escape(name) + r" \.\.\. ok$", log, re.M), (file, name)
    assert "1 passed; 0 failed; 0 ignored" in log, file
original = (output / "sea-query-original.log").read_text()
for backend in ("mysql", "postgres", "sqlite"):
    block = re.search(
        r"Running tests/" + backend + r"/mod\.rs.*?(?=\n\s*Running |\Z)", original, re.S,
    )
    assert block, backend
    passed = re.search(r"test result: ok\. (\d+) passed; 0 failed", block.group())
    assert passed and int(passed.group(1)) > 0, backend
assert "test result: FAILED" not in original
PY
