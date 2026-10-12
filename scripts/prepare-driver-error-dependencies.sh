#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
dependency_output="${1:?Specify the dependency artifact directory}"
mkdir -p "$dependency_output/graphs"
printf '%s\n' "${GITHUB_SHA:?Run from the checked-out GitHub Actions revision}" > "$dependency_output/source-sha.txt"

python3 - "$dependency_output/features-before.json" <<'PY'
import json
import sys
import tomllib
from pathlib import Path

manifest = tomllib.loads(Path("crates/seaorm/Cargo.toml").read_text())
dependencies = manifest["dependencies"]
Path(sys.argv[1]).write_text(json.dumps({
    name: {
        "features": sorted(dependencies[name].get("features", [])),
        "default-features": dependencies[name].get("default-features", True),
    }
    for name in ("sea-orm", "sea-orm-migration")
}, indent=2) + "\n")
PY

cargo add --manifest-path crates/seaorm/Cargo.toml \
  'sea-orm@=2.0.0-rc.37' 'sea-orm-migration@=2.0.0-rc.37'

python3 - "$dependency_output/features-before.json" <<'PY'
import json
import os
import re
import sys
import tomllib
from pathlib import Path

root = Path.cwd().resolve()
vendor_packages = {
    "sqlx-postgres": "0.8.6",
    "sea-query": "1.0.0-rc.31",
    "sea-query-sqlx": "0.8.0-rc.14",
    "sea-orm": "2.0.0-rc.37",
}
for name, version in vendor_packages.items():
    vendor = root / "vendor" / name
    package = tomllib.loads((vendor / "Cargo.toml").read_text())["package"]
    assert (package["name"], package["version"]) == (name, version), package
    assert (vendor / "LICENSE-MIT").is_file(), name
    assert (vendor / "LICENSE-APACHE").is_file(), name
before = json.loads(Path(sys.argv[1]).read_text())
dependencies = tomllib.loads(Path("crates/seaorm/Cargo.toml").read_text())["dependencies"]
for name, original in before.items():
    current = dependencies[name]
    assert current["version"] == "=2.0.0-rc.37", (name, current)
    assert sorted(current.get("features", [])) == original["features"], name
    assert current.get("default-features", True) == original["default-features"], name

root_manifest = Path("Cargo.toml")
text = root_manifest.read_text()
workspace = tomllib.loads(text)["workspace"]
excluded = workspace.get("exclude", [])
missing = [f"vendor/{name}" for name in vendor_packages if f"vendor/{name}" not in excluded]
if missing:
    excluded.extend(missing)
    start = text.index("[workspace]") + len("[workspace]")
    next_table = re.search(r"(?m)^\[", text[start:])
    end = start + next_table.start() if next_table else len(text)
    block = text[start:end]
    replacement = "exclude = " + json.dumps(excluded)
    if "exclude" in workspace:
        block, count = re.subn(r"(?m)^exclude\s*=\s*\[[^\]]*\]", replacement, block, count=1)
        assert count == 1, "Cannot locate the workspace exclude array"
    else:
        block = "\n" + replacement + block
    root_manifest.write_text(text[:start] + block + text[end:])

for relative in (
    "Cargo.toml",
    "compat-tests/rust-server/Cargo.toml",
    "compat-tests/schema-consumer/Cargo.toml",
    "examples/fullstack/backend/Cargo.toml",
):
    manifest = Path(relative)
    text = manifest.read_text()
    data = tomllib.loads(text)
    patch = data.get("patch", {}).get("crates-io", {})
    entries = []
    for name in vendor_packages:
        relative_vendor = os.path.relpath(root / "vendor" / name, manifest.resolve().parent)
        if name in patch:
            assert patch[name] == {"path": relative_vendor}, (relative, name, patch[name])
        else:
            entries.append(name + ' = { path = ' + json.dumps(relative_vendor) + ' }\n')
    if not entries:
        continue
    entry = "".join(entries)
    if "crates-io" in data.get("patch", {}):
        match = re.search(r"(?m)^\[patch\.crates-io\][ \t]*$", text)
        assert match, f"Cannot locate the crates.io patch table in {relative}"
        text = text[:match.end()] + "\n" + entry + text[match.end():]
    else:
        text = text.rstrip() + "\n\n[patch.crates-io]\n" + entry
    manifest.write_text(text)
PY

dependency_manifests=(
  Cargo.toml
  compat-tests/rust-server/Cargo.toml
  compat-tests/schema-consumer/Cargo.toml
  examples/fullstack/backend/Cargo.toml
)
# The older lock must resolve the mutually constrained package family in one operation.
dependency_constraints=(
  'sea-orm@=2.0.0-rc.37'
  'sea-orm-cli@=2.0.0-rc.37'
  'sea-orm-macros@=2.0.0-rc.37'
  'sea-orm-migration@=2.0.0-rc.37'
  'sea-schema@=0.17.0-rc.17'
  'sea-query@=1.0.0-rc.31'
  'sea-query-sqlx@=0.8.0-rc.14'
  'sqlx@=0.8.6'
  'sqlx-core@=0.8.6'
  'sqlx-postgres@=0.8.6'
)
dependency_constraint_names=()
for dependency_constraint in "${dependency_constraints[@]}"; do
  dependency_constraint_names+=("${dependency_constraint%@*}")
done
for dependency_index in "${!dependency_manifests[@]}"; do
  dependency_manifest="${dependency_manifests[$dependency_index]}"
  dependency_snapshot="$dependency_output/manifest-before-constraints-$dependency_index.toml"
  python3 - "$dependency_manifest" "$dependency_snapshot" "${dependency_constraint_names[@]}" <<'PY_CHECK'
import shutil
import sys
import tomllib
from pathlib import Path

manifest = Path(sys.argv[1])
data = tomllib.loads(manifest.read_text())
for section in ("dependencies", "dev-dependencies", "build-dependencies"):
    for name in sys.argv[3:]:
        assert name not in data.get(section, {}), (manifest, section, name)
shutil.copy2(manifest, sys.argv[2])
PY_CHECK
  cargo add --manifest-path "$dependency_manifest" --dev --no-default-features "${dependency_constraints[@]}"
  python3 - "$dependency_manifest" "$dependency_snapshot" "${dependency_constraints[@]}" <<'PY_CHECK'
import difflib
import json
import shutil
import sys
import tomllib
from pathlib import Path

manifest = Path(sys.argv[1])
snapshot = Path(sys.argv[2])
current = tomllib.loads(manifest.read_text())
expected = tomllib.loads(snapshot.read_text())
for constraint in sys.argv[3:]:
    name, version = constraint.split("@", 1)
    expected.setdefault("dev-dependencies", {})[name] = {
        "version": version,
        "default-features": False,
    }
difference = "".join(difflib.unified_diff(
    json.dumps(expected, sort_keys=True, indent=2).splitlines(keepends=True),
    json.dumps(current, sort_keys=True, indent=2).splitlines(keepends=True),
    fromfile="expected temporary dependencies",
    tofile=str(manifest),
))
assert current == expected, f"Temporary constraints changed persistent settings:\n{difference}"
# Restore the exact persistent manifest after validating the temporary Cargo changes.
shutil.copy2(snapshot, manifest)
PY_CHECK
  # Cargo removes temporary root edges while retaining the selected dependency versions.
  cargo metadata --manifest-path "$dependency_manifest" --all-features --format-version 1 > /dev/null
  cargo metadata --manifest-path "$dependency_manifest" --locked --all-features --format-version 1 \
    > "$dependency_output/graphs/$dependency_index.json"
done

python3 - "$dependency_output" <<'PY'
import json
import shutil
import sys
from pathlib import Path

root = Path.cwd().resolve()
output = Path(sys.argv[1])
expected = {
    "sea-orm": "2.0.0-rc.37",
    "sea-orm-cli": "2.0.0-rc.37",
    "sea-orm-macros": "2.0.0-rc.37",
    "sea-orm-migration": "2.0.0-rc.37",
    "sea-schema": "0.17.0-rc.17",
    "sea-query": "1.0.0-rc.31",
    "sea-query-sqlx": "0.8.0-rc.14",
    "sqlx": "0.8.6",
    "sqlx-core": "0.8.6",
    "sqlx-postgres": "0.8.6",
}
manifests = [
    "Cargo.toml",
    "compat-tests/rust-server/Cargo.toml",
    "compat-tests/schema-consumer/Cargo.toml",
    "examples/fullstack/backend/Cargo.toml",
]
registry = "registry+https://github.com/rust-lang/crates.io-index"
patched_packages = {"sqlx-postgres", "sea-query", "sea-query-sqlx", "sea-orm"}
summary = []
files = ["crates/seaorm/Cargo.toml"]
for index, relative in enumerate(manifests):
    graph = json.loads((output / f"graphs/{index}.json").read_text())
    selected = {}
    for name, version in expected.items():
        packages = [package for package in graph["packages"] if package["name"] == name]
        assert len(packages) == 1, (relative, name, packages)
        package = packages[0]
        assert package["version"] == version, (relative, name, package["version"])
        if name in patched_packages:
            assert package["source"] is None, (relative, package)
            assert Path(package["manifest_path"]).resolve() == root / "vendor" / name / "Cargo.toml"
            assert package["id"] not in graph["workspace_members"], "Vendor package must not join workspace-wide checks"
        else:
            assert package["source"] == registry, (relative, package)
        selected[name] = {"version": package["version"], "source": package["source"]}
    for package in graph["packages"]:
        if package["name"].startswith("sqlx-"):
            assert package["version"] == "0.8.6", (relative, package)
    summary.append({"manifest": relative, "packages": selected})
    files.extend([relative, str(Path(relative).with_name("Cargo.lock"))])

for relative in files:
    destination = output / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / relative, destination)
(output / "validation.json").write_text(json.dumps(summary, indent=2) + "\n")
(output / "manifest.txt").write_text("\n".join(files) + "\n")
PY
