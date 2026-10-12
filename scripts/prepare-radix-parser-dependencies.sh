#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
: "${GITHUB_SHA:?Run from the checked-out GitHub Actions revision}"
: "${GITHUB_ACTIONS:?Run dependency preparation in GitHub Actions}"
dependency_output="${1:?Specify the dependency artifact directory}"
mkdir -p "$dependency_output/graphs" "$dependency_output/logs"
printf '%s\n' "$GITHUB_SHA" > "$dependency_output/source-sha.txt"

preserve_artifacts() {
  dependency_status=$?
  git diff -- crates/core/Cargo.toml Cargo.lock compat-tests/rust-server/Cargo.lock \
    compat-tests/schema-consumer/Cargo.lock examples/fullstack/backend/Cargo.lock \
    > "$dependency_output/dependency.patch"
  python3 - "$dependency_output" "$dependency_status" <<'PY_ARTIFACT'
import hashlib
import json
import shutil
import sys
from pathlib import Path

output = Path(sys.argv[1])
files = [
    "crates/core/Cargo.toml", "Cargo.lock", "compat-tests/rust-server/Cargo.lock",
    "compat-tests/schema-consumer/Cargo.lock", "examples/fullstack/backend/Cargo.lock",
]
manifest = []
for relative in files:
    source = Path(relative)
    destination = output / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    manifest.append({"path": relative, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()})
(output / "artifact-manifest.json").write_text(json.dumps({
    "status": int(sys.argv[2]), "files": manifest,
}, indent=2) + "\n")
PY_ARTIFACT
  exit "$dependency_status"
}
trap preserve_artifacts EXIT

cargo add --manifest-path crates/core/Cargo.toml lexical-parse-float \
  --no-default-features --features power-of-two \
  2>&1 | tee "$dependency_output/logs/cargo-add.log"

dependency_manifests=(
  Cargo.toml
  compat-tests/rust-server/Cargo.toml
  compat-tests/schema-consumer/Cargo.toml
  examples/fullstack/backend/Cargo.toml
)
for dependency_index in "${!dependency_manifests[@]}"; do
  dependency_manifest="${dependency_manifests[$dependency_index]}"
  # Cargo resolves the new edge while retaining compatible entries in each existing lockfile.
  cargo metadata --manifest-path "$dependency_manifest" --all-features --format-version 1 \
    > "$dependency_output/graphs/$dependency_index-resolved.json" \
    2> "$dependency_output/logs/$dependency_index-resolve.log"
  cargo metadata --manifest-path "$dependency_manifest" --locked --all-features --format-version 1 \
    > "$dependency_output/graphs/$dependency_index.json" \
    2> "$dependency_output/logs/$dependency_index-locked.log"
done

python3 - "$dependency_output" <<'PY_VALIDATE'
import json
import sys
import tomllib
from pathlib import Path

output = Path(sys.argv[1])
root = Path.cwd().resolve()
manifest = tomllib.loads(Path("crates/core/Cargo.toml").read_text())
dependency = manifest["dependencies"]["lexical-parse-float"]
assert dependency.get("default-features", True) is False, dependency
assert dependency.get("features") == ["power-of-two"], dependency
summaries = []
for index, relative in enumerate([
    "Cargo.toml", "compat-tests/rust-server/Cargo.toml",
    "compat-tests/schema-consumer/Cargo.toml", "examples/fullstack/backend/Cargo.toml",
]):
    graph = json.loads((output / f"graphs/{index}.json").read_text())
    core = next(package for package in graph["packages"]
                if Path(package["manifest_path"]).resolve() == root / "crates/core/Cargo.toml")
    declared = next(item for item in core["dependencies"] if item["name"] == "lexical-parse-float")
    assert not declared["uses_default_features"], (relative, declared)
    assert declared["features"] == ["power-of-two"], (relative, declared)
    nodes = {node["id"]: node for node in graph["resolve"]["nodes"]}
    edge = next(item for item in nodes[core["id"]]["deps"] if item["name"] == "lexical_parse_float")
    selected = next(package for package in graph["packages"] if package["id"] == edge["pkg"])
    assert "power-of-two" in nodes[selected["id"]]["features"], (relative, selected)
    summaries.append({
        "manifest": relative, "name": selected["name"], "version": selected["version"],
        "source": selected["source"], "features": nodes[selected["id"]]["features"],
    })
assert len({entry["version"] for entry in summaries}) == 1, summaries
(output / "validation.json").write_text(json.dumps(summaries, indent=2) + "\n")
PY_VALIDATE
