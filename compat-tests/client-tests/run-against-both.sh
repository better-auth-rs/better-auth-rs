#!/usr/bin/env bash
set -euo pipefail

# Run the bun-based client-compat scenarios against the already-running
# TS reference server (port 3100) and Rust server (port 3200).
#
# Usage:
#   ./run-against-both.sh                # all phases
#   ./run-against-both.sh phase0         # single phase
#
# Prereq: both servers must be started separately. The cargo-driven
# wrapper (`cargo test --test client_compat_tests`) that used to live
# here will return in a later PR alongside the Rust-side harness
# binary; until then, drive the scenarios directly with `bun test`.

phase="all"

for arg in "$@"; do
  case "$arg" in
    phase0|phase1|phase2|phase3|all) phase="$arg" ;;
    --skip-build) ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

if [ "$phase" = "all" ]; then
  exec bun test
else
  exec bun test "tests/$phase"
fi
