#!/usr/bin/env bash
set -euo pipefail

phase="all"

for arg in "$@"; do
  case "$arg" in
    phase0|phase1|phase2|phase3|all) phase="$arg" ;;
    --skip-build) ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

case "$phase" in
  phase0) test_name="phase0_client_compat" ;;
  phase1) test_name="phase1_client_compat" ;;
  phase2) test_name="phase2_client_compat" ;;
  phase3) test_name="phase3_client_compat" ;;
  all) test_name="full_client_compat" ;;
esac

cargo test --test client_compat_tests "$test_name" -- --ignored --nocapture
