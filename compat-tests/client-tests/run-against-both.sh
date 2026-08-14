#!/usr/bin/env bash
set -euo pipefail

phase="all"

for arg in "$@"; do
  case "$arg" in
    phase0|phase1|phase2|phase3|phase4|phase5|phase6|phase7|phase8|phase9|phase10|phase11|phase12|all) phase="$arg" ;;
    --skip-build) ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

case "$phase" in
  phase0) test_name="phase0_client_compat" ;;
  phase1) test_name="phase1_client_compat" ;;
  phase2) test_name="phase2_client_compat" ;;
  phase3) test_name="phase3_client_compat" ;;
  phase4) test_name="phase4_client_compat" ;;
  phase5) test_name="phase5_client_compat" ;;
  phase6) test_name="phase6_client_compat" ;;
  phase7) test_name="phase7_client_compat" ;;
  phase8) test_name="phase8_client_compat" ;;
  phase9) test_name="phase9_client_compat" ;;
  phase10) test_name="phase10_client_compat" ;;
  phase11) test_name="phase11_client_compat" ;;
  phase12) test_name="phase12_client_compat" ;;
  all) test_name="full_client_compat" ;;
esac

cargo test --test client_compat_tests "$test_name" -- --ignored --nocapture
