#!/usr/bin/env bash
# run-against-both.sh — Run client integration tests against both TS and Rust servers.
#
# Usage:
#   bash run-against-both.sh              # build Rust, start both, test both
#   bash run-against-both.sh --skip-build # skip cargo build
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REF_SERVER_DIR="$PROJECT_ROOT/compat-tests/reference-server"
RUST_SERVER_DIR="$PROJECT_ROOT/compat-tests/rust-server"
CLIENT_DIR="$SCRIPT_DIR"

TS_PORT=3100
RUST_PORT=3200
TS_PID=""
RUST_PID=""
SKIP_BUILD=false

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
  if [[ -n "$TS_PID" ]] && kill -0 "$TS_PID" 2>/dev/null; then
    kill "$TS_PID" 2>/dev/null || true
    wait "$TS_PID" 2>/dev/null || true
  fi
  if [[ -n "$RUST_PID" ]] && kill -0 "$RUST_PID" 2>/dev/null; then
    kill "$RUST_PID" 2>/dev/null || true
    wait "$RUST_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
echo "=== Client Integration Tests ==="
echo ""

if ! command -v bun &>/dev/null; then
  echo "ERROR: bun is not available. Install Bun and try again."
  exit 1
fi
echo "  bun $(bun --version) ✓"

if [[ ! -d "$REF_SERVER_DIR/node_modules" ]]; then
  echo "  Installing reference server dependencies..."
  cd "$REF_SERVER_DIR" && bun install
  cd "$PROJECT_ROOT"
fi
echo "  reference-server deps ✓"

if [[ ! -d "$CLIENT_DIR/node_modules" ]]; then
  echo "  Installing client test dependencies..."
  cd "$CLIENT_DIR" && bun install
  cd "$PROJECT_ROOT"
fi
echo "  client-tests deps ✓"
echo ""

# ---------------------------------------------------------------------------
# Build Rust server
# ---------------------------------------------------------------------------
if [[ "$SKIP_BUILD" == "true" ]]; then
  echo "[1/5] Skipping Rust build (--skip-build)"
else
  echo "[1/5] Building Rust compat server..."
  cd "$PROJECT_ROOT"
  if ! cargo build --manifest-path "$RUST_SERVER_DIR/Cargo.toml" 2>&1; then
    echo "FAIL: Rust compat server failed to build."
    exit 1
  fi
  echo "  Build succeeded ✓"
fi
echo ""

# ---------------------------------------------------------------------------
# Start TS reference server
# ---------------------------------------------------------------------------
echo "[2/5] Starting TS reference server on port $TS_PORT..."
cd "$REF_SERVER_DIR"
PORT=$TS_PORT bun run server.mjs &
TS_PID=$!
cd "$PROJECT_ROOT"

READY=false
for _ in $(seq 1 30); do
  if curl -sf "http://localhost:$TS_PORT/__health" >/dev/null 2>&1; then
    READY=true
    break
  fi
  sleep 0.5
done

if [[ "$READY" != "true" ]]; then
  echo "FAIL: TS reference server did not become ready."
  exit 1
fi
echo "  TS server ready (PID $TS_PID) ✓"
echo ""

# ---------------------------------------------------------------------------
# Start Rust server
# ---------------------------------------------------------------------------
echo "[3/5] Starting Rust compat server on port $RUST_PORT..."
cd "$PROJECT_ROOT"
PORT=$RUST_PORT cargo run --manifest-path "$RUST_SERVER_DIR/Cargo.toml" &
RUST_PID=$!

READY=false
for _ in $(seq 1 60); do
  if curl -sf "http://localhost:$RUST_PORT/__health" >/dev/null 2>&1; then
    READY=true
    break
  fi
  sleep 0.5
done

if [[ "$READY" != "true" ]]; then
  echo "FAIL: Rust compat server did not become ready within 30s."
  exit 1
fi
echo "  Rust server ready (PID $RUST_PID) ✓"
echo ""

# ---------------------------------------------------------------------------
# Run tests against TS
# ---------------------------------------------------------------------------
echo "[4/5] Running client tests against TS server..."
cd "$CLIENT_DIR"
TS_EXIT=0
AUTH_BASE_URL="http://localhost:$TS_PORT" bun test tests/ 2>&1 | tee /tmp/client-test-ts.log || TS_EXIT=$?

if [[ "$TS_EXIT" -eq 0 ]]; then
  echo "  TS tests: PASS ✓"
else
  echo "  TS tests: FAIL (exit $TS_EXIT)"
fi
echo ""

# ---------------------------------------------------------------------------
# Run tests against Rust
# ---------------------------------------------------------------------------
echo "[5/5] Running client tests against Rust server..."
RUST_EXIT=0
AUTH_BASE_URL="http://localhost:$RUST_PORT" bun test tests/ 2>&1 | tee /tmp/client-test-rust.log || RUST_EXIT=$?

if [[ "$RUST_EXIT" -eq 0 ]]; then
  echo "  Rust tests: PASS ✓"
else
  echo "  Rust tests: FAIL (exit $RUST_EXIT)"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "====================================="
echo "    Client Integration Test Summary"
echo "====================================="

TOTAL_FAIL=0

if [[ "$TS_EXIT" -eq 0 ]]; then
  echo "  [PASS] TS reference server"
else
  echo "  [FAIL] TS reference server"
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi

if [[ "$RUST_EXIT" -eq 0 ]]; then
  echo "  [PASS] Rust compat server"
else
  echo "  [FAIL] Rust compat server"
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi

echo ""
if [[ "$TOTAL_FAIL" -eq 0 ]]; then
  echo "Result: BOTH SERVERS PASS ✓"
  exit 0
else
  echo "Result: $TOTAL_FAIL SERVER(S) FAILED ✗"
  echo ""
  echo "Logs:"
  echo "  /tmp/client-test-ts.log"
  echo "  /tmp/client-test-rust.log"
  exit 1
fi
