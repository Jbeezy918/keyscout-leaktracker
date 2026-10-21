#!/usr/bin/env bash
# NUC / local runner for KeyScout Leak Tracker MVP.
# Never sends provider reports. Never validates keys.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ -x "$ROOT/.venv/bin/python" ]]; then PYTHON="$ROOT/.venv/bin/python"; else PYTHON=python3; fi
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export LEAKTRACKER_DATA="${LEAKTRACKER_DATA:-$ROOT/data}"
export LEAKTRACKER_DASHBOARD="${LEAKTRACKER_DASHBOARD:-$ROOT/dashboard/public}"
export LEAKTRACKER_DRAFTS="${LEAKTRACKER_DRAFTS:-$ROOT/drafts/reports}"
mkdir -p "$LEAKTRACKER_DATA" "$LEAKTRACKER_DASHBOARD" "$LEAKTRACKER_DRAFTS"

cmd="${1:-all}"
shift || true

case "$cmd" in
  seed) "$PYTHON" -m leaktracker.cli seed "$@" ;;
  watch) "$PYTHON" -m leaktracker.cli watch "$@" ;;
  reweekly) "$PYTHON" -m leaktracker.cli weekly "$@" ;;
  check) "$PYTHON" -m leaktracker.cli recheck "$@" ;;
  drafts) "$PYTHON" -m leaktracker.cli drafts "$@" ;;
  dashboard) "$PYTHON" -m leaktracker.cli dashboard "$@" ;;
  weekly) "$PYTHON" -m leaktracker.cli weekly "$@" ;;
  check) "$PYTHON" -m leaktracker.cli check "$@" ;;
  all) "$PYTHON" -m leaktracker.cli all --seed --seconds "${LEAKTRACKER_SECONDS:-90}" "$@" ;;
  test) "$PYTHON" -m pytest "$ROOT/tests" -q "$@" ;;
  serve)
    cd "$LEAKTRACKER_DASHBOARD" && "$PYTHON" -m http.server "${PORT:-8765}"
    ;;
  *)
    echo "Usage: $0 {seed|watch|recheck|drafts|dashboard|weekly|check|all|test|serve}" >&2
    exit 2
    ;;
esac
