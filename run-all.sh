#!/usr/bin/env bash
# run-all.sh — one command for an operator: sweep + every vector + one report.
#
# Inside a disposable replica:
#   ./run-all.sh
#   ./run-all.sh --json report.json --report report.md --seed "$OUT/seedfile"
# Then, on the HOST:
#   host-verify/verify.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$ROOT/bin/sandeval" auto --replica "$@"
