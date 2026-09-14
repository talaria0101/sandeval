#!/usr/bin/env bash
# run.sh — zero-config entry point: `./run.sh` == `./bin/sandeval run --replica`.
#
# The harness refuses to run without --replica; this wrapper supplies it so a
# fresh agent or operator can start with one command inside a disposable
# replica. Everything after `--` is passed through.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$ROOT/bin/sandeval" run --replica "$@"
