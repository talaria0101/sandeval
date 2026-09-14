#!/usr/bin/env bash
# run.sh — the one-command run: every vector + the full sweep, unattended.
#
#   ./run.sh
#
# Writes sandeval-report.json, sandeval-report.md and sandeval-sweep.log in
# the working directory; pass your own --json/--report/--sweep-log to move
# them. Any other arguments are passed through to `sandeval auto`.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

has() { local needle="$1"; shift; case " $* " in *" $needle "*) return 0 ;; *) return 1 ;; esac; }

defaults=()
has --json "$@"      || defaults+=(--json sandeval-report.json)
has --report "$@"    || defaults+=(--report sandeval-report.md)
has --sweep-log "$@" || defaults+=(--sweep-log sandeval-sweep.log)

exec python3 "$ROOT/bin/sandeval" auto "${defaults[@]}" "$@"
