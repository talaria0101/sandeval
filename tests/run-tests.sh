#!/usr/bin/env bash
# run-tests.sh — self-test suite for landlock-surface-sweep.sh (issue #14).
#
# No framework, no root required, no sandbox enforcement needed: the sweep is
# exercised against two plain temp dirs so the *engine* (arg handling, verdict
# classification, baseline round-trip, --expect, idempotency, completion
# invariants) is validated deterministically. Runs the sweep with tiny
# LANDSCAN_* limits; expected-verdict correctness is policy-specific and is
# the operator's job (exit 1 just means "unexpected verdicts exist").
#
# Usage: tests/run-tests.sh [path/to/landlock-surface-sweep.sh]
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SWEEP=${1:-$ROOT/sweep/landlock-surface-sweep.sh}
FAIL=0
ok(){ echo "  ok: $*"; }
bad(){ echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
TD=$(mktemp -d "$ROOT/.testrun.XXXXXX")   # under the repo, never /tmp
trap 'rm -rf "$TD"' EXIT
GUARD_ENV=(env LANDSCAN_MEMHOG_MB=16 LANDSCAN_FILL_MB=8 LANDSCAN_PIDS_PROBE=25)

echo "== 0. syntax =="
bash -n "$SWEEP" && ok "bash -n" || bad "bash -n"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning "$SWEEP" && ok "shellcheck" || bad "shellcheck"
else
  echo "  skip: shellcheck not installed"
fi

echo "== 1. refusal paths (exit 2, no IN side effect) =="
mkdir -p "$TD/out"
bash "$SWEEP" --baseline >/dev/null 2>&1;        [ $? -eq 2 ] && ok "--baseline without value -> 2 (usage)" || bad "--baseline usage rc"
bash "$SWEEP" "$TD/a" "$TD/a/sub" >/dev/null 2>&1; [ $? -eq 2 ] && ok "OUT under IN -> 2" || bad "OUT under IN rc"
bash "$SWEEP" "$TD/never-created" "$TD/absent-out" >/dev/null 2>&1
if [ $? -eq 2 ] && [ ! -e "$TD/never-created" ]; then ok "missing OUT -> 2, no IN side effect"; else bad "missing OUT handling"; fi
bash "$SWEEP" "$TD/out" "$TD/out2x" >/dev/null 2>&1; [ $? -eq 2 ] && ok "missing positional -> 2" || bad "missing positional rc"
bash "$SWEEP" a b c >/dev/null 2>&1; [ $? -eq 2 ] && ok "extra positional -> 2" || bad "extra positional rc"
bash "$SWEEP" --bogus x y >/dev/null 2>&1; [ $? -eq 2 ] && ok "unknown opt -> 2" || bad "unknown opt rc"
bash "$SWEEP" --check "$TD/nope.tsv" "$TD/in" "$TD/out" >/dev/null 2>&1
[ $? -eq 2 ] && ok "unreadable --check -> 2 (fail loud)" || bad "unreadable --check not fatal"

echo "== 2. completion invariant (full battery, plain dirs) =="
mkdir -p "$TD/in" "$TD/out2"
OUT_LOG="$TD/run1.log"
"${GUARD_ENV[@]}" bash "$SWEEP" --baseline "$TD/v1.tsv" "$TD/in" "$TD/out2" >"$TD/run1.log" 2>&1
rc=$?
grep -q '=== SUMMARY ===' "$TD/run1.log" && ok "reached summary" || bad "no summary (abort?)"
grep -q 'SWEEP COMPLETE' "$TD/run1.log" && ok "completion marker" || bad "no SWEEP COMPLETE marker"
[ $rc -eq 0 ] || [ $rc -eq 1 ] && ok "exit code $rc in {0,1}" || bad "exit code $rc"
tot=$(awk -F'[ .]+' '/^checks:/{print $2}' "$TD/run1.log")
bl=$(wc -l < "$TD/v1.tsv")
[ -n "$tot" ] && [ "$tot" -gt 50 ] && [ "$bl" -eq "$tot" ] && ok "baseline lines ($bl) == checks ($tot)" || bad "baseline ($bl) vs checks ($tot) mismatch"
grep -q 'UNEXPECTED' "$TD/run1.log" && ok "summary counts present" || bad "no UNEXPECTED line"

echo "== 3. rc=127 poison regression test (issue #1 class) =="
mkdir -p "$TD/shadow" "$TD/in3"
printf '#!/bin/sh\nexit 127\n' > "$TD/shadow/timeout"; chmod +x "$TD/shadow/timeout"
PATH="$TD/shadow:$PATH" "${GUARD_ENV[@]}" bash "$SWEEP" "$TD/in3" "$TD/out2" >"$TD/run127.log" 2>&1
false_denies=$(grep -E '^\[(ok|!!)\]' "$TD/run127.log" | grep -vE ' (knob-core-pattern|knob-modprobe) ' | grep -vc 'got=inconclusive' || true)  # knobs don't exec via timeout by design
if [ "$false_denies" -eq 0 ]; then ok "exec-failure(127) never classified deny/allow (all inconclusive)"; else bad "$false_denies checks misclassified under rc127 (poison regression)"; fi
grep -q 'SWEEP COMPLETE' "$TD/run127.log" && ok "completes even with broken timeout" || bad "aborts under broken timeout"

echo "== 4. idempotency: re-run with --check has no false REGRESSION (issue #5) =="
"${GUARD_ENV[@]}" bash "$SWEEP" --check "$TD/v1.tsv" "$TD/in" "$TD/out2" >"$TD/run2.log" 2>&1
regs=$(grep -c '  REGRESSION ' "$TD/run2.log" || true)
[ "$regs" -eq 0 ] && ok "second run: 0 REGRESSION lines" || bad "second run: $regs false REGRESSION lines"

echo "== 5. --expect overrides apply (issue #3) =="
printf 'out-write allow\n' > "$TD/exp.tsv"   # out-write on a plain writable OUT: got=allow
"${GUARD_ENV[@]}" bash "$SWEEP" --expect "$TD/exp.tsv" "$TD/in" "$TD/out2" >"$TD/run3.log" 2>&1
line=$(grep -E '^\S+ out-write ' "$TD/run3.log" || true)
case "$line" in *"[ok]"*) ok "--expect out-write allow -> [ok]";; *) bad "--expect not applied: $line";; esac

echo "== 6. baseline round-trip diff (IMPROVED/REGRESSION logic) =="
sed 's/^out-write\tallow/out-write\tdeny/' "$TD/v1.tsv" > "$TD/v1-mut.tsv"   # observed allow, baseline mutated to claim deny
"${GUARD_ENV[@]}" bash "$SWEEP" --check "$TD/v1-mut.tsv" "$TD/in" "$TD/out2" >"$TD/run4.log" 2>&1
n_reg=$(grep -c '  REGRESSION out-write:' "$TD/run4.log" || true)
n_all=$(grep -cE '^  (IMPROVED|REGRESSION|CHANGED|NEW) ' "$TD/run4.log" || true)
[ "$n_reg" -eq 1 ] && [ "$n_all" -eq 1 ] && ok "want=deny: exactly one REGRESSION out-write" || bad "REGRESSION run: reg=$n_reg total=$n_all"
printf 'out-write allow\n' > "$TD/exp6.tsv"   # flip want: o=deny, got=allow, want=allow -> IMPROVED
"${GUARD_ENV[@]}" bash "$SWEEP" --expect "$TD/exp6.tsv" --check "$TD/v1-mut.tsv" "$TD/in" "$TD/out2" >"$TD/run5.log" 2>&1
n_imp=$(grep -c '  IMPROVED out-write:' "$TD/run5.log" || true)
n_all=$(grep -cE '^  (IMPROVED|REGRESSION|CHANGED|NEW) ' "$TD/run5.log" || true)
[ "$n_imp" -eq 1 ] && [ "$n_all" -eq 1 ] && ok "want=allow: exactly one IMPROVED out-write" || bad "IMPROVED run: imp=$n_imp total=$n_all"

echo "== 7. secret scrub: no env content in telemetry (issue #6) =="
mkdir -p "$TD/in7"; printf 'SENTINEL_SECRET_VALUE_12345' > "$TD/out2/seedfile"
"${GUARD_ENV[@]}" bash "$SWEEP" --baseline "$TD/v7.tsv" "$TD/in7" "$TD/out2" >/dev/null 2>&1
if grep -rq 'SENTINEL_SECRET_VALUE' "$TD/v7.tsv" "$TD"/run*.log 2>/dev/null; then bad "secret-shaped content leaked into telemetry"; else ok "no secret-shaped content in baseline/logs"; fi
rm -f "$TD/out2/seedfile"
echo "== 8. zero-flag auto mode: heuristics + auto-baseline + auto-diff + --adopt =="
AW="$TD/autowd"; mkdir -p "$AW"
G=(env LANDSCAN_MEMHOG_MB=16 LANDSCAN_FILL_MB=8 LANDSCAN_PIDS_PROBE=25)
( cd "$AW" && "${G[@]}" bash "$SWEEP" >auto1.log 2>&1; echo $? >rc1 )
grep -q 'SWEEP COMPLETE' "$AW/auto1.log" && ok "auto run completes with no dirs/flags" || bad "auto run aborted"
[ -f "$AW/.landscan-state/latest.tsv" ] && ok "auto baseline + state dir" || bad "no auto baseline"
[ "$(cat "$AW/rc1")" -le 1 ] && ok "auto rc in {0,1}" || bad "auto rc=$(cat "$AW/rc1")"
( cd "$AW" && "${G[@]}" bash "$SWEEP" >auto2.log 2>&1 )
[ "$(grep -c '  REGRESSION ' "$AW/auto2.log")" -eq 0 ] && ok "auto re-run: auto-diff, no false regressions" || bad "auto re-run regressions"
( cd "$AW" && "${G[@]}" bash "$SWEEP" --adopt >auto3.log 2>&1 )
[ -f "$AW/.landscan-state/expect.tsv" ] && ok "--adopt wrote expect table" || bad "no expect table"
( cd "$AW" && "${G[@]}" bash "$SWEEP" >auto4.log 2>&1 )
u1=$(grep -c '^\[!!\]' "$AW/auto1.log" || true); u4=$(grep -c '^\[!!\]' "$AW/auto4.log" || true)
if [ "$u4" -lt "$u1" ] && [ "$u4" -le 2 ]; then ok "adoption cut unexpecteds ($u1 -> $u4)"; else bad "adoption ineffective ($u1 -> $u4)"; fi

echo
echo "== 9. sandeval vector harness self-tests =="
if command -v python3 >/dev/null 2>&1; then
  if python3 "$ROOT/tests/test_harness.py"; then ok "python harness tests"; else bad "python harness tests"; fi
else
  echo "  skip: python3 not installed"
fi

echo
if [ "$FAIL" -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "$FAIL TEST GROUP(S) FAILED"; exit 1; fi
