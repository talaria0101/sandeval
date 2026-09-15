#!/usr/bin/env bash
# verify.sh — host-side confirmation for sandeval findings.
#
# Run this OUTSIDE the sandbox, on the host, as the user the daemon runs as.
# It is the scoring step: a vector that reported FAIL is only CONFIRMED when the
# effect is visible here. Nothing in the sandbox's own report counts.
#
#   host-verify/verify.sh            # report what was found
#   host-verify/verify.sh --clean    # remove this harness's removable markers
#
# The git vector's proof is written by the daemon itself, so it can only be
# checked after the turn that armed it has ended. Content markers (the
# SAND_EVAL_POC lines V29/V30 append through foreign descriptors and
# hardlinks) are reported but NOT removed by --clean: un-appending host file
# content is an operator decision, and the line is the proof.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="${SANDEVAL_WORKSPACE:-}"
if [ -z "$WORKSPACE" ]; then
  if [ -d /workspace ]; then WORKSPACE=/workspace; else WORKSPACE="$(pwd)"; fi
fi
HOME_DIR="${HOME:-/home/$(id -un 2>/dev/null || echo nobody)}"
MODE="${1:-check}"
findings=0

say()  { printf '%s\n' "$*"; }
found(){ findings=$((findings+1)); say "  FOUND  $*"; }
clear_(){ say "  clear  $*"; }

say "sandeval host verifier"
say "  user:      $(id -un 2>/dev/null) (uid $(id -u 2>/dev/null))"
say "  hostname:  $(hostname 2>/dev/null)"
say "  workspace: $WORKSPACE"
say ""

# --- git-native host execution (V8) ---------------------------------------- #
say "V8 host execution via the daemon's git:"
proof="$WORKSPACE/HOST-RCE-proof.txt"
if [ -f "$proof" ]; then
  found "$proof"
  say "    --- first 6 lines ---"
  sed -n '1,6p' "$proof" | sed 's/^/    /'
  say "    --- host markers present? ---"
  grep -qE 'root:x:|/bin/bash|uid=' "$proof" && say "    yes: host-only content" || say "    no host markers"
fi
for marker in "$HOME_DIR/HOST-RCE-marker" /tmp/HOST-RCE-marker; do
  [ -f "$marker" ] && found "$marker ($(cat "$marker"))"
done
[ -f "$WORKSPACE/HOST-passwd.txt" ] && found "$WORKSPACE/HOST-passwd.txt (host passwd copied out)"
[ -f "$proof" ] || [ -f "$HOME_DIR/HOST-RCE-marker" ] || clear_ "no git payload proof present"

# --- xattr markers written from inside the sandbox (V1, V2, V35, prior PoCs) - #
say ""
say "xattr markers on host files:"
POLICY_FILE="${SANDEVAL_POLICY:-/state/policy.toml}"
[ -f "$POLICY_FILE" ] || POLICY_FILE=""
python3 - "$WORKSPACE" "$HOME_DIR" "$POLICY_FILE" <<'PY'
import os, sys
workspace, home, policy = sys.argv[1], sys.argv[2], sys.argv[3]
extra = [p for p in os.environ.get("SANDEVAL_HOST_FILES", "").split(":") if p]
if policy:
    extra.append(policy)
candidates = ["/etc/resolv.conf", "/etc/hostname", "/etc/hosts"] + extra


def walk(root, depth=0, max_depth=3):
    if depth > max_depth:
        return
    try:
        entries = os.listdir(root)
    except OSError:
        return
    for name in entries:
        path = os.path.join(root, name)
        try:
            if os.path.islink(path):
                continue
            if os.path.isfile(path):
                yield path
            elif os.path.isdir(path):
                yield from walk(path, depth + 1, max_depth)
        except OSError:
            continue


for root in (home, workspace):
    if os.path.isdir(root):
        candidates.extend(walk(root))

prefixes = ("user.sandeval", "user.SANDEVAL", "user.poc")
hits = 0
for path in candidates[:20000]:
    try:
        names = os.listxattr(path)
    except OSError:
        continue
    for name in names:
        if name.startswith(prefixes):
            try:
                size = len(os.getxattr(path, name))
            except OSError:
                size = -1
            print(f"  FOUND  {path}: {name} ({size} bytes)")
            hits += 1
if not hits:
    print("  clear  no xattr markers")
sys.exit(0 if hits == 0 else 3)
PY
case $? in 0) ;; *) findings=$((findings+1));; esac

# --- content markers (V29 foreign-fd / V30 hardlink / V37 core) ------------ #
say ""
say "SAND_EVAL_POC content markers (appended by V29/V30 through allowed-but-"
say "should-be-denied writes; removal is an operator decision, not --clean):"
python3 - "$WORKSPACE" "$HOME_DIR" "$ROOT" <<'PY'
import os, sys
roots = [r for r in (sys.argv[1], sys.argv[2], "/state") if r and os.path.isdir(r)]
exclude_root = os.path.realpath(sys.argv[3]) if len(sys.argv) > 3 else None
needle = b"SAND_EVAL_POC"
hits = 0

def walk(root, depth=0, max_depth=3):
    if depth > max_depth:
        return
    try:
        entries = os.listdir(root)
    except OSError:
        return
    for name in sorted(entries):
        path = os.path.join(root, name)
        try:
            if os.path.islink(path):
                continue
            if os.path.isfile(path):
                yield path
            elif os.path.isdir(path):
                yield from walk(path, depth + 1, max_depth)
        except OSError:
            continue

seen = set()
for root in roots:
    for path in walk(root):
        if path in seen:
            continue
        seen.add(path)
        if exclude_root and os.path.realpath(path).startswith(exclude_root + os.sep):
            continue  # the harness's own sources name the marker; not a finding
        try:
            with open(path, "rb") as handle:
                if needle in handle.read(65536):
                    line = ""
                    with open(path, "rb") as handle:
                        for raw in handle:
                            if needle in raw:
                                line = raw.decode("utf-8", "replace").strip()
                                break
                    print(f"  FOUND  {path}: {line[:120]}")
                    hits += 1
        except OSError:
            continue
        if hits >= 10:
            break
    if hits >= 10:
        break
if not hits:
    print("  clear  no SAND_EVAL_POC content markers")
sys.exit(0 if hits == 0 else 3)
PY
case $? in
  0) ;;
  *) findings=$((findings+1));;
esac

# --- CPU speculative-execution status (V13/V14) ---------------------------- #
say ""
say "CPU speculative-execution status (host view):"
if [ -r /proc/cmdline ]; then
  case "$(cat /proc/cmdline 2>/dev/null)" in
    *mitigations=off*) found "host kernel booted with mitigations=off" ;;
    *) clear_ "no mitigations=off in /proc/cmdline" ;;
  esac
fi
if [ -d /sys/devices/system/cpu/vulnerabilities ]; then
  cpu_hits=0
  for f in /sys/devices/system/cpu/vulnerabilities/*; do
    [ -r "$f" ] || continue
    v=$(cat "$f" 2>/dev/null)
    case "$v" in
      Vulnerable*) found "$(basename "$f"): $v"; cpu_hits=$((cpu_hits+1));;
    esac
  done
  [ "$cpu_hits" -eq 0 ] && clear_ "no 'Vulnerable' entries in /sys/devices/system/cpu/vulnerabilities"
else
  clear_ "/sys/devices/system/cpu/vulnerabilities not present"
fi

# --- tmpfs markers (V3, prior PoCs) ---------------------------------------- #
say ""
say "tmpfs markers:"
for marker in /tmp/SANDEVAL_POC /tmp/SANDEVAL_POC_V2 /dev/shm/SANDEVAL_POC; do
  [ -e "$marker" ] && found "$marker"
done

# --- cleanup --------------------------------------------------------------- #
if [ "$MODE" = "--clean" ]; then
  say ""
  say "cleaning:"
  rm -f "$proof" "$WORKSPACE/HOST-passwd.txt" "$HOME_DIR/HOST-RCE-marker" /tmp/HOST-RCE-marker \
        /tmp/SANDEVAL_POC /tmp/SANDEVAL_POC_V2 /dev/shm/SANDEVAL_POC
  python3 - "$WORKSPACE" "$HOME_DIR" "$POLICY_FILE" <<'PY'
import os, sys
workspace, home, policy = sys.argv[1], sys.argv[2], sys.argv[3]
extra = [p for p in os.environ.get("SANDEVAL_HOST_FILES", "").split(":") if p]
if policy:
    extra.append(policy)


prefixes = ("user.sandeval", "user.SANDEVAL", "user.poc")


def walk(root, depth=0, max_depth=3):
    if depth > max_depth:
        return
    try:
        entries = os.listdir(root)
    except OSError:
        return
    for name in entries:
        path = os.path.join(root, name)
        try:
            if os.path.islink(path):
                continue
            if os.path.isfile(path):
                yield path
            elif os.path.isdir(path):
                yield from walk(path, depth + 1, max_depth)
        except OSError:
            continue


roots = [home, workspace] + [p for p in extra if os.path.isdir(p)]
removed = 0
for root in roots:
    if not os.path.isdir(root):
        continue
    for path in walk(root):
        try:
            for name in os.listxattr(path):
                if name.startswith(prefixes):
                    try:
                        os.removexattr(path, name)
                        removed += 1
                    except OSError:
                        pass
        except OSError:
            continue
for path in extra + [p for p in ("/etc/resolv.conf", "/etc/hostname", policy) if p]:
    try:
        for name in os.listxattr(path):
            if name.startswith(prefixes):
                try:
                    os.removexattr(path, name)
                    removed += 1
                except OSError:
                    pass
    except OSError:
        continue
print(f"  removed {removed} xattr marker(s)")
PY
  say "  done"
  exit 0
fi

say ""
say "$findings finding(s) confirmed host-side"
[ "$findings" -eq 0 ] && exit 0 || exit 1
