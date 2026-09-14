#!/usr/bin/env bash
# verify.sh — host-side confirmation for sandeval findings.
#
# Run this OUTSIDE the sandbox, on the host, as the user the daemon runs as.
# It is the scoring step: a vector that reported FAIL is only CONFIRMED when the
# effect is visible here. Nothing in the sandbox's own report counts.
#
#   host-verify/verify.sh            # report what was found
#   host-verify/verify.sh --clean    # remove this harness's markers
#
# The git vector's proof is written by the daemon itself, so it can only be
# checked after the turn that armed it has ended.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="${SANDEVAL_WORKSPACE:-/workspace}"
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

# --- xattr markers written from inside the sandbox (V1, V2, prior PoCs) ----- #
say ""
say "xattr markers on host files:"
python3 - "$WORKSPACE" <<'PY'
import os, sys
workspace = sys.argv[1]
targets = []
for base in ("/etc/resolv.conf", "/etc/hostname", "/home", workspace):
    if os.path.isfile(base):
        targets.append(base)
# walk the user's Local tree and the workspace, but tolerate denials
for base in (os.path.join(os.path.expanduser("~"), "Local"), workspace):
    for root, _d, files in os.walk(base):
        for f in files:
            p = os.path.join(root, f)
            if not os.path.islink(p):
                targets.append(p)
        if len(targets) > 4000:
            break
prefixes = ("user.sandeval", "user.SANDEVAL", "user.poc")
hits = 0
for path in targets:
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
  python3 - "$WORKSPACE" <<'PY'
import os, sys
workspace = sys.argv[1]
prefixes = ("user.sandeval", "user.SANDEVAL", "user.poc")
removed = 0
for base in (workspace, os.path.join(os.path.expanduser("~"), "Local")):
    for root, _d, files in os.walk(base):
        for f in files:
            p = os.path.join(root, f)
            try:
                for name in os.listxattr(p):
                    if name.startswith(prefixes):
                        try:
                            os.removexattr(p, name)
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
