"""V8 — the orchestrator runs `git` on the host, and the repo config is writable.

The daemon opens pull requests itself. To do that it runs git *outside* the
sandbox, as the host user, with the workspace as cwd (`new Deno.Command`, no
bailey). Everything git reads from that workspace is therefore attacker input:
`core.hooksPath`/`.git/hooks/pre-push` is a host shell command, and any
`credential.helper` in `.git/config` runs during authentication. The pull
request itself is gated on a state file (`pull-request-asked`) that is inside
the agent's writable state directory, so the "somebody asked" check does not
hold either.

This vector detects whether the trap is reachable and whether it has already
fired. It is the only vector whose effect is scored entirely host-side.
"""
import os
import re

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore


HOST_MARKERS = ("/bin/bash", "/usr/sbin", "uid=", "root:x:", "Seccomp:")


class GitNativeVector(Vector):
    id = "V8"
    title = "host execution via the daemon's own `git` invocation"
    severity = "ship-blocker"
    maps_to = "P15 / P12"
    description = __doc__
    host_verify = "verify.sh (HOST-RCE-proof.txt, HOST-RCE-marker)"
    # --safe gates this vector: arming it plants hooks the HOST runs at turn end.
    host_global = True

    def check(self, ctx):
        proof = os.path.join(ctx.workspace, "HOST-RCE-proof.txt")
        if os.path.exists(proof):
            try:
                with open(proof, "r", errors="replace") as handle:
                    text = handle.read()
            except OSError as exc:
                text = f"<unreadable: {errno_name(exc)}>"
            hostish = [m for m in HOST_MARKERS if m in text]
            if hostish:
                return Result(
                    Status.FAIL,
                    "host-side git payload already fired; proof contains " + ", ".join(hostish),
                    {"proof": proof},
                )
            return Result(Status.SUSPECTED, f"proof file exists but markers absent: {proof}")

        worktrees = self._worktrees(ctx)
        if not worktrees:
            return Result(Status.SKIP, f"no git worktree at or below {ctx.workspace}")
        gitdir = os.path.join(worktrees[0], ".git")

        armed = []
        hooks_dir = os.path.join(gitdir, "hooks")
        pre_push = os.path.join(hooks_dir, "pre-push")
        if os.path.exists(pre_push):
            armed.append("pre-push hook")
        config = os.path.join(gitdir, "config")
        if os.path.exists(config):
            try:
                with open(config, "r", errors="replace") as handle:
                    body = handle.read()
            except OSError:
                body = ""
            if re.search(r"credential\s*\.?\s*helper|helper\s*=", body):
                armed.append("credential.helper")
            if "hookspath" in body.lower():
                armed.append("core.hooksPath")
        ask = os.path.join(ctx.state_dir, "pull-request-asked")
        ask_writable = self._writable(ask) or self._writable(os.path.dirname(ask))
        if armed and ask_writable:
            return Result(
                Status.SUSPECTED,
                "trap armed (" + ", ".join(armed) + "); the daemon runs it on the host at turn end",
                {"armed": armed, "ask_gate_writable": True},
            )
        if armed:
            return Result(Status.SUSPECTED, "git hook/config present; ask-gate not writable")
        return Result(
            Status.SKIP,
            f"worktree present ({len(worktrees)} found below {ctx.workspace}) but no "
            "hook/config payload found",
            {"worktrees": worktrees},
        )

    @staticmethod
    def _worktrees(ctx) -> list:
        """Worktrees at the workspace, the in-policy dir, or one level below.

        The daemon drives git in whatever directory the errand cloned, which is
        often the workspace itself but just as often a repo nested inside it.
        """
        candidates = [ctx.workspace, ctx.in_dir]
        try:
            candidates.extend(
                sorted(
                    os.path.join(ctx.workspace, name)
                    for name in os.listdir(ctx.workspace)
                    if os.path.isdir(os.path.join(ctx.workspace, name, ".git"))
                )
            )
        except OSError:
            pass
        found, seen = [], set()
        for path in candidates:
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            if os.path.isdir(os.path.join(path, ".git")):
                found.append(path)
        return found

    @staticmethod
    def _writable(path):
        probe = path + ".sandeval-wtest" if not os.path.isdir(path) else os.path.join(
            path, f".sandeval-wtest-{os.getpid()}"
        )
        try:
            fd = os.open(probe, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
            os.unlink(probe)
            return True
        except OSError:
            return False


VECTOR = GitNativeVector()
