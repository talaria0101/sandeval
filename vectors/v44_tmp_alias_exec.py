"""V44 - the declared execute list does not describe where code can run.

`policy.toml` states `execute = [...]` as a list of path strings, and a reader
of that file concludes which directories hold runnable code. This vector asks
whether the list predicts the behaviour it claims to.

Three locations are written with the same known ELF and exec'd:

  a. the state directory root - the list does not name it, so it must refuse
  b. the state directory's `tmp` subdir - also unnamed by the list
  c. `/tmp` - also unnamed by the list
  plus a workspace file as the control that `exec` works at all here

Both (b) and (c) are the same directory on the same filesystem: `/tmp` is a
bind mount whose root is the state dir's `tmp` subtree, so the two paths are
one object. Landlock attaches a grant to that object rather than to the
string used to reach it, and bailey grants read+write on the private `/tmp`
for every isolated world. `AccessFs::from_read()` carries `Execute`
(landlock crate, `fs.rs`), so the private-`/tmp` grant is also an execute
grant, and it reaches `/state/tmp` through the alias while the root of
`/state` stays refused.

Measured, not assumed: the verdict is written only when (a) refuses and the
workspace control runs, so "exec is enforced" and "exec is enforced
everywhere the list does not name" are separable claims.
"""
import errno as errno_mod
import os
import re

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

PAYLOAD_NAME = ".sandeval-v44.bin"
EXECUTE_LINE = re.compile(r"^\s*execute\s*=\s*\[(.*?)\]", re.S | re.M)
QUOTED = re.compile(r"\"([^\"]+)\"")
BIND = re.compile(r"\{\s*path\s*=\s*\"([^\"]+)\"\s*,\s*at\s*=\s*\"([^\"]+)\"\s*,?\s*\}")
CRASH = 97
WANT = 42
ELF_SOURCE = "/bin/sh"
MAX_PAYLOAD = 4 * 1024 * 1024


def _payload():
    try:
        with open(ELF_SOURCE, "rb") as handle:
            data = handle.read(MAX_PAYLOAD)
    except OSError:
        return b""
    return data if data.startswith(b"\x7fELF") else b""


def _attempt_exec(path):
    """Run ``sh -c 'exit 42'`` from ``path`` in a child; return rc and errno."""
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_end)
        try:
            os.execve(path, ["sh", "-c", "exit 42"], os.environ.copy())
        except OSError as exc:
            os.write(write_end, str(exc.errno or 0).encode())
            os._exit(CRASH)
        os._exit(CRASH)
    os.close(write_end)
    raw = b""
    try:
        while True:
            chunk = os.read(read_end, 64)
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(read_end)
    rc = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
    if rc == CRASH:
        code = int(raw or b"0")
        return rc, errno_mod.errorcode.get(code, str(code))
    return rc, ""


def _declared_execute(policy_text):
    """Paths the policy's own ``execute`` list names, aliases resolved."""
    match = EXECUTE_LINE.search(policy_text or "")
    if not match:
        return []
    aliases = {host: sandbox for host, sandbox in BIND.findall(policy_text or "")}
    out = []
    for path in QUOTED.findall(match.group(1)):
        out.append(aliases.get(path, path))
    return list(dict.fromkeys(out))


class TmpAliasExecVector(Vector):
    id = "V44"
    title = "private /tmp grant executes code at a path the execute list does not name"
    severity = "high"
    maps_to = "P2 / P9"
    description = __doc__
    host_verify = "verify.sh (none: the payload exits 42 in a child)"

    def check(self, ctx):
        payload = _payload()
        if not payload:
            return Result(Status.SKIP, f"{ELF_SOURCE} is not an ELF: no payload to run")

        state = (ctx.state_dir or "/state").rstrip("/")
        declared = _declared_execute(ctx._policy_text())
        detail = {
            "declared_execute": declared,
            "payload": ELF_SOURCE,
            "attempts": {},
            "same_object": False,
        }

        named = {
            state: "state root",
            os.path.join(state, "tmp"): "state tmp subdir",
            "/tmp": "/tmp",
            ctx.workspace or "/workspace": "workspace",
        }
        seeds = []
        for path, label in named.items():
            if not path or not os.path.isdir(path):
                detail["attempts"][label] = {"rc": CRASH, "errno": "no such dir"}
                continue
            target = os.path.join(path, PAYLOAD_NAME)
            try:
                with open(target, "wb") as handle:
                    handle.write(payload)
                os.chmod(target, 0o755)
            except OSError as exc:
                detail["attempts"][label] = {"rc": CRASH, "errno": errno_name(exc)}
                continue
            seeds.append(target)
            rc, err = _attempt_exec(target)
            detail["attempts"][label] = {
                "path": target,
                "rc": rc,
                "errno": err,
                "ran": err == "",
                "declared": path in declared,
            }

        try:
            tmp_stat = os.stat("/tmp")
            state_tmp_stat = os.stat(os.path.join(state, "tmp"))
            detail["same_object"] = (
                tmp_stat.st_dev == state_tmp_stat.st_dev
                and tmp_stat.st_ino == state_tmp_stat.st_ino
            )
            detail["tmp_ino"] = tmp_stat.st_ino
            detail["state_tmp_ino"] = state_tmp_stat.st_ino
            detail["tmp_dev"] = tmp_stat.st_dev
        except OSError as exc:
            detail["same_object_error"] = errno_name(exc)

        attempts = detail["attempts"]
        state_root = attempts.get("state root", {})
        workspace = attempts.get("workspace", {})
        unnamed_runs = [
            label
            for label in ("state tmp subdir", "/tmp")
            if attempts.get(label, {}).get("ran")
            and not attempts.get(label, {}).get("declared")
        ]

        if not workspace.get("ran"):
            return Result(
                Status.SKIP,
                "control failed: the workspace file did not run, so a refusal "
                f"elsewhere means nothing here ({workspace.get('errno')})",
                detail,
            )
        if state_root.get("ran"):
            return Result(
                Status.PASS,
                "the state root executes even though the policy does not name it: "
                "the declared execute list is not the whole truth either way",
                detail,
            )
        if unnamed_runs and detail["same_object"]:
            return Result(
                Status.FAIL,
                f"{', '.join(unnamed_runs)} ran code from an execute-granted file "
                "while the state root refused it: the private /tmp grant reaches the "
                "state tmp subtree by alias, so the declared execute list does not "
                "predict where code can run",
                detail,
            )
        if unnamed_runs:
            return Result(
                Status.FAIL,
                f"{', '.join(unnamed_runs)} ran code at a path the policy execute "
                f"list does not name ({state_root.get('errno')} at the state root)",
                detail,
            )
        return Result(
            Status.PASS,
            "every location the policy does not name refused the payload, and the "
            "workspace control ran: the declared execute list predicts execution",
            detail,
        )

    def cleanup(self, ctx):
        state = (ctx.state_dir or "/state").rstrip("/")
        removed = []
        for directory in (state, os.path.join(state, "tmp"), "/tmp", ctx.workspace or ""):
            if not directory:
                continue
            candidate = os.path.join(directory, PAYLOAD_NAME)
            try:
                os.unlink(candidate)
                removed.append(candidate)
            except OSError:
                pass
        return Result(Status.INFO, f"removed {len(removed)} payload file(s)")


VECTOR = TmpAliasExecVector()
