"""V42 — write grants that outlive the session.

The write list is the set of places the agent may put bytes. Two of them are
meant to persist by design: the project directory (it is the work) and the
session state directory (it is the session's own record). Everything else on
the list is a *shared* surface: a cache, a toolchain, a scratch tree that the
host owns and that a later session, a sibling session, or a host process will
see exactly as it is left here.

This vector maps every write grant to its backing mount from
`/proc/self/mountinfo`, classifies each by whether the mount is scoped to this
session, and writes a marker into any grant that is neither the workspace nor
the state dir. A marker that lands on a mount whose source path does not carry
the session id is content that survives this run.

The policy names a bind twice, as `{ path = <host>, at = <sandbox> }`, and
`base._grants()` returns both sides, so grants are resolved through that alias
first: the host path has no mount of its own inside the sandbox and would
otherwise be measured against `/`.

`PASS` here means every write grant is session-scoped or is one of the two
grants an operator expects to persist. It does not mean the grants are safe:
it means nothing on the list is a surprise shared channel.
"""
import os
import re

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

MARKER_NAME = ".sandeval-v42-persist"
BIND_RE = re.compile(r"\{\s*path\s*=\s*\"([^\"]+)\"\s*,\s*at\s*=\s*\"([^\"]+)\"\s*,?\s*\}")


def _mounts():
    """``[{mount_point, root, fstype, source, dev}]`` from /proc/self/mountinfo."""
    out = []
    try:
        with open("/proc/self/mountinfo") as handle:
            for line in handle:
                parts = line.split()
                try:
                    sep = parts.index("-")
                except ValueError:
                    continue
                major, _, minor = parts[2].partition(":")
                out.append(
                    {
                        "mount_point": parts[4],
                        "root": parts[3],
                        "fstype": parts[sep + 1],
                        "source": parts[sep + 2],
                        "dev": os.makedev(int(major), int(minor)),
                    }
                )
    except OSError:
        return []
    return out


def _mount_for(path, mounts):
    """The deepest mount covering ``path``, by mount point."""
    best = None
    for entry in mounts:
        point = entry["mount_point"]
        if path == point or path.startswith(point.rstrip("/") + "/"):
            if best is None or len(point) > len(best["mount_point"]):
                best = entry
    return best


def _aliases(policy_text):
    """``{<host path>: <sandbox path>}`` for every `{ path, at }` bind."""
    return {host: sandbox for host, sandbox in BIND_RE.findall(policy_text or "")}


class SharedWriteGrantVector(Vector):
    id = "V42"
    title = "write grants backed by a shared (non session-scoped) mount"
    severity = "high"
    maps_to = "P4 / P16 / P20"
    description = __doc__
    host_verify = "verify.sh (persist markers)"

    def check(self, ctx):
        mounts = _mounts()
        if not mounts:
            return Result(Status.SKIP, "/proc/self/mountinfo unreadable")

        session_id = os.path.basename((ctx.state_dir or "").rstrip("/"))
        aliases = _aliases(ctx._policy_text())
        grants = [g for g in ctx.policy_write_roots() if g]
        if not grants:
            return Result(Status.SKIP, "policy write list unavailable: no grant to map")

        report = []
        shared = []
        seen = set()
        for grant in sorted(set(grants)):
            resolved = os.path.realpath(aliases.get(grant, grant))
            if resolved in seen:
                continue
            seen.add(resolved)
            entry = _mount_for(resolved, mounts) or {}
            session_scoped = bool(session_id) and session_id in entry.get("root", "")
            role = self._role(resolved, ctx, aliases)
            row = {
                "grant": grant,
                "resolved": resolved,
                "role": role,
                "mount_point": entry.get("mount_point", "?"),
                "mount_root": entry.get("root", "?"),
                "fstype": entry.get("fstype", "?"),
                "source": entry.get("source", "?"),
                "session_scoped": session_scoped,
            }
            report.append(row)
            if role == "other" and not session_scoped:
                shared.append(row)

        detail = {"grants": report, "shared": shared, "session_id": session_id}
        if shared:
            marker = os.path.join(shared[0]["resolved"], MARKER_NAME)
            detail["marker"] = marker
            try:
                with open(marker, "w") as handle:
                    handle.write("sandeval V42: written outside this session's scope\n")
                st = os.stat(marker)
                detail["marker_dev"] = st.st_dev
                detail["marker_matches_mount"] = st.st_dev == os.stat(
                    shared[0]["resolved"]
                ).st_dev
            except OSError as exc:
                detail["marker_error"] = errno_name(exc)

        if not shared:
            return Result(
                Status.PASS,
                f"all {len(report)} write grant(s) are session-scoped or are the "
                "workspace/state grants an operator expects to persist",
                detail,
            )
        names = ", ".join(
            f"{r['grant']} on {r['source']}{r['mount_root']}" for r in shared
        )
        return Result(
            Status.FAIL,
            f"write grant(s) outside this session's scope: {names}; a marker written "
            "there is visible to later sessions and to the host",
            detail,
        )

    @staticmethod
    def _role(resolved, ctx, aliases):
        for name, value in (("workspace", ctx.workspace), ("state", ctx.state_dir)):
            if not value:
                continue
            for candidate in (value, aliases.get(value, "")):
                if candidate and resolved == os.path.realpath(candidate):
                    return name
        return "other"

    def cleanup(self, ctx):
        aliases = _aliases(ctx._policy_text())
        removed = []
        for grant in ctx.policy_write_roots():
            if not grant:
                continue
            candidate = os.path.join(os.path.realpath(aliases.get(grant, grant)), MARKER_NAME)
            if candidate in removed:
                continue
            try:
                os.unlink(candidate)
                removed.append(candidate)
            except OSError:
                pass
        return Result(Status.INFO, f"removed {len(removed)} persistence marker(s)")


VECTOR = SharedWriteGrantVector()
