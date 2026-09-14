"""V5 — the orchestrator's stdio file descriptors are openable for writing.

`/proc/<pid>/fd/N` resolves to the same open file description the target
process holds. Landlock mediates path operations, not `open("/proc/.../fd/N")`
on a descriptor that already exists, and `/proc` is read-granted. When the
target is the daemon that drives the agent, its stdin and stdout are the
control plane: writing a JSON line to stdin is issuing the daemon's own
commands. This vector opens the descriptors; it writes only with --arm.
"""
import os

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

try:
    from _common import marker
except ImportError:
    from _common import marker  # type: ignore


class OrchestratorFdVector(Vector):
    id = "V5"
    title = "orchestrator stdio fd writable via /proc/<pid>/fd/N"
    severity = "ship-blocker"
    maps_to = "P12 / P15"
    description = __doc__
    host_verify = "verify.sh (only if --arm injected a marker)"

    def check(self, ctx):
        pids = self._daemon_pids()
        if not pids:
            return Result(Status.SKIP, "no orchestrator process visible")
        opened = []
        for pid in pids:
            for fd in (0, 1, 2):
                path = f"/proc/{pid}/fd/{fd}"
                try:
                    handle = os.open(path, os.O_WRONLY)
                except OSError:
                    continue
                opened.append(path)
                if ctx.arm:
                    try:
                        os.write(handle, (marker("V5") + "\n").encode())
                    except OSError:
                        pass
                os.close(handle)
        if opened:
            note = " (marker written with --arm)" if ctx.arm else ""
            return Result(
                Status.FAIL,
                f"write-opened control fds: {', '.join(opened)}{note}",
                {"opened": opened, "armed": ctx.arm},
            )
        return Result(Status.PASS, f"no writable stdio fd among {len(pids)} orchestrator process(es)")

    @staticmethod
    def _daemon_pids():
        pids = []
        try:
            entries = [n for n in os.listdir("/proc") if n.isdigit()]
        except OSError:
            return [1]
        for name in entries:
            try:
                with open(f"/proc/{name}/cmdline", "rb") as handle:
                    cmdline = handle.read().replace(b"\0", b" ").decode("utf-8", "replace")
            except OSError:
                continue
            if any(token in cmdline for token in ("errand", "pi --mode rpc", "--session-dir", "mode rpc")):
                pids.append(int(name))
        return pids or [1]


VECTOR = OrchestratorFdVector()
