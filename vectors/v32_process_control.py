"""V32 — process control over the orchestrator: signals, priority, OOM.

Same-uid processes can be signalled, re-niced and OOM-tuned by each other
unless a pid namespace or seccomp intervenes. Landlock has no opinion here:
it mediates paths, not process control. This vector probes four primitives
against the orchestrator (pid 1 and the daemon's own processes) without ever
disturbing them: `kill(pid, 0)` (permission check, no signal),
`pidfd_send_signal` with signal 0, `setpriority` to the target's CURRENT
nice value (a no-op write), and a same-value write-back of
`/proc/<pid>/oom_score_adj`. Any success is a denial-of-service primitive:
SIGSTOP the daemon at will, park it at nice 19, or set OOM-immunity, and
with a pipe `core_pattern` (V37) it chains to host-root code execution.
"""
import ctypes
import os

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

try:
    from _common import libc, raw_syscall, visible_pids
except ImportError:
    from _common import libc, raw_syscall, visible_pids  # type: ignore

SYS_PIDFD_OPEN = 434
SYS_PIDFD_SEND_SIGNAL = 424


def daemon_pids():
    """pid 1 plus any process whose cmdline names the daemon runtime."""
    pids = []
    for pid in visible_pids(limit=48, exclude={os.getpid()}):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                cmdline = handle.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if any(token in cmdline for token in ("errand", "pi --mode rpc", "mode rpc", "--session-dir")):
            pids.append(pid)
    if os.path.exists("/proc/1") and 1 not in pids:
        pids.append(1)
    return pids[:3] or [1]


class ProcessControlVector(Vector):
    id = "V32"
    title = "signal / scheduler control over the orchestrator (sig 0 probes)"
    severity = "high"
    maps_to = "P12 / V5 / V37"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        targets = daemon_pids()
        results, successes = {}, []
        for pid in targets:
            results[pid] = {}

            # 1. kill(pid, 0): classic permission probe, no signal sent.
            try:
                os.kill(pid, 0)
                results[pid]["kill0"] = "ok"
            except OSError as exc:
                results[pid]["kill0"] = errno_name(exc)

            # 2. pidfd_send_signal with sig 0: same check through the newer API.
            try:
                libc()
                pd, err = raw_syscall(SYS_PIDFD_OPEN, pid, 0)
                if pd < 0:
                    results[pid]["pidfd_sig0"] = errno_name(OSError(err, "pidfd_open"))
                else:
                    res, err = raw_syscall(
                        SYS_PIDFD_SEND_SIGNAL, pd, 0, ctypes.c_void_p(0), 0
                    )  # sig=0, info=NULL, flags=0
                    os.close(pd)
                    results[pid]["pidfd_sig0"] = errno_name(OSError(err, "pidfd_send_signal"))
            except OSError as exc:
                results[pid]["pidfd_sig0"] = errno_name(exc)

            # 3. setpriority to the CURRENT value: proves the write primitive
            #    without changing the target's scheduling.
            try:
                cur = os.getpriority(os.PRIO_PROCESS, pid)
                os.setpriority(os.PRIO_PROCESS, pid, cur)
                results[pid]["setpriority"] = f"ok (nice stays {cur})"
            except OSError as exc:
                results[pid]["setpriority"] = errno_name(exc)

            # 4. oom_score_adj write-back of its own value.
            try:
                with open(f"/proc/{pid}/oom_score_adj") as handle:
                    cur = handle.read().strip()
                with open(f"/proc/{pid}/oom_score_adj", "w") as handle:
                    handle.write(cur)
                results[pid]["oom_adj"] = f"ok (stays {cur})"
            except OSError as exc:
                results[pid]["oom_adj"] = errno_name(exc)

            for name, res in results[pid].items():
                if str(res).startswith("ok"):
                    successes.append(f"pid {pid} {name}: {res}")

        detail = {"targets": targets, "results": results,
                  "note": "no signal was delivered; sig 0 and same-value writes only"}
        if successes:
            return Result(
                Status.FAIL,
                "orchestrator process control reachable (DoS primitive): " + "; ".join(successes[:4]),
                detail,
            )
        return Result(
            Status.PASS,
            f"every process-control primitive denied on {len(targets)} target(s) "
            f"({results[targets[0]] if targets else 'no target'})",
            detail,
        )


VECTOR = ProcessControlVector()
