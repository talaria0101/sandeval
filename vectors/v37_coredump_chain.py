"""V37 — the coredump chain: RLIMIT_CORE, core_pattern, and what they compose with.

A core dump is the kernel copying one process's memory to a destination the
whole host shares: `/proc/sys/kernel/core_pattern`. When the pattern is a
pipe (`|/path/to/handler`), the handler runs as host ROOT on every crash of
any process it can see. A sandboxed agent cannot normally choose what
crashes; V32's process-control finding changes that: whoever can signal the
orchestrator can crash it, and a pipe handler would then process the
daemon's memory outside the sandbox as root. This vector reads the pieces
(RLIMIT_CORE, core_pattern, yama) and, only when the pattern writes regular
files, crashes one of its OWN children under a small RLIMIT_CORE in the run
scratch to prove core files land and are readable. When the pattern is a
pipe it deliberately does nothing beyond reporting the combination, because
the chain's next step would be harming a live process.
"""
import os
import resource
import signal
import subprocess
import time

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

try:
    from _common import MARKER
except ImportError:
    from _common import MARKER  # type: ignore


class CoredumpChainVector(Vector):
    id = "V37"
    title = "coredump chain (RLIMIT_CORE / core_pattern / V32 composition)"
    severity = "medium"
    maps_to = "P9 / V32"
    description = __doc__
    host_verify = "verify.sh (core file with SAND_EVAL_POC in the workspace scratch)"

    def __init__(self):
        self._core_file = None

    def check(self, ctx):
        pattern = self._read("/proc/sys/kernel/core_pattern") or "<unreadable>"
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
        except (ValueError, OSError) as exc:
            soft = hard = None
        detail = {
            "core_pattern": pattern,
            "RLIMIT_CORE": [soft, hard],
            "marker": MARKER,
        }

        is_pipe = pattern.startswith("|")
        handler = pattern[1:].split()[0] if is_pipe and len(pattern) > 1 else ""
        detail["pipe_handler"] = handler if is_pipe else None

        # Compose with V32: can we signal the orchestrator? (sig 0 only)
        killable = self._orchestrator_killable()
        detail["orchestrator_signallable"] = killable

        if is_pipe and killable and handler:
            return Result(
                Status.SUSPECTED,
                f"core_pattern pipes crashes to {handler} as host root, and the orchestrator "
                "is signallable (V32): crashing it would run the handler outside the sandbox "
                "with the daemon's memory. Withheld: needs a real SIGSEGV/SIGQUIT delivery.",
                detail,
            )
        if is_pipe:
            return Result(
                Status.INFO,
                f"core_pattern is a pipe ({handler}); host-root handler exists but the "
                "composition with V32 does not hold here",
                detail,
            )

        written = self._crash_child_core(ctx, soft)
        if written:
            return Result(
                Status.INFO,
                f"core dumps of own processes land in the sandbox as readable files "
                f"({written}); RLIMIT_CORE={soft}. Disk-fill and forensics noise only.",
                detail,
            )
        if soft == 0:
            return Result(Status.PASS, "RLIMIT_CORE is 0 and the pattern writes files: no core surface", detail)
        return Result(
            Status.SUSPECTED,
            f"RLIMIT_CORE={soft}, pattern={pattern!r}, but the own-child core write "
            "did not land (pattern may point outside the sandbox)",
            detail,
        )

    def cleanup(self, ctx):
        removed = False
        if self._core_file and os.path.exists(self._core_file):
            try:
                os.unlink(self._core_file)
                removed = True
            except OSError:
                pass
        self._core_file = None
        return Result(Status.INFO, "core file removed" if removed else "nothing to undo")

    @staticmethod
    def _read(path):
        try:
            with open(path) as handle:
                return handle.read().strip()
        except OSError:
            return None

    @staticmethod
    def _orchestrator_killable():
        try:
            os.kill(1, 0)
            return True
        except OSError:
            return False

    def _crash_child_core(self, ctx, soft):
        """Crash an own child with a bounded core into the run scratch."""
        if not soft:
            return None
        scratch = ctx.scratch
        try:
            os.makedirs(scratch, exist_ok=True)
        except OSError:
            return None
        cap = min(soft, 8 * 1024 * 1024)
        script = (
            "import os,resource,signal,sys\n"
            f"os.chdir({scratch!r})\n"
            f"resource.setrlimit(resource.RLIMIT_CORE, ({cap},{cap}))\n"
            f"open({os.path.join(scratch, 'sandeval-crash-proof.txt')}, 'w').write('{MARKER} V37\\n')\n"
            "os.kill(os.getpid(), signal.SIGSEGV)\n"
        )
        try:
            proc = subprocess.run(
                ["python3", "-c", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30
            )
        except subprocess.TimeoutExpired:
            return None
        if proc.returncode != -signal.SIGSEGV:
            return None
        time.sleep(0.2)
        try:
            for name in sorted(os.listdir(scratch)):
                if name.startswith("core"):
                    path = os.path.join(scratch, name)
                    self._core_file = path
                    size = os.path.getsize(path)
                    return f"{path} ({size}B)"
        except OSError:
            pass
        return None


VECTOR = CoredumpChainVector()
