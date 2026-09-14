"""V6 — `clone(CLONE_NEWUSER)` is allowed while `unshare`/`setns` are denied.

The seccomp filter denies the namespace syscalls it names, but `clone(2)` is
not one of them. A child cloned with CLONE_NEWUSER is root in a fresh user
namespace with a full capability set. mount(2) is still filtered, so this is
not, by itself, a filesystem escape; it removes the last capability barrier
between the agent and any future kernel bug or un-denied syscall.
"""
import os
import shutil
import subprocess

try:
    from sandeval.base import Result, Status, Vector, errno_name
    from _common import tools_dir
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore
    from _common import tools_dir  # type: ignore


class UserNamespaceCloneVector(Vector):
    id = "V6"
    title = "clone(CLONE_NEWUSER) reachable (seccomp gap)"
    severity = "high"
    maps_to = "P9 / sweep ns-unshare"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        source = os.path.join(tools_dir(), "userns_clone.c")
        if not cc or not os.path.exists(source):
            return self._python_probe(ctx)
        binary = os.path.join(ctx.scratch, "userns_clone")
        build = subprocess.run(
            [cc, "-O2", "-o", binary, source],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if build.returncode != 0:
            return Result(Status.SKIP, f"could not build helper: {build.stderr.strip()[:160]}")
        run = subprocess.run([binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if run.returncode == 1:
            return Result(Status.PASS, "clone(CLONE_NEWUSER) refused: " + run.stderr.strip()[:120])
        if run.returncode == 0:
            caps = [
                line.strip()
                for line in run.stdout.splitlines()
                if line.startswith(("CapEff", "CapPrm"))
            ]
            return Result(
                Status.FAIL,
                "clone(CLONE_NEWUSER) succeeded inside the sandbox; " + "; ".join(caps),
                {"stdout": run.stdout.strip()},
            )
        return Result(Status.SKIP, f"helper inconclusive rc={run.returncode}: {run.stderr.strip()[:120]}")

    def _python_probe(self, ctx):
        """Fallback when no compiler is present: call clone via libc."""
        try:
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
        except Exception as exc:  # noqa: BLE001
            return Result(Status.SKIP, f"no compiler and ctypes unavailable: {exc}")
        SYS_clone = 56  # x86_64
        CLONE_NEWUSER = 0x10000000
        SIGCHLD = 17
        libc.syscall.restype = ctypes.c_long
        pid = libc.syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0)
        err = ctypes.get_errno()
        if pid == 0:
            os._exit(0)  # child: on the parent's stack, do not return
        if pid > 0:
            os.waitpid(pid, 0)
            return Result(Status.FAIL, "clone(CLONE_NEWUSER) succeeded (ctypes probe)")
        return Result(Status.PASS, f"clone(CLONE_NEWUSER) refused: {errno_name(OSError(err, 'clone'))}")


VECTOR = UserNamespaceCloneVector()
