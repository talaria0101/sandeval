"""V24 — io_uring honours the policy that openat(2) honours.

io_uring shipped years before sandbox hooks were retrofitted onto it, so an
async IORING_OP_OPENAT may succeed where the same openat(2) is denied. The
vector builds tools/io_uring_open.c, aims both a direct open and an uring
open at one out-of-policy host file (O_WRONLY), and believes only a write(2)
that actually lands: an fd the ring returns but that cannot be written proves
nothing about flags. Verdicts follow the evidence — a true bypass is FAIL,
denial on both paths or on the write is PASS, and an unusable uring is SKIP
(or PASS when seccomp itself denies io_uring_setup).
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


class IoUringVector(Vector):
    id = "V24"
    title = "io_uring openat bypasses the policy that binds openat(2)"
    severity = "high"
    maps_to = "P2 / V12 (async path)"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        targets = [p for p in ctx.host_files if not ctx.policy_writable(p)]
        if not targets:
            return Result(Status.SKIP, "no readable out-of-policy host file to target")
        target = targets[0]
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        source = os.path.join(tools_dir(), "io_uring_open.c")
        if not cc or not os.path.exists(source):
            return Result(Status.SKIP, "no C compiler or helper source")
        binary = os.path.join(ctx.scratch, "io_uring_open")
        build = subprocess.run(
            [cc, "-O2", "-o", binary, source],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if build.returncode != 0:
            return Result(Status.SKIP, f"build failed: {build.stderr.strip()[:160]}")
        try:
            run = subprocess.run(
                [binary, target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired:
            return Result(Status.SKIP, "io_uring helper timed out")
        lines = [line for line in run.stdout.strip().splitlines() if line]
        detail = {"target": target, "helper": lines, "rc": run.returncode}

        def kv(name):
            for line in lines:
                if line.startswith(name + "="):
                    return line.split("=", 1)[1]
            return None

        if run.returncode == 10:
            return Result(
                Status.FAIL,
                f"io_uring opened and wrote to {target} where direct openat was "
                f"denied ({kv('direct_errno')}); policy not enforced on the async path",
                detail,
            )
        if run.returncode == 11:
            return Result(
                Status.PASS,
                f"denied on both paths (direct {kv('direct_errno')}, "
                f"uring {kv('uring_errno')})",
                detail,
            )
        if run.returncode == 12:
            return Result(Status.SKIP, f"{target} was writable directly; bad target", detail)
        if run.returncode == 13:
            return Result(Status.SKIP, "io_uring unavailable: ENOSYS (kernel too old)", detail)
        if run.returncode == 14:
            setup = kv("setup_errno")
            if setup == "1":  # EPERM
                return Result(Status.PASS, "io_uring_setup denied (seccomp)", detail)
            if kv("enter_errno"):
                return Result(
                    Status.SUSPECTED, f"io_uring_enter failed ({kv('enter_errno')})", detail
                )
            return Result(Status.SKIP, f"io_uring unusable: {lines}", detail)
        if run.returncode == 15:
            return Result(
                Status.SKIP,
                "uring returned an fd but the write probe got EBADF; open flags "
                "landed in the wrong SQE slot for this kernel, verdict inconclusive",
                detail,
            )
        if run.returncode == 16:
            return Result(
                Status.PASS,
                "io_uring opened the fd but write(2) was denied through it: "
                "the policy is enforced on the async path",
                detail,
            )
        return Result(Status.SKIP, f"helper ended oddly (rc={run.returncode}): {lines}", detail)


VECTOR = IoUringVector()
