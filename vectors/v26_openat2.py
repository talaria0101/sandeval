"""V26 — openat2 conformance: the newer VFS entry honours the same policy.

openat2(2) (kernel 5.6, syscall 437) is the replacement path for openat with
RESOLVE_* restrictions, and like io_uring it is exactly the kind of newer
entry point that historically lags policy hooks. The vector opens one
out-of-policy host file O_WRONLY twice, once with openat and once with
openat2, and only believes a write(2) that actually lands. FAIL requires the
openat2 path to succeed where openat was denied; every other combination is
an honest PASS or SKIP.
"""
import ctypes
import errno
import os
import struct

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

SYS_OPENAT2 = 437  # unified numbering
AT_FDCWD = -100


class Openat2Vector(Vector):
    id = "V26"
    title = "openat2 honours the policy that binds openat(2)"
    severity = "medium"
    maps_to = "P2 / V12 (newer path)"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        targets = [p for p in ctx.host_files if not ctx.policy_writable(p)]
        if not targets:
            return Result(Status.SKIP, "no readable out-of-policy host file to target")
        target = targets[0]
        try:
            libc = ctypes.CDLL(None, use_errno=True)
        except OSError as exc:
            return Result(Status.SKIP, f"no libc: {errno_name(exc)}")
        libc.syscall.restype = ctypes.c_long
        how = struct.pack("QQQ", os.O_WRONLY, 0, 0)  # struct open_how: flags, mode, resolve

        direct_ok = True
        try:
            fd = os.open(target, os.O_WRONLY)
            os.close(fd)
        except OSError as exc:
            direct_ok = False
            direct_err = errno_name(exc)
        if direct_ok:
            return Result(Status.SKIP, f"{target} was writable directly; bad target")

        ctypes.set_errno(0)
        got = libc.syscall(
            ctypes.c_long(SYS_OPENAT2),
            ctypes.c_int(AT_FDCWD),
            target.encode(),
            how,
            ctypes.c_size_t(len(how)),
        )
        if got >= 0:
            try:
                os.write(got, b"s")
                os.close(got)
                return Result(
                    Status.FAIL,
                    f"openat2 opened and wrote {target} where openat was denied "
                    f"({direct_err}): policy not enforced on the newer path",
                    {"target": target, "direct_errno": direct_err},
                )
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    return Result(
                        Status.SKIP,
                        "openat2 returned an fd but write() got EBADF; flags were "
                        "not applied, verdict inconclusive",
                        {"target": target},
                    )
                os.close(got)
                return Result(
                    Status.PASS,
                    f"openat2 opened {target} but the write through it was denied "
                    f"({errno_name(exc)}): policy enforced on the async result",
                    {"target": target},
                )
        err2 = errno_name(OSError(ctypes.get_errno() or 0, "openat2"))
        if err2 == "ENOSYS":
            return Result(Status.SKIP, "openat2 unavailable: ENOSYS (kernel < 5.6)")
        if err2 == "EPERM":
            return Result(Status.PASS, "openat2 denied by seccomp outright", {"target": target})
        if err2 == direct_err:
            return Result(
                Status.PASS,
                f"denied on both paths ({direct_err}): policy enforced on the newer path",
                {"target": target, "openat2_errno": err2},
            )
        return Result(
            Status.SUSPECTED,
            f"openat2 failed differently than openat (direct {direct_err}, openat2 {err2}); "
            "worth a manual look",
            {"target": target},
        )


VECTOR = Openat2Vector()
