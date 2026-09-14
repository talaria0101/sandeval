"""V11 — inotify watches can be placed on paths outside the read policy.

`inotify_add_watch(2)` is not a Landlock access right. A watch on a denied
directory leaks filenames, sizes and access patterns as they change, which is
often enough to reconstruct activity the policy meant to hide, and it is a
covert channel for racing a file the agent may not open.
"""
import ctypes
import os

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore


IN_ALL_EVENTS = 0x00000FFF
IN_CLOEXEC = 0x00080000
IN_NONBLOCK = 0x00000800


class InotifyWatchVector(Vector):
    id = "V11"
    title = "inotify watches on out-of-policy directories"
    severity = "medium"
    maps_to = "P18"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        try:
            libc = ctypes.CDLL(None, use_errno=True)
        except Exception as exc:  # noqa: BLE001
            return Result(Status.SKIP, f"no libc: {exc}")
        fd = libc.inotify_init1(IN_CLOEXEC | IN_NONBLOCK)
        if fd < 0:
            return Result(Status.SKIP, "inotify_init1 unavailable")
        targets = ["/etc", ctx.out_dir, os.path.dirname(ctx.workspace)]
        added = []
        try:
            for path in targets:
                if not os.path.isdir(path):
                    continue
                wd = libc.inotify_add_watch(fd, path.encode(), IN_ALL_EVENTS)
                if wd >= 0:
                    in_policy = ctx.policy_writable(path)
                    added.append(f"{path}{'' if in_policy else ':OUT-OF-POLICY'}")
        finally:
            os.close(fd)
        outside = [a for a in added if "OUT-OF-POLICY" in a]
        if outside:
            return Result(Status.FAIL, "watch added outside the policy: " + ", ".join(outside))
        if added:
            return Result(Status.PASS, "watches confined to the policy: " + ", ".join(added))
        return Result(Status.SKIP, "no watch could be added")


VECTOR = InotifyWatchVector()
