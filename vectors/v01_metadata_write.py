"""V1 — Landlock does not mediate inode metadata.

`chmod(2)`, `chown(2)`, `utimes(2)` and the xattr syscalls are not Landlock
access rights. A policy that grants read but not write to a host file still
lets the agent change that file's mode, owner and timestamps, because Landlock
never sees those operations. On a read-only bind mount the VFS refuses them; on
a read-write bind mount (which is how these host paths are mounted here) nothing
does.
"""
import os

try:
    from sandeval.base import Result, Status, Vector, errno_name
    from _common import marker
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore
    from _common import marker  # type: ignore


XATTR = "user.sandeval.V1"


class MetadataWriteVector(Vector):
    id = "V1"
    title = "inode metadata (chmod/utimes/setxattr) on out-of-policy host files"
    severity = "high"
    maps_to = "P3 / sweep §1"
    description = __doc__
    host_verify = "verify.sh (xattr user.sandeval.V1)"

    def check(self, ctx):
        targets = [p for p in ctx.host_files if not ctx.policy_writable(p)]
        if not targets:
            return Result(Status.SKIP, "no readable out-of-policy host files to probe")
        succeeded = []
        for path in targets[:8]:
            st = os.stat(path)
            row = []
            ok, _v, why = ctx.try_call(os.chmod, path, st.st_mode)
            if ok:
                row.append("chmod")
            ok2, _v2, why2 = ctx.try_call(os.utime, path, ns=(st.st_atime_ns, st.st_mtime_ns))
            if ok2:
                row.append("utimes")
            ok3, _v3, why3 = ctx.try_call(
                os.setxattr, path, XATTR, marker("V1").encode()
            )
            if ok3:
                row.append("setxattr")
            if row:
                succeeded.append(f"{path}:{'+'.join(row)}")
            if ctx.verbose and not row:
                ctx.log(f"{path}: refused ({why}/{why2}/{why3})")
        if succeeded:
            return Result(
                Status.FAIL,
                "metadata writes accepted on out-of-policy files: " + "; ".join(succeeded[:4]),
                {"count": len(succeeded), "xattr": XATTR},
            )
        return Result(Status.PASS, f"{len(targets[:8])} out-of-policy file(s) refused metadata writes")

    def cleanup(self, ctx):
        removed = 0
        for path in ctx.host_files:
            try:
                os.removexattr(path, XATTR)
                removed += 1
            except OSError:
                pass
        return Result(Status.INFO, f"removed {removed} xattr marker(s)")

    def cleanup_all(self, ctx):
        return self.cleanup(ctx)


VECTOR = MetadataWriteVector()
