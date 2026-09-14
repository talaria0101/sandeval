"""V2 — arbitrary data in out-of-policy inodes via extended attributes.

An xattr is stored in the inode. If a readable-but-not-writable host file
accepts one, the agent has written attacker-controlled bytes into a host inode
that Landlock's write policy was supposed to guard. 64 KiB is the usual
`XATTR_SIZE_MAX`, so a full-size write is a meaningful payload, not a marker.
"""
import os

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore


XATTR = "user.sandeval.V2"
PAYLOAD = b"A" * 65536


class XattrPayloadVector(Vector):
    id = "V2"
    title = "64 KiB xattr payload written into out-of-policy host inode"
    severity = "high"
    maps_to = "P3 / V1"
    description = __doc__
    host_verify = "verify.sh (xattr user.sandeval.V2)"

    def check(self, ctx):
        targets = [p for p in ctx.host_files if not ctx.policy_writable(p)]
        if not targets:
            return Result(Status.SKIP, "no readable out-of-policy host files to probe")
        if not hasattr(os, "setxattr"):
            return Result(Status.SKIP, "os.setxattr unavailable on this Python")
        written = []
        for path in targets[:6]:
            size = len(PAYLOAD)
            while size >= 1:
                ok, _v, why = ctx.try_call(os.setxattr, path, XATTR, PAYLOAD[:size])
                if ok:
                    written.append(f"{path}:{size}B")
                    break
                if "E2BIG" in why or "ENOSPC" in why or "ERANGE" in why:
                    size //= 2
                    continue
                break
        if written:
            return Result(Status.FAIL, "xattr payload accepted: " + "; ".join(written), {"xattr": XATTR})
        return Result(Status.PASS, "no out-of-policy file accepted the xattr payload")

    def cleanup(self, ctx):
        removed = 0
        for path in ctx.host_files:
            try:
                os.removexattr(path, XATTR)
                removed += 1
            except OSError:
                pass
        return Result(Status.INFO, f"removed {removed} xattr marker(s)")


VECTOR = XattrPayloadVector()
