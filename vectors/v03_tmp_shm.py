"""V3 — /tmp and /dev/shm are fully writable although not in the write policy.

The policy names its writable roots. If a world-writable tmpfs is reachable
with create/write/unlink anyway, then the write list is not the write set: the
agent has scratch space of unbounded size outside the paths the operator
enumerated, and any other process in the same mount namespace shares it.
"""
import os
import time

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

try:
    from _common import marker
except ImportError:
    from _common import marker  # type: ignore


CANDIDATES = ["/tmp", "/dev/shm", "/var/tmp"]


class TmpShmVector(Vector):
    id = "V3"
    title = "writable /tmp and /dev/shm outside the write policy"
    severity = "medium"
    maps_to = "P4 / sweep §2"
    description = __doc__
    host_verify = ""  # tmpfs may be private to the sandbox mount namespace

    def check(self, ctx):
        results = []
        for directory in CANDIDATES:
            if not os.path.isdir(directory):
                continue
            probe = os.path.join(directory, f".sandeval-V3-{os.getpid()}-{int(time.time())}")
            ok, _v, why = ctx.try_call(_write, probe, marker("V3").encode() * 16)
            if ok:
                in_policy = ctx.policy_writable(directory)
                results.append(f"{directory}:writable{'' if in_policy else ':OUT-OF-POLICY'}")
                try:
                    os.unlink(probe)
                except OSError:
                    pass
            elif ctx.verbose:
                ctx.log(f"{directory}: {why}")
        outside = [r for r in results if "OUT-OF-POLICY" in r]
        if outside:
            return Result(
                Status.FAIL,
                "write accepted outside the policy write list: " + ", ".join(outside),
                {"probed": results},
            )
        if results:
            return Result(Status.PASS, "tmpfs writes confined to the policy: " + ", ".join(results))
        return Result(Status.SKIP, "no tmpfs candidate present")


def _write(path, data):
    with open(path, "wb") as handle:
        handle.write(data)
    return len(data)


VECTOR = TmpShmVector()
