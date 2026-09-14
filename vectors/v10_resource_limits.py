"""V10 — resource limits: are memory, process count and file size bounded?

A sandbox that cannot exhaust the host is a sandbox that cannot deny service.
The policy asks for cgroup limits; this vector reads what was actually applied
and whether a per-file size cap exists. Absent `memory.max`/`pids.max` means a
single agent turn can starve every other tenant.
"""
import os
import resource

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore


def _cgroup_dir():
    try:
        with open("/proc/self/cgroup") as handle:
            for line in handle:
                parts = line.strip().split(":", 2)
                if len(parts) == 3 and parts[0] == "0":
                    return os.path.join("/sys/fs/cgroup", parts[2].lstrip("/"))
    except OSError:
        pass
    return "/sys/fs/cgroup"


def _read(path):
    try:
        with open(path) as handle:
            return handle.read().strip()
    except OSError:
        return None


class ResourceLimitsVector(Vector):
    id = "V10"
    title = "cgroup and rlimit bounds (memory / pids / file size)"
    severity = "medium"
    maps_to = "P11 / sweep §10"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        cg = _cgroup_dir()
        memory = _read(os.path.join(cg, "memory.max")) or _read("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        pids = _read(os.path.join(cg, "pids.max")) or _read("/sys/fs/cgroup/pids/pids.max")
        io_max = _read(os.path.join(cg, "io.max"))
        try:
            fsize = resource.getrlimit(resource.RLIMIT_FSIZE)
        except (ValueError, OSError):
            fsize = None
        observed = {"cgroup": cg, "memory.max": memory, "pids.max": pids, "io.max": io_max, "RLIMIT_FSIZE": fsize}
        unbounded = []
        if memory in (None, "max"):
            unbounded.append("memory")
        if pids in (None, "max"):
            unbounded.append("pids")
        if fsize in (None, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)):
            unbounded.append("file-size")
        if unbounded:
            return Result(
                Status.FAIL,
                "unbounded: " + ", ".join(unbounded) + f" (cgroup {cg})",
                observed,
            )
        return Result(Status.PASS, f"limits present (memory={memory}, pids={pids})", observed)


VECTOR = ResourceLimitsVector()
