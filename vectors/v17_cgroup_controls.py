"""V17 — cgroup controls reachable from inside the sandbox.

Resource limits live in cgroup files. If the sandbox's own cgroup directory is
writable, the agent can raise its own `memory.max`, re-enter a wider group via
`cgroup.procs`, or (cgroup v1) plant a `release_agent`, which is a known
container-escape primitive. Every write here is a no-op — the current value, or
the process's own pid — so the verdict is permission, not effect.
"""
import os

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


class CgroupControlsVector(Vector):
    id = "V17"
    title = "cgroup controls writable (limit bypass / release_agent)"
    severity = "high"
    maps_to = "P11 / P9"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        base = _cgroup_dir()
        observed = {"cgroup": base}
        findings = []

        procs = os.path.join(base, "cgroup.procs")
        current = None
        try:
            with open(procs) as handle:
                current = handle.read(4096)
        except OSError as exc:
            observed["cgroup.procs"] = errno_name(exc)
        if current is not None:
            try:
                with open(procs, "w") as handle:
                    handle.write(str(os.getpid()))
                findings.append("cgroup.procs writable")
                observed["cgroup.procs"] = "writable"
            except OSError as exc:
                observed["cgroup.procs"] = errno_name(exc)

        memory = os.path.join(base, "memory.max")
        value = self._read(memory)
        observed["memory.max"] = value
        if value is not None:
            try:
                with open(memory, "w") as handle:
                    handle.write(value)
                findings.append("memory.max writable (own limit can be raised)")
            except OSError as exc:
                observed["memory.max write"] = errno_name(exc)

        subtree = os.path.join(base, "cgroup.subtree_control")
        observed["subtree_control"] = self._read(subtree)
        observed["subtree_control writable"] = os.access(subtree, os.W_OK)

        # cgroup v1 release_agent — only meaningful if present
        for candidate in ("/sys/fs/cgroup/release_agent", os.path.join(base, "release_agent")):
            if os.path.exists(candidate):
                observed[candidate] = self._read(candidate)
                try:
                    with open(candidate, "a") as handle:
                        handle.write("")
                    findings.append(f"{candidate} writable (escape primitive)")
                except OSError as exc:
                    observed[candidate + " write"] = errno_name(exc)

        if findings:
            return Result(Status.FAIL, "; ".join(findings), observed)
        return Result(Status.PASS, "cgroup controls are read-only from inside", observed)

    @staticmethod
    def _read(path):
        try:
            with open(path) as handle:
                return handle.read().strip()
        except OSError:
            return None


VECTOR = CgroupControlsVector()
