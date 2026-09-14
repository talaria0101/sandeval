"""V15 — kernel hardening knobs reachable from inside the sandbox.

Some kernel surfaces are global, not namespaced, and their settings decide how
much a local process learns. `kptr_restrict=0` prints real addresses in
`/proc/kallsyms`; `dmesg_restrict=0` exposes the ring buffer; ASLR can be weak;
`/proc/kcore` and `/dev/kvm` are whole-address-space / virtualization surfaces.
None of these is mediated by a path policy on the workspace, so the check is
what the running kernel actually exposes.
"""
import os
import re

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore


def _read(path):
    try:
        with open(path) as handle:
            return handle.read().strip()
    except OSError:
        return None


def _write_same(path):
    """Prove writability without changing anything, when the value is readable."""
    current = _read(path)
    if current is None:
        return False, "unreadable"
    try:
        with open(path, "w") as handle:
            handle.write(current + "\n" if not current.endswith("\n") else current)
        return True, "writable"
    except OSError as exc:
        return False, errno_name(exc)


class KernelKnobsVector(Vector):
    id = "V15"
    title = "kernel hardening knobs (kptr/dmesg/ASLR/kcored/kvm)"
    severity = "medium"
    maps_to = "P9 / sweep §5-§7"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        findings = []
        observed = {}

        kptr = _read("/proc/sys/kernel/kptr_restrict")
        observed["kptr_restrict"] = kptr
        kallsyms = _read("/proc/kallsyms")
        if kallsyms:
            first = kallsyms.splitlines()[0].split()
            if len(first) >= 3 and first[0] not in ("0000000000000000", ""):
                observed["kallsyms_first"] = f"{first[0]} {first[2]}"
                findings.append("kallsyms exposes real addresses")

        dmesg = _read("/proc/sys/kernel/dmesg_restrict")
        observed["dmesg_restrict"] = dmesg
        if dmesg == "0":
            ok, _v, why = ctx.try_call(open, "/dev/kmsg", "rb")
            if ok:
                findings.append("/dev/kmsg readable with dmesg_restrict=0")

        aslr = _read("/proc/sys/kernel/randomize_va_space")
        observed["randomize_va_space"] = aslr
        if aslr is not None and aslr != "2":
            findings.append(f"ASLR not full (randomize_va_space={aslr})")

        observed["modules_disabled"] = _read("/proc/sys/kernel/modules_disabled")
        observed["sysrq"] = _read("/proc/sys/kernel/sysrq")
        observed["unprivileged_bpf_disabled"] = _read("/proc/sys/kernel/unprivileged_bpf_disabled")
        observed["perf_event_paranoid"] = _read("/proc/sys/kernel/perf_event_paranoid")
        observed["lockdown"] = _read("/sys/kernel/security/lockdown")

        ok, _v, why = ctx.try_call(open, "/proc/kcore", "rb")
        observed["kcore"] = "readable" if ok else why
        if ok:
            findings.append("/proc/kcore readable")

        ok, _v, why = ctx.try_call(open, "/dev/kvm", "r+b")
        observed["kvm"] = "openable" if ok else why
        if ok:
            findings.append("/dev/kvm openable (hardware virtualization reachable)")

        # are the global sysctls writable?
        for path in ("/proc/sys/kernel/core_pattern", "/proc/sys/kernel/modprobe"):
            ok, why = _write_same(path)
            observed[path] = "writable" if ok else why
            if ok:
                findings.append(f"{path} writable")

        if findings:
            return Result(Status.FAIL, "; ".join(findings), observed)
        return Result(Status.PASS, "no reachable hardening regression among the probed knobs", observed)


VECTOR = KernelKnobsVector()
