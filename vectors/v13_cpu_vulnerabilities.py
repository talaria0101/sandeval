"""V13 — CPU speculative-execution mitigation status (Spectre, Meltdown, …).

The sandbox shares a CPU with everything else. If mitigations are disabled, an
unprivileged process can read across process and privilege boundaries with a
side channel — no policy involved, and no way for a path-based sandbox to stop
it.

This vector reads the evidence a confined process can actually see:

* ``/proc/cmdline`` — ``mitigations=off`` (or ``spectre_v2=off``, ``nopti``,
  ``nospectre_v2``) means the kernel was told not to mitigate.
* ``/proc/cpuinfo`` ``bugs`` — the CPU itself is affected by these classes.
* ``/sys/devices/system/cpu/vulnerabilities/*`` — present on most hosts; the
  sandbox may not mount ``/sys``, so it is a bonus, not the only source.

Vulnerable CPU + disabled mitigations is a FAIL: the hardware is shared and the
side channel is available.
"""
import glob
import os
import re

try:
    from sandeval.base import Result, Status, Vector
except ImportError:
    from base import Result, Status, Vector  # type: ignore


VULN_DIR = "/sys/devices/system/cpu/vulnerabilities"
AFFECTED_RE = re.compile(
    r"spectre|meltdown|l1tf|mds|spec_store|srso|tsa|vmscape|retbleed|mmio_stale|gds",
    re.I,
)
DISABLING = (
    "mitigations=off",
    "nospectre_v2",
    "spectre_v2=off",
    "spectre_v1=off",
    "nopti",
    "pti=off",
    "noibrs",
    "noibpb",
    "ssbd=force-off",
)


class CpuVulnerabilitiesVector(Vector):
    id = "V13"
    title = "CPU speculative-execution mitigations (Spectre/Meltdown)"
    severity = "ship-blocker"
    maps_to = "P9 / new"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        cmdline = self._read("/proc/cmdline") or ""
        disabled = [token for token in DISABLING if token in cmdline]
        bugs = self._bugs()
        affected = sorted(b for b in bugs if AFFECTED_RE.search(b))
        sysfs = self._sysfs()
        sysfs_vuln = [k for k, v in sysfs.items() if re.search(r"\bVulnerable\b", v)]

        detail = {
            "cmdline_disable": disabled,
            "affected_bugs": affected,
            "sysfs": sysfs,
            "sysfs_vulnerable": sysfs_vuln,
        }

        if sysfs_vuln:
            return Result(
                Status.FAIL,
                "kernel reports vulnerable: " + "; ".join(f"{k}={sysfs[k]}" for k in sysfs_vuln),
                detail,
            )
        if disabled and affected:
            return Result(
                Status.FAIL,
                f"mitigations disabled ({', '.join(disabled)}) on a CPU affected by "
                + ", ".join(affected),
                detail,
            )
        if disabled:
            return Result(
                Status.FAIL,
                f"mitigations disabled ({', '.join(disabled)})",
                detail,
            )
        if affected:
            return Result(
                Status.SUSPECTED,
                "CPU affected (" + ", ".join(affected) + ") but no disable flag in /proc/cmdline",
                detail,
            )
        return Result(Status.PASS, "no affected CPU bug and no disable flag visible", detail)

    @staticmethod
    def _read(path):
        try:
            with open(path) as handle:
                return handle.read().strip()
        except OSError:
            return None

    @staticmethod
    def _bugs():
        try:
            with open("/proc/cpuinfo") as handle:
                for line in handle:
                    if line.lower().startswith("bugs"):
                        return set(line.split(":", 1)[1].split())
        except OSError:
            pass
        return set()

    @staticmethod
    def _sysfs():
        out = {}
        for path in sorted(glob.glob(os.path.join(VULN_DIR, "*"))):
            try:
                with open(path) as handle:
                    out[os.path.basename(path)] = handle.read().strip()
            except OSError:
                continue
        return out


VECTOR = CpuVulnerabilitiesVector()
