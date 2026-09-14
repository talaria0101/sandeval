"""V14 — Spectre v1 (bounds-check bypass) side channel, attempted live.

V13 records what the kernel claims. This vector tries to make the claim false:
it builds `tools/spectre_v1.c` and runs the canonical Flush+Reload
bounds-check-bypass against a known secret in its own address space. If the
secret comes back, the speculation barrier is not working and the CPU is
leaking memory an unprivileged process must not see.

It is a one-process feasibility probe, not a cross-process exploit. That is
enough: the sandbox's guarantee is a boundary between processes, and the CPU is
shared between them.
"""
import os
import shutil
import subprocess

try:
    from sandeval.base import Result, Status, Vector
    from _common import tools_dir
except ImportError:
    from base import Result, Status, Vector  # type: ignore
    from _common import tools_dir  # type: ignore


class SpectreV1Vector(Vector):
    id = "V14"
    title = "Spectre v1 (bounds-check bypass) side channel reproduces"
    severity = "high"
    maps_to = "P9 / V13"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        source = os.path.join(tools_dir(), "spectre_v1.c")
        if not cc or not os.path.exists(source):
            return Result(Status.SKIP, "no C compiler or helper source")
        binary = os.path.join(ctx.scratch, "spectre_v1")
        build = subprocess.run(
            [cc, "-O2", "-o", binary, source],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if build.returncode != 0:
            return Result(Status.SKIP, f"build failed: {build.stderr.strip()[:160]}")
        leaks = []
        for _attempt in range(3):
            try:
                run = subprocess.run(
                    [binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=90
                )
            except subprocess.TimeoutExpired:
                leaks.append("<timeout>")
                continue
            lines = run.stdout.strip().splitlines()
            leaked = lines[0] if lines else ""
            leaks.append(leaked)
            if "VULNERABLE" in run.stdout or "SPECT" in leaked:
                return Result(
                    Status.FAIL,
                    f"recovered the known secret through speculation: {leaked!r} (attempt {_attempt + 1}/3)",
                    {"leaks": leaks, "stderr_tail": run.stderr.strip().splitlines()[-3:]},
                )
        # did the kernel already say it is vulnerable? consult cmdline + bugs
        # when the sandbox does not mount /sys.
        cmdline = ""
        try:
            with open("/proc/cmdline") as handle:
                cmdline = handle.read()
        except OSError:
            pass
        bugs = []
        try:
            with open("/proc/cpuinfo") as handle:
                for line in handle:
                    if line.lower().startswith("bugs"):
                        bugs = line.split(":", 1)[1].split()
                        break
        except OSError:
            pass
        mitigations_off = "mitigations=off" in cmdline or "spectre_v2=off" in cmdline
        affected = any("spectre" in b for b in bugs)
        if mitigations_off and affected:
            return Result(
                Status.SUSPECTED,
                "mitigations=off on an affected CPU but this PoC did not reproduce (tuning needed)",
                {"leaks": leaks, "bugs": bugs},
            )
        return Result(Status.PASS, "no leak reproduced", {"leaks": leaks})


VECTOR = SpectreV1Vector()
