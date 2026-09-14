"""V16 — cross-process reconnaissance through /proc and /proc/net.

`/proc` is read-granted wholesale, so the question is how much of every other
process in the PID namespace is visible: command lines, credential ids, memory
maps, open descriptors, and the host's socket tables. Memory layout plus a
speculative-execution side channel (V13/V14) is the pairing that turns an
information leak into a read.
"""
import os

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore


class ProcfsReconVector(Vector):
    id = "V16"
    title = "cross-process recon via /proc (maps, cmdline, fds, /proc/net)"
    severity = "medium"
    maps_to = "P7 / P8"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        peers = []
        maps_readable = []
        cmdline_readable = []
        try:
            pids = [n for n in os.listdir("/proc") if n.isdigit()]
        except OSError:
            return Result(Status.SKIP, "/proc not listable")
        self_pid = str(os.getpid())
        for pid in pids:
            if pid == self_pid:
                continue
            cmd = self._read(f"/proc/{pid}/cmdline")
            if cmd is not None:
                cmdline_readable.append(pid)
                peers.append({"pid": pid, "cmd": cmd[:80]})
            maps = self._read(f"/proc/{pid}/maps")
            if maps is not None and maps.strip():
                maps_readable.append(pid)

        observed = {
            "pids": len(pids),
            "cmdline_readable": len(cmdline_readable),
            "maps_readable": len(maps_readable),
            "peers": peers[:8],
            "net_tcp": os.path.exists("/proc/net/tcp"),
            "net_unix": os.path.exists("/proc/net/unix"),
        }
        if maps_readable:
            return Result(
                Status.FAIL,
                f"memory maps of {len(maps_readable)} peer process(es) are readable",
                observed,
            )
        if cmdline_readable:
            return Result(
                Status.SUSPECTED,
                f"cmdlines of {len(cmdline_readable)} peer(s) readable; memory maps are not",
                observed,
            )
        return Result(Status.PASS, "no peer process metadata readable", observed)

    @staticmethod
    def _read(path):
        try:
            with open(path, "rb") as handle:
                data = handle.read(4096)
            return data.replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            return None


VECTOR = ProcfsReconVector()
