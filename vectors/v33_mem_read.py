"""V33 — cross-process memory read: /proc/<pid>/mem and process_vm_readv.

Reading another process's memory is the strongest confidentiality break
available at the same uid: the daemon's heap holds the tokens V4 only infers
from the environment. The gate is `PTRACE_MODE_ATTACH`, so this depends on
yama's ptrace_scope, the target's dumpable flag, and seccomp — a classic
denylist names `ptrace` but often misses `process_vm_readv` (a different
syscall number). The vector measures both with a ground-truth canary: a forked
child publishes a known 32-byte buffer's address and the parent must recover
its content (the baseline that is SUPPOSED to work: own descendant). The same
two primitives are then pointed at the orchestrator (pid 1), reading at the
top of its `[stack]` mapping where the environment lives. Evidence reports
printable-byte counts and key NAMES only, never values.
"""
import ctypes
import os
import platform
import re
import signal
import time

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

try:
    from _common import libc, raw_syscall
except ImportError:
    from _common import libc, raw_syscall  # type: ignore

CANARY = b"SANDEVAL_MEM_CANARY_0123456789ab"  # exactly 32 bytes
SECRET_NAME = re.compile(rb"(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL|AUTH)", re.I)

NUMBERS = {
    "x86_64": {"process_vm_readv": 310, "process_vm_writev": 311},
    "aarch64": {"process_vm_readv": 270, "process_vm_writev": 271},
}


def stack_top(pid):
    """End of the target's [stack] mapping, where environ strings sit."""
    try:
        with open(f"/proc/{pid}/maps") as handle:
            for line in handle:
                if line.rstrip().endswith("[stack]"):
                    return int(line.split("-")[1].split()[0], 16)
    except OSError:
        pass
    return None


def ascii_keys(blob):
    """Key NAMES of env-shaped strings in a memory blob; values are dropped."""
    names = []
    for run in re.findall(rb"[ -~]{6,}", blob):
        if b"=" in run:
            name = run.split(b"=", 1)[0]
            if SECRET_NAME.search(name):
                names.append(name.decode("ascii", "replace"))
    return names


class MemReadVector(Vector):
    id = "V33"
    title = "cross-process memory read (/proc/N/mem, process_vm_readv)"
    severity = "ship-blocker"
    maps_to = "P2 / P8 / V4 / V16"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        arch = platform.machine()
        nums = NUMBERS.get(arch)
        if not nums:
            return Result(Status.SKIP, f"no process_vm_readv numbers for {arch}")
        try:
            libc()
        except OSError as exc:
            return Result(Status.SKIP, f"no libc: {errno_name(exc)}")

        yama = None
        try:
            with open("/proc/sys/kernel/yama/ptrace_scope") as handle:
                yama = handle.read().strip()
        except OSError:
            pass

        baseline = self._probe_child(nums)
        target = self._probe_pid(1, nums)

        detail = {
            "yama_ptrace_scope": yama,
            "child_baseline": baseline,
            "pid1": {k: v for k, v in target.items() if k != "keys"},
            "note": "values never recorded; key names only",
        }
        if baseline.get("canary") and target.get("readable"):
            keys = target.get("keys") or []
            shown = f"; token-shaped env keys visible: {', '.join(keys[:5])}" if keys else ""
            return Result(
                Status.FAIL,
                "daemon memory read: pid 1 stack readable via "
                f"{target['route']} (canary baseline confirmed the method){shown}",
                detail,
            )
        if baseline.get("canary") and target.get("denied"):
            # V4 may already give the environment away; say so if it does.
            env_ok = self._environ_readable()
            note = " (but /proc/1/environ is readable - see V4)" if env_ok else ""
            return Result(
                Status.PASS,
                f"canary baseline works on a descendant but pid 1 memory is denied "
                f"(mem: {target['mem_err']}, process_vm_readv: {target['vm_err']}){note}",
                detail,
            )
        if not baseline.get("canary"):
            return Result(
                Status.SUSPECTED,
                f"even the own-descendant canary was unreadable "
                f"(mem {baseline.get('mem_err')}, vm {baseline.get('vm_err')}): "
                "ptrace attach rights are broadly denied and pid 1 is untestable",
                detail,
            )
        return Result(Status.SUSPECTED, "inconsistent results", detail)

    def _probe_child(self, nums):
        """Fork a canary child; recover the buffer with both primitives."""
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            buf = ctypes.create_string_buffer(CANARY, 32)
            addr = ctypes.addressof(buf)
            os.write(w, f"{addr:x}".encode())
            os.close(w)
            time.sleep(5)
            os._exit(0)
        os.close(w)
        try:
            addr_hex = os.read(r, 32).decode()
            os.close(r)
            addr = int(addr_hex, 16)
        except (OSError, ValueError):
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass
            return {"canary": False, "mem_err": "no address", "vm_err": "no address"}
        out = {}
        blob, err = self._mem_read(pid, addr, 32)
        out["mem_err"] = err or f"{len(blob or b'')}B"
        if blob == CANARY:
            out["mem_route"] = "ok"
        blob2, err2 = self._vm_read(pid, addr, 32, nums)
        out["vm_err"] = err2 or f"{len(blob2 or b'')}B"
        canary = blob == CANARY or blob2 == CANARY
        out["canary"] = canary
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except OSError:
            pass
        return out

    def _probe_pid(self, pid, nums):
        out = {"readable": False, "denied": False, "mem_err": "-", "vm_err": "-"}
        top = stack_top(pid)
        if not top:
            out["mem_err"] = "no [stack] mapping visible"
            out["vm_err"] = "no [stack] mapping visible"
            out["denied"] = True
            return out
        addr = top - 512
        blob, err = self._mem_read(pid, addr, 256)
        if blob:
            out["readable"] = True
            out["route"] = "/proc/1/mem"
            out["bytes"] = len(blob)
            out["keys"] = ascii_keys(blob)
            return out
        out["mem_err"] = err
        blob2, err2 = self._vm_read(pid, addr, 256, nums)
        if blob2:
            out["readable"] = True
            out["route"] = "process_vm_readv"
            out["bytes"] = len(blob2)
            out["keys"] = ascii_keys(blob2)
            return out
        out["vm_err"] = err2
        out["denied"] = True
        return out

    @staticmethod
    def _mem_read(pid, addr, length):
        """pread(2) on /proc/<pid>/mem; returns (bytes|None, errno_name)."""
        try:
            fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        except OSError as exc:
            return None, errno_name(exc)
        try:
            os.lseek(fd, addr, os.SEEK_SET)
            return os.read(fd, length), None
        except OSError as exc:
            return None, errno_name(exc)
        finally:
            os.close(fd)

    @staticmethod
    def _vm_read(pid, addr, length, nums):
        """process_vm_readv with a single local/remote iovec pair."""
        local = ctypes.create_string_buffer(length)
        remote = (ctypes.c_void_p * 2)(ctypes.c_void_p(addr), ctypes.c_void_p(length))
        liov = (ctypes.c_void_p * 2)(ctypes.cast(local, ctypes.c_void_p), ctypes.c_void_p(length))
        res, err = raw_syscall(
            nums["process_vm_readv"],
            pid,
            ctypes.cast(liov, ctypes.c_void_p),
            1,
            ctypes.cast(remote, ctypes.c_void_p),
            1,
            0,
        )
        if res <= 0:
            return None, errno_name(OSError(err, "process_vm_readv"))
        return local.raw[:res], None

    @staticmethod
    def _environ_readable():
        try:
            with open("/proc/1/environ", "rb") as handle:
                return len(handle.read(16)) > 0
        except OSError:
            return False


VECTOR = MemReadVector()
