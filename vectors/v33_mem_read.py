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
import hashlib
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

    # Token shapes the deep scan looks for in live anonymous memory.
    TOKEN_SHAPES = (
        (rb"gh[pousr]_[A-Za-z0-9]{20,}", "github"),
        (rb"github_pat_[A-Za-z0-9_]{20,}", "github-pat"),
        (rb"sk-[A-Za-z0-9-]{20,}", "api-key"),
        (rb"xox[baprs]-[A-Za-z0-9-]{10,}", "slack"),
        (rb"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "jwt"),
        (rb"AKIA[0-9A-Z]{16}", "aws"),
    )
    SCAN_BUDGET = 96 * 1024 * 1024

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

        # Route independence: is a secret the sandbox already holds (from the
        # daemon env) ALSO recoverable through the memory route alone? Hash
        # matched - the value is never recorded.
        route_proof = self._route_independence()
        # Deep scan: token-shaped values in live anon memory NOT covered by
        # the environ read. This is what would make memory read strictly
        # stronger than V4 on a given deployment.
        deep = self._deep_scan()

        detail = {
            "yama_ptrace_scope": yama,
            "child_baseline": baseline,
            "pid1": {k: v for k, v in target.items() if k != "keys"},
            "route_independence": route_proof,
            "deep_scan": deep,
            "note": "values never recorded; hashes and counts only",
        }
        if baseline.get("canary") and target.get("readable"):
            keys = target.get("keys") or []
            shown = f"; token-shaped env keys visible: {', '.join(keys[:5])}" if keys else ""
            extra = ""
            if route_proof.get("match"):
                extra = f"; a credential already in the sandbox env was re-recovered from pid 1 stack " \
                        f"via /proc/1/mem alone (sha256:{route_proof['sha']}, value not shown)"
            if deep.get("hits"):
                extra += f"; {len(deep['hits'])} secret-shaped value(s) in live memory beyond environ"
            return Result(
                Status.FAIL,
                "daemon memory read: pid 1 stack readable via "
                f"{target['route']} (canary baseline confirmed the method){shown}{extra}",
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

    def _route_independence(self):
        """Recover an env credential through /proc/1/mem ONLY (hash check)."""
        out = {"match": False}
        try:
            with open("/proc/1/environ", "rb") as handle:
                env = handle.read()
        except OSError:
            return out
        creds = [v for v in env.split(b"\0") if b"=" in v and len(v.split(b"=", 1)[1]) >= 16]
        if not creds:
            return out
        top = stack_top(1)
        if not top:
            return out
        try:
            mem = open("/proc/1/mem", "rb")
        except OSError:
            return out
        try:
            for off in range(0, 1024 * 1024, 65536):
                addr = top - off - 65536
                if addr < 0:
                    break
                try:
                    mem.seek(addr)
                    data = mem.read(65536)
                except OSError:
                    continue
                for cred in creds:
                    if cred in data:
                        out["match"] = True
                        out["sha"] = hashlib.sha256(cred).hexdigest()[:16]
                        out["addr"] = hex(addr)
                        return out
        finally:
            mem.close()
        return out

    def _deep_scan(self):
        """Token-shaped values in pid 1's anon memory, beyond environ."""
        out = {"scanned_bytes": 0, "hits": []}
        try:
            env = open("/proc/1/environ", "rb").read()
        except OSError:
            env = b""
            out["env_read"] = "unreadable (deep scan cannot subtract environ)"
        env_blob = b"\n".join(v for v in env.split(b"\0") if b"=" in v)
        try:
            maps = open("/proc/1/maps").read().splitlines()
            mem = open("/proc/1/mem", "rb")
        except OSError:
            return out
        with mem:
            for line in maps:
                if out["scanned_bytes"] >= self.SCAN_BUDGET:
                    break
                parts = line.split()
                if "r" not in parts[1]:
                    continue
                path = parts[5] if len(parts) > 5 else "[anon]"
                if path.startswith("/"):
                    continue  # file-backed code/rodata: string constants, not live secrets
                start_s, end_s = parts[0].split("-")
                start, end = int(start_s, 16), int(end_s, 16)
                if end - start > 256 * 1024 * 1024:
                    continue
                try:
                    mem.seek(start)
                    data = mem.read(end - start)
                except OSError:
                    continue
                out["scanned_bytes"] += len(data)
                for rx, label in self.TOKEN_SHAPES:
                    for match in re.finditer(rx, data):
                        tok = match.group(0)
                        if tok in env_blob:
                            continue
                        out["hits"].append({
                            "shape": label,
                            "sha256": hashlib.sha256(tok).hexdigest()[:16],
                            "len": len(tok),
                            "region": path,
                        })
                        break  # one hit per shape per region is enough
        out["hits"] = out["hits"][:8]
        return out

    @staticmethod
    def _environ_readable():
        try:
            with open("/proc/1/environ", "rb") as handle:
                return len(handle.read(16)) > 0
        except OSError:
            return False


VECTOR = MemReadVector()
