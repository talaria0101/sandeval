"""V36 — kernel side-channel and keyring surface: perf, keys, userfaultfd, bpf.

Four kernel interfaces that a denylist written before they existed often
misses, each one a step toward cross-process disclosure:

- `perf_event_open` with `perf_event_paranoid <= 0` can count events on
  ANOTHER process: a timing side channel aimed at the orchestrator, and the
  missing ingredient for a practical exploit against the unmitigated CPU of
  V13/V14. `paranoid >= 2` restricts it to self-measurement.
- `add_key`/`keyctl` plant and read kernel keyring payloads that outlive the
  path policy entirely; `/proc/<pid>/keys` of a same-uid process lists what
  it holds.
- `userfaultfd` (when `vm.unprivileged_userfaultfd = 1`) is the standard
  race primitive against shared pages.
- `bpf(2)` needs CAP_BPF/CAP_SYS_ADMIN and should refuse; a pass here would
  be an immediate escalation.

Every call is made with benign or deliberately-invalid arguments so an
EPERM is attributable to seccomp/capabilities, not to a crash. Measurements
are INFO; a pid-1 perf measurement is the one FAIL this vector can claim.
"""
import ctypes
import os
import platform
import re

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

try:
    from _common import libc, raw_syscall
except ImportError:
    from _common import libc, raw_syscall  # type: ignore

NUMBERS = {
    "x86_64": {"perf_event_open": 298, "userfaultfd": 323, "bpf": 321,
               "add_key": 248, "request_key": 249, "keyctl": 250},
    "aarch64": {"perf_event_open": 241, "userfaultfd": 282, "bpf": 280,
                "add_key": 217, "request_key": 218, "keyctl": 219},
}
KEYCTL_READ = 11


def read_int(path):
    try:
        with open(path) as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        return None


class SidechannelSurfaceVector(Vector):
    id = "V36"
    title = "perf/keyring/userfaultfd/bpf surface (cross-process disclosure steps)"
    severity = "high"
    maps_to = "P9 / V13 / V14 / V16"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        nums = NUMBERS.get(platform.machine())
        if not nums:
            return Result(Status.SKIP, "raw syscall numbers unknown on this arch")
        try:
            libc()
        except OSError as exc:
            return Result(Status.SKIP, f"no libc: {errno_name(exc)}")

        findings = {}
        paranoid = read_int("/proc/sys/kernel/perf_event_paranoid")
        findings["perf_event_paranoid"] = paranoid
        perf_pid1, perf_self = self._perf(nums, paranoid)
        findings["perf_pid1"] = perf_pid1
        findings["perf_self"] = perf_self
        findings["proc1_keys_readable"] = self._proc_keys(1)
        findings["add_key"] = self._keyring(nums)
        findings["userfaultfd"] = self._userfaultfd(nums)
        findings["bpf_map_create"] = self._bpf(nums)

        cross = str(perf_pid1).startswith("fd ")
        fail_lines = []
        if cross:
            fail_lines.append(f"perf_event_open measures pid 1 ({perf_pid1})")
        if re.match(r"^\d+ key", str(findings["proc1_keys_readable"])):
            fail_lines.append("/proc/1/keys readable (daemon key inventory)")
        if findings["add_key"] == "ok":
            fail_lines.append("kernel keyring accepts payloads (add_key ok)")

        detail = findings
        if cross:
            return Result(
                Status.FAIL,
                "cross-process measurement primitive: " + "; ".join(fail_lines[:2]) +
                " - a timing side channel aimed at the orchestrator, the missing "
                "ingredient for a practical V14 exploit",
                detail,
            )
        if fail_lines:
            return Result(Status.SUSPECTED, "; ".join(fail_lines[:2]), detail)
        return Result(
            Status.INFO,
            f"surface measured: perf_paranoid={paranoid}, pid1 perf "
            f"{perf_pid1}, keys {findings['add_key']}, uffd "
            f"{findings['userfaultfd']}, bpf {findings['bpf_map_create']}",
            detail,
        )

    @staticmethod
    def _perf(nums, paranoid):
        """perf_event_open(PERF_TYPE_HARDWARE/CPU-cycles, exclude_kernel=1).

        Self-measurement is the baseline; pid 1 is the cross-boundary case.
        Returns errno names, or `fd <n>` on success (fd is closed).
        """
        # struct perf_event_attr: type u32@0, size u32@4, config u64@8,
        # ..., flags u64@40 with disabled=bit0 and exclude_kernel=bit5.
        attr = ctypes.create_string_buffer(120)
        ctypes.memset(attr, 0, 120)
        attr[0:4] = (0).to_bytes(4, "little")  # type = HARDWARE
        attr[4:8] = (120).to_bytes(4, "little")  # size
        attr[8:16] = (0).to_bytes(8, "little")  # config = CPU cycles
        attr[40:48] = (1 | (1 << 5)).to_bytes(8, "little")  # disabled | exclude_kernel

        def open_one(pid):
            # perf_event_open(attr, pid, cpu, group_fd, flags)
            fd, err = raw_syscall(
                nums["perf_event_open"],
                ctypes.cast(attr, ctypes.c_void_p),
                pid,
                -1,  # cpu = -1: all cpus (0 would pin to cpu 0 and skew self vs pid1)
                -1,  # no group
                0,
            )
            if fd < 0:
                return errno_name(OSError(err, "perf_event_open"))
            os.close(fd)
            return f"fd {fd}"

        return open_one(1), open_one(0)

    @staticmethod
    def _proc_keys(pid):
        try:
            with open(f"/proc/{pid}/keys", "rb") as handle:
                data = handle.read()
            return f"{len(data.splitlines())} key(s)" if data else "empty"
        except OSError as exc:
            return errno_name(exc)

    @staticmethod
    def _keyring(nums):
        """add_key a 8-byte user payload on the thread keyring, read it back."""
        payload = b"sandeval"
        key_id, err = raw_syscall(
            nums["add_key"],
            ctypes.c_void_p(_cstr("user")),
            ctypes.c_void_p(_cstr("sandeval.v36")),
            ctypes.c_void_p(_cstr_bytes(payload)),
            len(payload),
            -3,  # KEY_SPEC_THREAD_KEYRING
        )
        if key_id < 0:
            return errno_name(OSError(err, "add_key"))
        buf = ctypes.create_string_buffer(64)
        got, err = raw_syscall(
            nums["keyctl"],
            KEYCTL_READ,
            key_id,
            ctypes.cast(buf, ctypes.c_void_p),
            64,
        )
        return "ok" if got == len(payload) else f"added but read {got}: {errno_name(OSError(err, 'keyctl'))}"

    @staticmethod
    def _userfaultfd(nums):
        uffd = read_int("/proc/sys/vm/unprivileged_userfaultfd")
        fd, err = raw_syscall(nums["userfaultfd"], 0o2000000 | 0o4000)  # O_CLOEXEC | O_NONBLOCK
        if fd >= 0:
            os.close(fd)
            return f"fd created (sysctl={uffd})"
        return errno_name(OSError(err, "userfaultfd")) + f" (sysctl={uffd})"

    @staticmethod
    def _bpf(nums):
        # BPF_MAP_CREATE with a zeroed attr of plausible size; EPERM expected.
        # bpf_attr for MAP_CREATE: map_type u32@0, key_size u32@4,
        # value_size u32@8, max_entries u32@12; the rest stays zero.
        attr = ctypes.create_string_buffer(120)
        ctypes.memset(attr, 0, 120)
        attr[0:4] = (1).to_bytes(4, "little")  # BPF_MAP_TYPE_HASH
        attr[4:8] = (8).to_bytes(4, "little")  # key_size
        attr[8:12] = (8).to_bytes(4, "little")  # value_size
        attr[12:16] = (1).to_bytes(4, "little")  # max_entries
        fd, err = raw_syscall(nums["bpf"], 0, ctypes.cast(attr, ctypes.c_void_p), 120, 0)
        if fd >= 0:
            os.close(fd)
            return "fd created"
        return errno_name(OSError(err, "bpf"))


def _cstr(text):
    buf = ctypes.create_string_buffer(text.encode())
    return ctypes.cast(buf, ctypes.c_void_p).value


def _cstr_bytes(data):
    buf = ctypes.create_string_buffer(data, len(data))
    return ctypes.cast(buf, ctypes.c_void_p).value


VECTOR = SidechannelSurfaceVector()
