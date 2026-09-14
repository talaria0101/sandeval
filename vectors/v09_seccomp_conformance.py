"""V9 — seccomp conformance: is every denylisted syscall actually denied?

The filter is a denylist: everything not named is allowed. A conformance check
therefore has to call each denied syscall and confirm the filter, not the
kernel's argument validation, is what stopped it. Each probe passes deliberately
invalid arguments so that a permitted syscall reaches the kernel's own checks
and returns EFAULT/EINVAL/EBADF, while a filtered one returns EPERM without
looking at the arguments.
"""
import ctypes
import os
import platform

try:
    from sandeval.base import Result, Status, Vector
except ImportError:
    from base import Result, Status, Vector  # type: ignore

X86_64 = {
    "ptrace": 101, "add_key": 248, "request_key": 249, "keyctl": 250,
    "kexec_load": 246, "kexec_file_load": 320, "init_module": 175,
    "finit_module": 313, "delete_module": 176, "bpf": 321,
    "perf_event_open": 298, "userfaultfd": 323, "swapon": 167, "swapoff": 168,
    "reboot": 169, "mount": 165, "umount2": 166, "fsopen": 430,
    "fsconfig": 431, "fsmount": 432, "move_mount": 429, "open_tree": 428,
    "fspick": 433, "mount_setattr": 442, "pivot_root": 155, "setns": 308,
    "unshare": 272, "process_vm_readv": 310, "process_vm_writev": 311,
    "open_by_handle_at": 304, "acct": 163,
}
AARCH64 = {
    "ptrace": 117, "add_key": 217, "request_key": 218, "keyctl": 219,
    "kexec_load": 104, "kexec_file_load": 294, "init_module": 105,
    "finit_module": 273, "delete_module": 106, "bpf": 280,
    "perf_event_open": 241, "userfaultfd": 282, "swapon": 224, "swapoff": 225,
    "reboot": 142, "mount": 40, "umount2": 39, "fsopen": 430, "fsconfig": 431,
    "fsmount": 432, "move_mount": 429, "open_tree": 428, "fspick": 433,
    "mount_setattr": 442, "pivot_root": 41, "setns": 268, "unshare": 97,
    "process_vm_readv": 270, "process_vm_writev": 271, "open_by_handle_at": 265,
    "acct": 89,
}
# Arguments chosen so that an *unfiltered* call faults before any capability
# check, leaving EPERM as a seccomp signal rather than a capability denial.
ARGS = {
    "ptrace": (0, 0, 0, 0),
    "add_key": (0, 0, 0, 0, 0, 0),
    "request_key": (0, 0, 0, 0, 0),
    "keyctl": (0, 0, 0, 0, 0),
    "kexec_load": (0, 0, 0, 0),
    "kexec_file_load": (0, 0, 0, 0, 0),
    "init_module": (0, 0, 0),
    "finit_module": (0, 0, 0),
    "delete_module": (0, 0),
    "bpf": (0, 0, 0),
    "perf_event_open": (0, 0, 0, 0, 0),
    "userfaultfd": (0xFFFFFFFF,),
    "swapon": (0, 0),
    "swapoff": (0,),
    "reboot": (0, 0, 0, 0),
    "mount": (0, 0, 0, 0, 0),
    "umount2": (0, 0),
    "fsopen": (0, 0),
    "fsconfig": (0, 0, 0, 0, 0),
    "fsmount": (0, 0, 0),
    "move_mount": (0, 0, 0, 0, 0),
    "open_tree": (0, 0, 0),
    "fspick": (0, 0, 0),
    "mount_setattr": (0, 0, 0, 0, 0),
    "pivot_root": (0, 0),
    "setns": (-1, 0),
    "unshare": (0,),
    "process_vm_readv": (0, 0, 0, 0, 0, 0),
    "process_vm_writev": (0, 0, 0, 0, 0, 0),
    "open_by_handle_at": (-1, 0, 0),
    "acct": (0,),
}
FAULTY = {"EFAULT", "EINVAL", "EBADF", "ENOSYS", "ENOTTY", "EOPNOTSUPP", "EAGAIN", "EINTR"}


class SeccompConformanceVector(Vector):
    id = "V9"
    title = "seccomp denylist conformance (denied syscalls really are denied)"
    severity = "ship-blocker"
    maps_to = "P9 / sweep ks-*"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        machine = platform.machine()
        table = X86_64 if machine in ("x86_64", "amd64") else AARCH64 if machine in ("aarch64", "arm64") else None
        if not table:
            return Result(Status.SKIP, f"no syscall table for {machine}")
        try:
            libc = ctypes.CDLL(None, use_errno=True)
        except Exception as exc:  # noqa: BLE001
            return Result(Status.SKIP, f"no libc: {exc}")
        libc.syscall.restype = ctypes.c_long
        reachable = []
        denied = []
        for name, nr in sorted(table.items()):
            args = ARGS.get(name, (0,) * 6)
            ctypes.set_errno(0)
            libc.syscall(nr, *args)
            err = ctypes.get_errno()
            if err == 0:
                reachable.append(f"{name}(rc=0)")
            elif err in (1, 13):  # EPERM / EACCES -> filter
                denied.append(name)
            else:
                try:
                    import errno as _e

                    label = _e.errorcode.get(err, str(err))
                except Exception:  # noqa: BLE001
                    label = str(err)
                if label in FAULTY:
                    reachable.append(f"{name}({label})")
                else:
                    reachable.append(f"{name}({label})")
        if reachable:
            return Result(
                Status.FAIL,
                f"{len(reachable)}/{len(table)} denylisted syscalls reachable: "
                + ", ".join(reachable[:10]),
                {"reachable": reachable, "denied": denied},
            )
        return Result(Status.PASS, f"all {len(table)} denylisted syscalls returned EPERM/EACCES")


VECTOR = SeccompConformanceVector()
