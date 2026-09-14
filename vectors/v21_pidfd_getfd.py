"""V21 — pidfd_getfd: duplicate another process's file descriptors.

`pidfd_open(2)` plus `pidfd_getfd(2)` duplicates a descriptor from any process
the caller may ptrace. Landlock never sees it, and seccomp filters written
before the syscall existed (438, 2020) leave it open: the duplicate is a real,
usable descriptor to the victim's stdio, logs or sockets. This vector only
fstats what it steals; it never reads or writes through a descriptor owned by
another process, because that could corrupt a live stream.
"""
import ctypes
import os

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

# Unified syscall numbers (x86_64 == aarch64 for everything from 424 up).
SYS_PIDFD_OPEN = 434
SYS_PIDFD_GETFD = 438
PROBE_FDS = (0, 1, 2, 3, 4)


class PidfdGetfdVector(Vector):
    id = "V21"
    title = "pidfd_getfd duplicates other processes' descriptors"
    severity = "high"
    maps_to = "P12 / V5"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        try:
            libc = ctypes.CDLL(None, use_errno=True)
        except OSError as exc:
            return Result(Status.SKIP, f"no libc to call syscalls through: {errno_name(exc)}")

        def sc(num, *args):
            libc.syscall.restype = ctypes.c_long
            ctypes.set_errno(0)
            return libc.syscall(ctypes.c_long(num), *args)

        targets = []
        for pid in (1, os.getppid()):
            if pid > 0 and pid != os.getpid() and os.path.exists(f"/proc/{pid}"):
                targets.append(pid)
        try:
            for entry in sorted(os.listdir("/proc")):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                if pid != os.getpid() and pid not in targets:
                    targets.append(pid)
                if len(targets) >= 6:
                    break
        except OSError:
            pass
        if not targets:
            return Result(Status.SKIP, "no other processes visible in /proc")

        stolen, open_errs, getfd_errs = [], {}, {}
        for pid in targets:
            pd = sc(SYS_PIDFD_OPEN, pid, ctypes.c_uint(0))
            if pd < 0:
                open_errs[pid] = errno_name(OSError(ctypes.get_errno(), "pidfd_open"))
                continue
            for fd in PROBE_FDS:
                dup = sc(SYS_PIDFD_GETFD, pd, ctypes.c_int(fd), ctypes.c_uint(0))
                if dup < 0:
                    err = ctypes.get_errno()
                    getfd_errs[errno_name(OSError(err, "pidfd_getfd"))] = (
                        getfd_errs.get(errno_name(OSError(err, "pidfd_getfd")), 0) + 1
                    )
                    continue
                info = {"pid": pid, "fd": fd}
                try:
                    st = os.fstat(dup)
                    info["fstat"] = f"mode={oct(st.st_mode)} size={st.st_size} inode={st.st_ino}"
                except OSError as exc:
                    info["fstat"] = errno_name(exc)
                os.close(dup)
                stolen.append(info)
            os.close(pd)

        if stolen:
            shown = "; ".join(
                f"pid {s['pid']} fd {s['fd']} ({s['fstat']})" for s in stolen[:3]
            )
            return Result(
                Status.FAIL,
                f"pidfd_getfd duplicated {len(stolen)} foreign descriptor(s): {shown}",
                {"stolen": stolen, "pidfd_open_errors": open_errs},
            )
        if not open_errs:
            return Result(
                Status.PASS,
                f"pidfd_getfd denied on every target (errors: {getfd_errs or 'none recorded'})",
                {"targets": targets},
            )
        if all(e in ("ENOSYS", "EPERM") for e in open_errs.values()) and not getfd_errs:
            worst = sorted(set(open_errs.values()))[0]
            if worst == "ENOSYS":
                return Result(Status.SKIP, "pidfd_open unavailable: kernel too old (< 5.3)")
            return Result(
                Status.PASS, "pidfd_open denied everywhere (seccomp or capability gap)",
                {"pidfd_open_errors": open_errs},
            )
        return Result(
            Status.PASS,
            f"pidfd_open ok on some targets but every pidfd_getfd was denied: {getfd_errs}",
            {"pidfd_open_errors": open_errs, "targets": targets},
        )


VECTOR = PidfdGetfdVector()
