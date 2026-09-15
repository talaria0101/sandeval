"""V28 — SysV shared memory: attach to host segments the policy never sees.

System V IPC objects live in no namespace by default, so a sandbox that
shares the kernel (not a container) shares the host's shm/sem/msg arrays.
Any segment owned by the same uid — or every segment, for root — is a
candidate for a read-only attach, which is cross-process memory read through
a legacy interface no path policy mediates. The vector enumerates
/proc/sysvipc/shm, attaches read-only to foreign segments, and detaches
immediately. With no segments visible it reports SKIP honestly rather than
inventing a pass.
"""
import ctypes
import os

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

SHM_RDONLY = 0o010000  # 0x1000


class SysvShmVector(Vector):
    id = "V28"
    title = "SysV shared memory: read-only attach to host segments"
    severity = "high"
    maps_to = "P2 / P12 (IPC namespace)"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        try:
            with open("/proc/sysvipc/shm") as handle:
                header = handle.readline().split()
                rows = [dict(zip(header, line.split())) for line in handle if line.strip()]
        except OSError as exc:
            return Result(Status.SKIP, f"/proc/sysvipc/shm unreadable: {errno_name(exc)}")

        euid = os.geteuid()
        foreign = [
            r for r in rows
            if int(r["cpid"]) != os.getpid() and (int(r["uid"]) == euid or euid == 0)
        ]
        if not foreign:
            return Result(
                Status.SKIP,
                f"no SysV shm segments visible to test ({len(rows)} segment(s) total, "
                "none foreign to this process); the boundary is untested",
            )

        try:
            libc = ctypes.CDLL(None, use_errno=True)
        except OSError as exc:
            return Result(Status.SKIP, f"no libc: {errno_name(exc)}")
        libc.shmat.restype = ctypes.c_void_p
        libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]

        attached, denied, rw_attached = [], [], []
        for row in foreign[:5]:
            shmid = int(row["shmid"])
            ctypes.set_errno(0)
            addr = libc.shmat(shmid, None, SHM_RDONLY)
            if ctypes.cast(addr, ctypes.c_void_p).value in (None,) and addr in (0, ctypes.c_void_p(-1).value):
                denied.append(errno_name(OSError(ctypes.get_errno() or 0, "shmat")))
                continue
            if not addr:
                denied.append(errno_name(OSError(ctypes.get_errno() or 0, "shmat")))
                continue
            read_ok = "?"
            try:
                data = ctypes.string_at(addr, min(32, int(row["size"])))
                read_ok = len(data)
            except OSError as exc:
                read_ok = errno_name(exc)
            libc.shmdt(ctypes.c_void_p(addr))
            attached.append(
                f"shmid {shmid} (uid {row['uid']}, {row['size']}B, nattch {row['nattch']}): "
                f"attached read-only, read {read_ok}"
            )
            # The stronger half of the primitive: attach read-write. Verified
            # by attach success alone - no byte is written to foreign memory.
            ctypes.set_errno(0)
            addr_rw = libc.shmat(shmid, None, 0)
            if addr_rw and addr_rw != ctypes.c_void_p(-1).value:
                libc.shmdt(ctypes.c_void_p(addr_rw))
                rw_attached.append(shmid)

        detail = {
            "segments_visible": len(rows),
            "foreign": [r["shmid"] for r in foreign],
            "attached": attached,
            "rw_attached": rw_attached,
            "denied": denied,
            "euid": euid,
        }
        if rw_attached:
            return Result(
                Status.FAIL,
                "shmat attached to host shared memory READ-WRITE (no byte written, but the "
                "write primitive is proven): segments " + ", ".join(map(str, rw_attached[:3])),
                detail,
            )
        if attached:
            return Result(
                Status.FAIL,
                "shmat attached to host shared memory outside the policy: " + "; ".join(attached[:3]),
                detail,
            )
        return Result(
            Status.PASS,
            f"all {len(foreign)} foreign segment(s) refused attach ({denied[:2]}): control holds",
            detail,
        )


VECTOR = SysvShmVector()
