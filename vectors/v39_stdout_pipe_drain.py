"""V39 — bytes written into the orchestrator's stdout pipe are drained by a
reader the sandbox cannot address.

V5 proved `/proc/<pid>/fd/1` opens for write and stopped at the open; V29
wrote a marker through a duplicated descriptor and reported that delivery was
not demonstrated, because the marker never appeared in the transcript. This
vector settles the delivery question by measuring the pipe instead of the
transcript: it writes newline-only payloads into the orchestrator's stdout
pipe and compares how much the kernel accepts against a control pipe that
nobody reads.

A pipe holds ~64 KiB. If no process is reading, a non-blocking write stops at
that capacity and reports `EAGAIN`; if a reader on the other end is running,
the write is drained without limit. Anything well past the control capacity
means an external process is consuming bytes this sandbox put there, in real
time.

The payload is newline-only on purpose: it is the one byte a JSONL framer
accepts without a record, and errand's `dispatch()` discards empty lines
before parsing, so the probe cannot corrupt the stream it is measuring.
Chunked at `PIPE_BUF` so a write never interleaves with the other writer's
record.
"""
import errno
import fcntl
import os
import time

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

try:
    from _common import fd_inventory, visible_pids
except ImportError:
    from _common import fd_inventory, visible_pids  # type: ignore

CHUNK = 4096  # <= PIPE_BUF: one write never interleaves with the other writer
CEILING = 512 * 1024  # 8x the usual pipe capacity, well short of the 8 MiB framer limit
WINDOW = 2.0
SPIN_LIMIT = 100  # consecutive refused writes before "nobody is reading"
SPIN_SLEEP = 0.01  # so a live reader gets the CPU between turns


def _fill(fd, ceiling=CEILING, window=WINDOW):
    """Write newline bytes until the pipe stops taking more, the ceiling, or
    the window closes.

    Returns ``(accepted, reason)`` where reason is one of ``drained``,
    ``full``, ``window`` or an errno name. A single ``EAGAIN`` is not evidence
    of a missing consumer: a live reader drains between writes, so the pipe
    stalls and unstalls constantly. The loop therefore keeps retrying until
    ``SPIN_LIMIT`` consecutive refused writes, which means the far end stopped
    draining rather than that it was busy for a moment.
    """
    fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
    payload = b"\n" * CHUNK
    accepted = 0
    deadline = time.monotonic() + window
    spins = 0
    while accepted < ceiling:
        if time.monotonic() > deadline:
            return accepted, "window"
        try:
            accepted += os.write(fd, payload)
            spins = 0
        except BlockingIOError:
            spins += 1
            if spins >= SPIN_LIMIT:
                return accepted, "full"
            time.sleep(SPIN_SLEEP)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                spins += 1
                if spins >= SPIN_LIMIT:
                    return accepted, "full"
                time.sleep(SPIN_SLEEP)
            else:
                return accepted, errno_name(exc)
    return accepted, "drained"


class StdoutPipeDrainVector(Vector):
    id = "V39"
    title = "orchestrator stdout pipe drained by a reader outside the sandbox"
    severity = "ship-blocker"
    maps_to = "P12 / P15"
    description = __doc__
    host_global = True  # the payload enters a host-side stream, however harmless
    host_verify = "verify.sh (none: delivery is scored by the drain ratio)"

    def check(self, ctx):
        target, inode = self._stdout_pipe()
        if target is None:
            return Result(Status.SKIP, "no orchestrator stdout pipe visible")

        holders = self._holders(inode)
        in_ns_readers = [
            h for h in holders if h["pid"] != target and h["readable"]
        ]

        control_fd, control_write = os.pipe()
        try:
            control, control_reason = _fill(control_write, window=1.5)
        finally:
            os.close(control_write)
            os.close(control_fd)

        try:
            write_fd = os.open(f"/proc/{target}/fd/1", os.O_WRONLY | os.O_NONBLOCK)
        except OSError as exc:
            return Result(
                Status.SKIP,
                f"stdout pipe not write-openable: {errno_name(exc)}",
                {"control_capacity": control},
            )
        try:
            accepted, reason = _fill(write_fd)
        finally:
            os.close(write_fd)

        detail = {
            "target_pid": target,
            "pipe": inode,
            "control_capacity": control,
            "control_reason": control_reason,
            "accepted": accepted,
            "reason": reason,
            "holders": holders,
            "in_namespace_readers": in_ns_readers,
            "payload": f"newline-only, {CEILING} byte ceiling, {WINDOW}s window",
            "external_reader": not in_ns_readers,
        }

        if reason == "full" or accepted <= control * 2:
            return Result(
                Status.PASS,
                f"pipe stalled at {accepted} bytes ({reason}) against a "
                f"{control}-byte control ({control_reason}): no consumer on the "
                "other end",
                detail,
            )
        where = (
            "outside this pid namespace" if not in_ns_readers else "inside it"
        )
        return Result(
            Status.FAIL,
            f"{accepted} bytes of injected payload drained ({reason}) against a "
            f"{control}-byte control ({control_reason}): a reader {where} is "
            f"consuming bytes this sandbox wrote into {target}'s stdout pipe",
            detail,
        )

    @staticmethod
    def _stdout_pipe():
        """``(pid, inode)`` for a visible process whose stdout is a pipe."""
        order = [1] + [p for p in visible_pids() if p != 1]
        for pid in order:
            try:
                target = os.readlink(f"/proc/{pid}/fd/1")
            except OSError:
                continue
            if target.startswith("pipe:["):
                return pid, target
        return None, None

    @staticmethod
    def _holders(inode):
        """Every visible descriptor on that pipe, with its access mode."""
        out = []
        for pid in visible_pids(limit=64, exclude={os.getpid()}):
            for entry in fd_inventory(pid):
                if entry["target"] != inode:
                    continue
                flags = entry["flags"]
                mode = None if flags is None else flags & os.O_ACCMODE
                out.append(
                    {
                        "pid": pid,
                        "fd": entry["fd"],
                        "readable": mode in (os.O_RDONLY, os.O_RDWR),
                    }
                )
        return out


VECTOR = StdoutPipeDrainVector()
