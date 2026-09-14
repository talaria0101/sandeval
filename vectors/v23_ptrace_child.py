"""V23 — ptrace a child: attach, read its memory, write it back.

Denylist conformance suites validate ptrace with a call to pid 0 and call it
denied, which proves nothing. This vector exercises the real primitive: a
forked child does PTRACE_TRACEME and stops; the parent plants a marker string
before forking, so after the stop the child owns a private copy of the page it
lives on. The parent reads that copy with PTRACE_PEEKDATA and re-writes the
same word with PTRACE_POKEDATA. Recovering the marker from the child is proof
of arbitrary cross-process memory read and write — the reconnaissance and
injection halves of code injection in one syscall. If the filter denies
ptrace outright, the child says so and the vector PASSes.
"""
import ctypes
import os
import signal

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 3
WORD = 8  # bytes per PEEKDATA word on 64-bit platforms
MARKER = (b"SANDEVAL_V23" + b"\x00" * WORD)[:WORD]
TRACEME_DENIED = 3  # child exit code: PTRACE_TRACEME failed


class PtraceChildVector(Vector):
    id = "V23"
    title = "ptrace read/write of a stopped child's memory"
    severity = "high"
    maps_to = "P12 / V9 (behavioral)"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        try:
            libc = ctypes.CDLL(None, use_errno=True)
        except OSError as exc:
            return Result(Status.SKIP, f"no libc to call syscalls through: {errno_name(exc)}")
        libc.ptrace.restype = ctypes.c_long
        libc.ptrace.argtypes = [
            ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
        ]

        marker = ctypes.create_string_buffer(MARKER + b"\x00" * 8)
        addr = ctypes.addressof(marker)
        try:
            pid = os.fork()
        except OSError as exc:
            return Result(Status.SKIP, f"fork unavailable: {errno_name(exc)}")
        if pid == 0:  # child
            signal.alarm(10)
            rc = libc.ptrace(PTRACE_TRACEME, 0, None, None)
            if rc != 0:
                os._exit(TRACEME_DENIED)
            os.kill(os.getpid(), signal.SIGSTOP)  # trace-stop; parent peeks here
            os._exit(0)

        prev_alarm = signal.signal(
            signal.SIGALRM, lambda *_n: (_ for _ in ()).throw(TimeoutError("ptrace probe hung"))
        )
        signal.alarm(15)
        word_bytes = None
        poked = False
        try:
            _pid, status = os.waitpid(pid, os.WUNTRACED)
            if os.WIFEXITED(status) and os.WEXITSTATUS(status) == TRACEME_DENIED:
                ctypes.set_errno(0)  # errno belongs to the child; do not guess it
                return Result(
                    Status.PASS, "PTRACE_TRACEME denied in the child; ptrace filtered"
                )
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                return Result(Status.SKIP, "child died before reaching its trace-stop")
            ctypes.set_errno(0)
            word = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(addr), None)
            if word == -1:
                why = errno_name(OSError(ctypes.get_errno() or 0, "PTRACE_PEEKDATA"))
                self._reap(libc, pid)
                return Result(
                    Status.SUSPECTED,
                    f"trace-stop reached but PTRACE_PEEKDATA failed ({why})",
                )
            word_bytes = (word & ((1 << (WORD * 8)) - 1)).to_bytes(WORD, "little")
            ctypes.set_errno(0)
            if libc.ptrace(PTRACE_POKEDATA, pid, ctypes.c_void_p(addr), ctypes.c_void_p(word)) != -1:
                poked = True
            self._reap(libc, pid)
        except (TimeoutError, OSError, ChildProcessError) as exc:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
            return Result(Status.SKIP, f"ptrace probe interrupted: {exc}")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, prev_alarm)

        if word_bytes == MARKER:
            detail = {"marker": MARKER.rstrip(b"\x00").decode(), "read": word_bytes.hex(), "writeback": poked}
            note = "write-back verified" if poked else "write not attempted/failed"
            return Result(
                Status.FAIL,
                f"read the marker out of the stopped child's private memory via "
                f"PTRACE_PEEKDATA ({note}); arbitrary peer-memory R/W works",
                detail,
            )
        return Result(
            Status.SUSPECTED,
            f"PTRACE_PEEKDATA returned data but not the marker "
            f"(got {word_bytes.hex() if word_bytes else '?'})",
        )

    @staticmethod
    def _reap(libc, pid):
        libc.ptrace(PTRACE_CONT, pid, None, None)
        try:
            os.kill(pid, signal.SIGCONT)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass


VECTOR = PtraceChildVector()
