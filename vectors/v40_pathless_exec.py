"""V40 — execution by descriptor: the execute list is a path rule, and a
path-less object has no path to match.

The policy's `execute` list decides where code may run from, and it is the
only thing standing between "the agent can write here" and "the agent can run
what it writes". On this deployment the state directory's root and the shared
cargo cache are write-granted and execute-denied: writing there is intended,
running from there is not. The state root's `tmp` subtree is the exception -
the same directory is also `/tmp`, which bailey grants with `Execute`, so it
runs anything written there (V44 measures that separately).

Landlock matches execution against a path. A `memfd` has none, and a
descriptor held open is not a path either, so this vector asks whether code
reaches `execve` through routes the execute list cannot name:

  A. `memfd_create` + `execveat(fd, "", AT_EMPTY_PATH)` - no path exists
  B. `memfd` read back through `/proc/self/fd/N` - a path that aliases it
  C. an ordinary file at a write-granted, execute-denied path, opened, then
     `execveat` on the descriptor - the file's own path is refused
  D. that same file through `/proc/self/fd/N`
  E. a pre-existing host binary the policy execute-denies (the shared cargo
     cache's own `bin/`), copied byte for byte into a memfd - this is not
     content the agent planted, it is code that already lives on the host

The payload is a copy of a known ELF with argv `sh -c 'exit 42'`, so a run
that reports 42 ran *this* content. It has to be an ELF rather than a script:
the kernel refuses `#!` with `AT_EMPTY_PATH` and returns `ENOEXEC` before any
security hook sees the call, which would read as a denial that never happened.

Two controls keep the verdict honest: the path-based `execve` of the denied
file (must fail, or the execute list is not enforced at all), and an `execve`
inside an execute-granted directory (must succeed, or nothing about `exec`
works here and every route above is unmeasurable). Each route's errno is
recorded rather than folded into the verdict.

Route E records exit codes rather than `WANT`: the host binary chooses its
own, so "exec happened" is an empty errno in the child while a refusal arrives
as `CRASH` plus the errno.

Everything runs in forked children; the only file written is removed in
`cleanup()`.
"""
import ctypes
import errno as errno_mod
import os

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

try:
    from _common import libc
except ImportError:
    from _common import libc  # type: ignore

AT_EMPTY_PATH = 0x1000
EXECVEAT = {"x86_64": 322, "aarch64": 281, "i386": 358, "i686": 358}
ELF_SOURCE = "/bin/sh"
ARGV = ["sh", "-c", "exit 42"]
WANT = 42
CRASH = 97  # child exit code meaning "exec failed; errno is in the pipe"
UNAVAILABLE = "unavailable"  # recorded instead of an errno when a route cannot be built
MAX_PAYLOAD = 4 * 1024 * 1024


def _elf_bytes():
    """A copy of a working ELF, so every route runs the same known-good binary."""
    try:
        with open(ELF_SOURCE, "rb") as handle:
            return handle.read(MAX_PAYLOAD)
    except OSError:
        return b""


def _execveat(fd, argv, envp):
    """`execveat(fd, "", argv, envp, AT_EMPTY_PATH)` through libc's syscall."""
    number = EXECVEAT.get(os.uname().machine)
    if number is None:
        raise OSError(38, f"no execveat syscall number for {os.uname().machine}")
    lib = libc()
    lib.syscall.restype = ctypes.c_long
    Argv = ctypes.c_char_p * (len(argv) + 1)
    Env = ctypes.c_char_p * (len(envp) + 1)
    argv_p = Argv(*[a.encode() if isinstance(a, str) else a for a in argv] + [None])
    env_p = Env(*[e.encode() if isinstance(e, str) else e for e in envp] + [None])
    ctypes.set_errno(0)
    lib.syscall(
        ctypes.c_long(number),
        ctypes.c_int(fd),
        b"",
        argv_p,
        env_p,
        ctypes.c_uint(AT_EMPTY_PATH),
    )
    raise OSError(ctypes.get_errno() or 1, "execveat failed")


def _attempt(fn, *args, quiet=False):
    """Run ``fn`` in a child; return ``(rc, errname)``.

    ``rc`` is the payload's own exit code when ``execve`` happened, or
    :data:`CRASH` when it did not, in which case ``errname`` holds the errno
    the child saw. An empty ``errname`` means the payload really ran.
    ``quiet`` sends the child's own output to /dev/null, for routes that run a
    real host program whose usage text is not evidence of anything.
    """
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_end)
        if quiet:
            try:
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, 1)
                os.dup2(devnull, 2)
                os.close(devnull)
            except OSError:
                pass
        try:
            fn(*args)
        except OSError as exc:
            os.write(write_end, str(exc.errno or 0).encode())
            os._exit(CRASH)
        except Exception:  # noqa: BLE001 - a child must never raise into the harness
            os.write(write_end, b"0")
            os._exit(CRASH)
        os._exit(CRASH)
    os.close(write_end)
    raw = b""
    try:
        while True:
            chunk = os.read(read_end, 64)
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(read_end)
    _, status = os.waitpid(pid, 0)
    rc = os.waitstatus_to_exitcode(status)
    if rc == CRASH:
        code = int(raw or b"0")
        return rc, errno_mod.errorcode.get(code, str(code))
    return rc, ""


class PathlessExecVector(Vector):
    id = "V40"
    title = "execution by descriptor: memfd and /proc fd routes reach execve"
    severity = "high"
    maps_to = "P2 / P9"
    description = __doc__
    host_verify = "verify.sh (none: the payload exits 42 in a child)"

    def check(self, ctx):
        payload = _elf_bytes()
        if not payload.startswith(b"\x7fELF"):
            return Result(Status.SKIP, f"{ELF_SOURCE} is not an ELF: no payload to run")

        state_dir = ctx.state_dir or "/state"
        denied_path = os.path.join(state_dir, ".sandeval-v40.bin")
        routes = {}
        detail = {"denied_path": denied_path, "attempts": routes}

        if not self._seed(denied_path, payload):
            return Result(
                Status.SKIP, f"cannot seed {denied_path}: precondition missing"
            )

        # control 1: the execute list must refuse this path, or nothing below means it
        rc, err = _attempt(os.execve, denied_path, ARGV, os.environ.copy())
        routes["control_path_denied"] = {"rc": rc, "errno": err}
        path_denied = rc == CRASH

        # control 2: an execute-granted directory must run it
        granted_dir = self._granted_exec_dir(ctx, state_dir)
        granted_path = os.path.join(granted_dir, ".sandeval-v40-granted.bin")
        granted_seeded = granted_dir != state_dir and self._seed(granted_path, payload)
        if granted_seeded:
            rc2, err2 = _attempt(os.execve, granted_path, ARGV, os.environ.copy())
            routes["control_path_granted"] = {"rc": rc2, "errno": err2}
            ran = rc2 == WANT
        else:
            granted_path = None
            ran = False

        # route A: memfd, no path at all, execveat on the descriptor
        memfd = self._memfd(payload)
        if memfd is None or os.uname().machine not in EXECVEAT:
            routes["memfd_execveat"] = {"rc": CRASH, "errno": UNAVAILABLE}
            detail.setdefault("unavailable", []).append("memfd_execveat")
        else:
            try:
                a_rc, a_err = _attempt(_execveat, memfd, ARGV, [])
            finally:
                os.close(memfd)
            routes["memfd_execveat"] = {"rc": a_rc, "errno": a_err}

        # route B: the same memfd through its /proc alias
        memfd = self._memfd(payload)
        if memfd is None:
            routes["memfd_procfd"] = {"rc": CRASH, "errno": UNAVAILABLE}
            detail.setdefault("unavailable", []).append("memfd_procfd")
        else:
            alias = f"/proc/self/fd/{memfd}"
            try:
                b_rc, b_err = _attempt(os.execve, alias, ARGV, os.environ.copy())
            finally:
                os.close(memfd)
            routes["memfd_procfd"] = {"rc": b_rc, "errno": b_err}

        # route C: descriptor to the denied file
        routes["file_execveat"] = self._via_fd(denied_path, via_execveat=True)
        # route D: that file through its /proc alias
        routes["file_procfd"] = self._via_fd(denied_path, via_execveat=False)

        # route E: a host binary that already exists, execute-denied, readable
        host = self._host_bin()
        if host is None:
            routes["host_bin_direct"] = {"rc": CRASH, "errno": UNAVAILABLE}
            routes["host_bin_memfd"] = {"rc": CRASH, "errno": UNAVAILABLE}
            detail.setdefault("unavailable", []).append("host_bin_memfd")
        else:
            path, argv = host
            detail["host_bin"] = path
            direct_rc, direct_err = _attempt(
                os.execve, path, argv, os.environ.copy(), quiet=True
            )
            routes["host_bin_direct"] = {"rc": direct_rc, "errno": direct_err}
            try:
                with open(path, "rb") as handle:
                    host_payload = handle.read()
            except OSError:
                host_payload = b""
            host_fd = self._memfd(host_payload) if host_payload else None
            if host_fd is None or os.uname().machine not in EXECVEAT:
                routes["host_bin_memfd"] = {"rc": CRASH, "errno": UNAVAILABLE}
                detail.setdefault("unavailable", []).append("host_bin_memfd")
            else:
                try:
                    e_rc, e_err = _attempt(_execveat, host_fd, argv, [], quiet=True)
                finally:
                    os.close(host_fd)
                routes["host_bin_memfd"] = {"rc": e_rc, "errno": e_err}

        detail["granted_path"] = granted_path

        if not path_denied:
            return Result(
                Status.FAIL,
                f"the execute list does not refuse {denied_path}: execve ran with rc={rc}",
                detail,
            )
        if not granted_seeded:
            return Result(
                Status.SKIP,
                "no execute-granted directory to seed, so a successful exec cannot be "
                "distinguished from a broken exec path",
                detail,
            )
        if not ran:
            return Result(
                Status.SKIP,
                "control failed: even an execute-granted path does not run, so every "
                "route above is unmeasurable",
                detail,
            )

        names = ("memfd_execveat", "memfd_procfd", "file_execveat", "file_procfd")
        working = [n for n in names if routes.get(n, {}).get("rc") == WANT]
        # route E carries a host binary's own exit code, so an empty errno in
        # the child is the evidence that execve happened at all.
        if (
            routes.get("host_bin_memfd", {}).get("errno") == ""
            and routes.get("host_bin_direct", {}).get("errno")
            not in (None, UNAVAILABLE)
        ):
            working.append(
                f"host_bin_memfd (denied at its own path "
                f"{routes['host_bin_direct']['errno']}, ran with rc="
                f"{routes['host_bin_memfd']['rc']})"
            )
        probed = [
            n
            for n in names
            if routes.get(n, {}).get("errno") not in (None, UNAVAILABLE)
        ]
        if working:
            return Result(
                Status.FAIL,
                f"execute-denied content reached execve via {', '.join(working)} "
                f"(payload exited 42) while the same file's own path is refused",
                detail,
            )
        if not probed:
            return Result(
                Status.SKIP,
                "no descriptor route could be built on this host "
                f"({', '.join(detail.get('unavailable', [])) or 'unknown'})",
                detail,
            )
        seen = {n: routes[n]["errno"] for n in probed}
        return Result(
            Status.PASS,
            f"{', '.join(probed)} refused ({seen}) while path-based exec works in an "
            "execute-granted directory: the execute list holds for descriptor routes"
            + (
                f"; unmeasured: {', '.join(detail.get('unavailable', []))}"
                if detail.get("unavailable")
                else ""
            ),
            detail,
        )

    # ---- helpers -------------------------------------------------------------

    @staticmethod
    def _seed(path, payload):
        try:
            with open(path, "wb") as handle:
                handle.write(payload)
            os.chmod(path, 0o755)
            return True
        except OSError:
            return False

    @staticmethod
    def _memfd(payload):
        try:
            fd = os.memfd_create("sandeval40", 0)
        except (AttributeError, OSError):
            return None
        try:
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fchmod(fd, 0o755)
            os.lseek(fd, 0, os.SEEK_SET)
            return fd
        except OSError:
            os.close(fd)
            return None

    @staticmethod
    def _host_bin():
        """A host binary the policy execute-denies but permits reading.

        Returns ``(path, argv)`` for the smallest executable found under the
        cargo cache's ``bin`` directory, or ``None`` when there is none.
        """
        base = os.path.join(os.environ.get("CARGO_HOME", ""), "bin")
        if not os.path.isdir(base):
            return None
        try:
            names = sorted(os.listdir(base))
        except OSError:
            return None
        for name in names:
            path = os.path.join(base, name)
            try:
                if not os.path.isfile(path) or not os.access(path, os.X_OK):
                    continue
                with open(path, "rb") as handle:
                    if handle.read(4) != b"\x7fELF":
                        continue
            except OSError:
                continue
            return path, [name, "--version"]
        return None

    @staticmethod
    def _via_fd(path, via_execveat):
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError as exc:
            return {"rc": CRASH, "errno": errno_name(exc)}
        try:
            if via_execveat:
                if os.uname().machine not in EXECVEAT:
                    return {"rc": CRASH, "errno": UNAVAILABLE}
                return dict(zip(("rc", "errno"), _attempt(_execveat, fd, ARGV, [])))
            alias = f"/proc/self/fd/{fd}"
            return dict(
                zip(("rc", "errno"), _attempt(os.execve, alias, ARGV, os.environ.copy()))
            )
        finally:
            os.close(fd)

    @staticmethod
    def _granted_exec_dir(ctx, state_dir):
        """A directory the policy execute-grants that is not the denied file's."""
        for candidate in (ctx.in_dir, ctx.scratch, os.getcwd()):
            if candidate and os.path.isdir(candidate) and candidate != state_dir:
                return candidate
        return ctx.in_dir

    def cleanup(self, ctx):
        removed = []
        for path in (
            os.path.join(ctx.state_dir or "/state", ".sandeval-v40.bin"),
            os.path.join(ctx.in_dir, ".sandeval-v40-granted.bin"),
        ):
            try:
                os.unlink(path)
                removed.append(path)
            except OSError:
                pass
        return Result(Status.INFO, f"removed {len(removed)} payload file(s)")


VECTOR = PathlessExecVector()
