"""V22 — chroot(2) reachable, and the classic escape walk.

Landlock has no opinion about chroot(2), so a policy that relies on a changed
root for isolation is only as strong as the caller's inability to chroot back
out. The classic escape needs a descriptor to a directory outside the new
root: fchdir to it, and the process can reach the whole mount namespace with
relative paths while its root still points into the cage. The vector runs the
entire sequence in a forked child so the harness is never left with a broken
root, and never claims FAIL unless the escaped vantage can open a file the
policy forbids: on a Landlock sandbox a successful walk is a SUSPECTED-grade
surface finding, because Landlock still mediates every path the escape can
name.
"""
import json
import os
import signal

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore


class ChrootEscapeVector(Vector):
    id = "V22"
    title = "chroot(2) reachable / classic escape walk"
    severity = "high"
    maps_to = "P9 / sweep chroot"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        read_fd, write_fd = os.pipe()
        try:
            pid = os.fork()
        except OSError as exc:
            os.close(read_fd)
            os.close(write_fd)
            return Result(Status.SKIP, f"fork unavailable: {errno_name(exc)}")
        if pid == 0:  # child: probe, report one JSON line, never return
            os.close(read_fd)
            signal.alarm(10)
            report = {"stage": "exception", "why": "unreachable"}
            try:
                report = self._probe(ctx)
            except Exception as exc:  # noqa: BLE001 - report and die quietly
                report = {"stage": "exception", "why": f"{type(exc).__name__}: {exc}"}
            try:
                os.write(write_fd, json.dumps(report).encode())
            finally:
                os._exit(0)
        os.close(write_fd)
        deadline = signal.signal(
            signal.SIGALRM, lambda *_n: (_ for _ in ()).throw(TimeoutError("chroot probe hung"))
        )
        signal.alarm(15)
        data = b""
        try:
            while True:
                chunk = os.read(read_fd, 65536)
                if not chunk:
                    break
                data += chunk
        except (TimeoutError, OSError):
            pass
        finally:
            os.close(read_fd)
            signal.alarm(0)
            signal.signal(signal.SIGALRM, deadline)
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        if not data.strip():
            return Result(Status.SKIP, "chroot probe child produced no report")
        try:
            report = json.loads(data.decode(errors="replace"))
        except ValueError:
            return Result(Status.SKIP, f"unparseable chroot report: {data[:80]!r}")
        stage = report.get("stage")
        if stage == "chroot-denied":
            return Result(
                Status.PASS, f"chroot(2) denied ({report.get('why')}); no root games available"
            )
        if stage == "chroot-ok-fchdir-denied":
            return Result(
                Status.PASS,
                "chroot reachable but fchdir to a descriptor outside the cage was denied "
                f"({report.get('why')}); the escape walk cannot start",
            )
        if stage == "walked":
            if report.get("escaped"):
                read = report.get("forbidden_read")
                if read == "ok":
                    return Result(
                        Status.FAIL,
                        "escape walk reached the real root AND an out-of-policy path was "
                        "opened from it; confinement is not holding",
                        report,
                    )
                return Result(
                    Status.SUSPECTED,
                    f"chroot reachable and escape walk succeeded in {report.get('steps')} "
                    f"step(s); out-of-policy read from the escaped vantage: {read}. "
                    "Confinement must come from Landlock/seccomp, not a changed root.",
                    report,
                )
            return Result(
                Status.PASS,
                "chroot reachable but the walk never reached the real root "
                f"(stopped after {report.get('steps')} step(s))",
                report,
            )
        return Result(Status.SKIP, f"chroot probe ended oddly: {report}")

    # runs in the forked child only ------------------------------------------

    def _probe(self, ctx):
        real_root = os.stat("/")  # Landlock does not mediate stat(2)
        # The escape needs a descriptor to a directory outside the cage. Landlock
        # may refuse to open the more privileged ones; try our own scratch first.
        root_fd = -1
        for candidate in (ctx.scratch, ctx.in_dir, "/tmp", os.getcwd(), "/"):
            try:
                root_fd = os.open(candidate, os.O_RDONLY | os.O_DIRECTORY)
                break
            except OSError:
                continue
        if root_fd < 0:
            return {"stage": "exception", "why": "no openable directory descriptor for the walk"}
        cage = os.path.join(ctx.scratch, "chroot-cage")
        os.makedirs(cage, exist_ok=True)
        try:
            os.chroot(cage)
        except OSError as exc:
            return {"stage": "chroot-denied", "why": errno_name(exc)}
        # root is now the cage; cwd is still ctx.scratch, which is outside it
        try:
            os.fchdir(root_fd)
        except OSError as exc:
            return {"stage": "chroot-ok-fchdir-denied", "why": errno_name(exc)}
        steps = 0
        escaped = False
        for _ in range(64):
            try:
                os.chdir("..")
            except OSError:
                break
            steps += 1
            st = os.stat(".")
            if st.st_ino == real_root.st_ino and st.st_dev == real_root.st_dev:
                escaped = True
                break
        report = {"stage": "walked", "steps": steps, "escaped": escaped}
        if escaped:
            try:  # restore the process root while cwd is the real root
                os.chroot(".")
                report["restored"] = True
            except OSError as exc:
                report["restored"] = f"failed: {errno_name(exc)}"
            target = ctx.seed or os.path.join(ctx.out_dir, "seedfile")
            try:
                with open(target, "rb") as handle:
                    handle.read(64)
                report["forbidden_read"] = "ok"
            except OSError as exc:
                report["forbidden_read"] = errno_name(exc)
        return report


VECTOR = ChrootEscapeVector()
