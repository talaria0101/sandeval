"""V12 — reaching an out-of-policy file by direct, symlink and hardlink paths.

The operator seeds a file outside the policy (`$OUT/seedfile`, a canary flag).
Landlock evaluates the *final* path of an operation, so a symlink created
inside the policy must not become a way to read the target, and a cross-boundary
hardlink must be refused. This vector tries each route and reports the first one
that yields a byte. Content is never copied into the report.
"""
import os

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore


class OutOfPolicyReadVector(Vector):
    id = "V12"
    title = "out-of-policy file read (direct / symlink / hardlink / proc fd)"
    severity = "ship-blocker"
    maps_to = "P2 / P14 / sweep out-symlink-read"
    description = __doc__
    host_verify = "verify.sh (seedfile)"

    def check(self, ctx):
        targets = []
        if ctx.seed:
            targets.append(ctx.seed)
        for candidate in (os.path.join(ctx.out_dir, "seedfile"), os.path.join(ctx.out_dir, "flag.txt")):
            if os.path.exists(candidate) and candidate not in targets:
                targets.append(candidate)
        targets = [t for t in targets if not ctx.policy_writable(t)]
        if not targets:
            return Result(Status.SKIP, "no readable out-of-policy seed configured (--seed / $OUT/seedfile)")
        wins = []
        for target in targets:
            methods = {}
            methods["direct"] = self._read_first_byte(target)
            link = os.path.join(ctx.scratch, "seedlink")
            try:
                if os.path.lexists(link):
                    os.unlink(link)
                os.symlink(target, link)
                methods["symlink"] = self._read_first_byte(link)
            except OSError as exc:
                methods["symlink"] = errno_name(exc)
            hard = os.path.join(ctx.scratch, "seedhard")
            try:
                if os.path.lexists(hard):
                    os.unlink(hard)
                os.link(target, hard)
                methods["hardlink"] = self._read_first_byte(hard)
            except OSError as exc:
                methods["hardlink"] = errno_name(exc)
            # the /proc/self/fd route: an already-open description re-opened
            # by path. Open the target (or its symlink alias) O_PATH and try
            # the read through /proc/self/fd/N.
            methods["proc-fd"] = self._read_via_proc_fd(
                link if os.path.islink(link) else target
            )
            for method, outcome in methods.items():
                if outcome == "read":
                    wins.append(f"{target} via {method}")
        if wins:
            return Result(Status.FAIL, "out-of-policy content reached: " + "; ".join(wins))
        return Result(Status.PASS, f"{len(targets)} out-of-policy seed(s) refused on every route")

    @staticmethod
    def _read_via_proc_fd(path):
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_PATH", 0))
        except OSError as exc:
            return errno_name(exc)
        try:
            return OutOfPolicyReadVector._read_first_byte(f"/proc/self/fd/{fd}")
        finally:
            os.close(fd)

    @staticmethod
    def _read_first_byte(path):
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError as exc:
            return errno_name(exc)
        try:
            data = os.read(fd, 1)
            return "read" if data else "empty"
        except OSError as exc:
            return errno_name(exc)
        finally:
            os.close(fd)


VECTOR = OutOfPolicyReadVector()
