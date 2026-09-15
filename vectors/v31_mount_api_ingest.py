"""V31 — the new mount API as a Landlock detour (open_tree + move_mount).

Landlock evaluates paths at operation time, and the classic `mount(2)` is
filtered by seccomp. But the new mount API is a different syscall pair:
`open_tree(428)` and `move_mount(429)`, which need only `CAP_SYS_ADMIN` over
the owning user namespace. V6 already showed `clone(CLONE_NEWUSER)` succeeds
here, and filters written as a denylist of classic names usually miss both
new numbers. The chain: clone into a fresh user+mount namespace, re-root a
foreign file inside the write-granted workspace with `open_tree` +
`move_mount`, then read it through its new workspace path. Landlock sees a
workspace path and grants what it refused at the original one. Same trick as
the btrfs-snapshot finding, one layer up the VFS.

The helper prints one STATUS line per step, so a FAIL names exactly which
gate was missing: clone denied (the control holding), opentree/movemount
denied (the filter covering the new numbers), or read ok (the detour
working). All mounts live in the child's own mount namespace and vanish when
it exits; the helper's view dirs are removed by `cleanup()`.
"""
import os
import shutil
import subprocess

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

try:
    from _common import tools_dir
except ImportError:
    from _common import tools_dir  # type: ignore




class MountApiIngestVector(Vector):
    id = "V31"
    title = "open_tree/move_mount re-root a foreign file into the workspace"
    severity = "ship-blocker"
    maps_to = "P2 / V6 / V24"
    description = __doc__
    host_verify = "verify.sh (view dirs live in the run scratch only; nothing host-side)"

    def __init__(self):
        self._viewdir = None

    def check(self, ctx):
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        source = os.path.join(tools_dir(), "mount_ingest.c")
        if not cc or not os.path.exists(source):
            return Result(Status.SKIP, "no C compiler or helper source")
        scratch = ctx.scratch
        try:
            os.makedirs(scratch, exist_ok=True)
        except OSError:
            pass
        binary = os.path.join(scratch, "mount_ingest")
        build = subprocess.run(
            [cc, "-O2", "-o", binary, source],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if build.returncode != 0:
            return Result(Status.SKIP, f"build failed: {build.stderr.strip()[:160]}")

        self._viewdir = os.path.join(scratch, "mntview")
        try:
            os.makedirs(self._viewdir, exist_ok=True)
        except OSError as exc:
            return Result(Status.SKIP, f"no scratch view dir: {errno_name(exc)}")

        # Target discovery: seed first, then the daemon's own open files, then
        # fixed /etc candidates if this sandbox shows /etc at all, then the
        # policy read list as an in-policy mechanism control.
        sources = []
        seen = set()

        def add(path, origin):
            if path in seen or not os.path.isfile(path):
                return
            seen.add(path)
            sources.append((path, origin))

        if ctx.seed:
            add(ctx.seed, "seed")
        try:
            from _common import fd_inventory, is_regular_path, visible_pids
        except ImportError:
            from _common import fd_inventory, is_regular_path, visible_pids  # type: ignore
        for pid in visible_pids(limit=6):
            for entry in fd_inventory(pid):
                if is_regular_path(entry["target"]):
                    add(entry["target"], f"daemon pid {pid} fd {entry['fd']}")
        for path in ("/etc/hostname", "/etc/passwd", "/etc/hosts"):
            add(path, "/etc probe")
        for path in (ctx.host_files or [])[:2]:
            add(path, "policy read list (in-policy control)")
        if not sources:
            return Result(Status.SKIP, "no visible regular file to ingest")

        steps, reads = {}, []
        bypass, mechanism = None, None
        for target, origin in sources[:6]:
            direct = "ok"
            try:
                with open(target, "rb") as handle:
                    handle.read(1)
            except OSError as exc:
                direct = errno_name(exc)
            try:
                run = subprocess.run(
                    [binary, target, self._viewdir],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30,
                )
            except subprocess.TimeoutExpired:
                steps[target] = {"origin": origin, "direct": direct, "timeout": True}
                continue
            parsed = {"origin": origin, "direct": direct}
            for line in run.stdout.splitlines():
                if line.startswith("STATUS "):
                    parts = line.split(None, 3)
                    if len(parts) >= 3:
                        parsed[parts[1]] = parts[2] if len(parts) == 3 else f"{parts[2]} {parts[3]}"
                elif line.startswith("READ "):
                    parsed["READ"] = line[5:53]
            steps[target] = parsed
            if str(parsed.get("read", "")).startswith("ok") and "READ" in parsed:
                record = {"target": target, "origin": origin, "direct": direct,
                          "bytes": parsed["READ"]}
                reads.append(record)
                if direct != "ok":
                    bypass = record
                    break
                if mechanism is None:
                    mechanism = record
            if parsed.get("clone") == "denied":
                break

        if bypass:
            return Result(
                Status.FAIL,
                f"Landlock bypass: {bypass['target']} is direct-{bypass['direct']} but its content was "
                f"read through an open_tree+move_mount re-rooting into the workspace "
                f"(first bytes: {bypass['bytes']!r})",
                {"steps": steps, "ingested": reads},
            )
        clone_denied = any(str(s.get("clone", "")).startswith("denied") for s in steps.values())
        if clone_denied:
            return Result(
                Status.PASS,
                "clone(CLONE_NEWUSER|CLONE_NEWNS) denied: the mount-API route loses its "
                "capability source and the detour is closed here",
                {"steps": steps},
            )
        if mechanism:
            return Result(
                Status.SUSPECTED,
                f"the open_tree+move_mount detour re-rooted {mechanism['target']} and read it, but that "
                "target was directly readable anyway (in-policy control); no out-of-policy file "
                "was visible to prove the bypass end to end",
                {"steps": steps, "ingested": reads},
            )
        ot = {t: s.get("opentree", "-") for t, s in steps.items()}
        mm = {t: s.get("movemount", "-") for t, s in steps.items()}
        if all(str(v).startswith("denied") for v in ot.values()):
            return Result(
                Status.PASS,
                f"open_tree denied on every target: the filter covers the new numbers ({ot})",
                {"steps": steps},
            )
        if all(str(v).startswith("denied") for v in mm.values()):
            return Result(
                Status.PASS,
                f"open_tree allowed but move_mount denied on every target ({mm})",
                {"steps": steps},
            )
        return Result(
            Status.SUSPECTED,
            f"mount steps inconsistent, no read confirmed (clone={ot}, move={mm})",
            {"steps": steps},
        )

    def cleanup(self, ctx):
        if not self._viewdir:
            return Result(Status.INFO, "nothing to undo")
        removed = 0
        for name in ("view", "view2"):
            try:
                os.rmdir(os.path.join(self._viewdir, name))
                removed += 1
            except OSError:
                pass
        try:
            os.rmdir(self._viewdir)
            removed += 1
        except OSError:
            pass
        self._viewdir = None
        return Result(Status.INFO, f"removed {removed} scratch view path(s)")


VECTOR = MountApiIngestVector()
