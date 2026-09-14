"""V19 — TOCTOU against Landlock's use-time path resolution.

Landlock evaluates the path at the moment of the operation, so a symlink whose
target changes between "check" and "use" should not help. This vector tries
anyway: one thread flips a symlink between an in-policy file and an
out-of-policy one while another opens it in a tight loop. Any successful read
of the out-of-policy content means resolution is cached somewhere it must not
be, which would be a race win.
"""
import os
import threading
import time

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore


class ToctouRaceVector(Vector):
    id = "V19"
    title = "TOCTOU: symlink swap between check and use"
    severity = "high"
    maps_to = "P17"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        outside = ctx.seed
        if not outside:
            for candidate in (os.path.join(ctx.out_dir, "seedfile"), "/etc/hostname"):
                if os.path.exists(candidate) and not ctx.policy_writable(candidate):
                    outside = candidate
                    break
        if not outside:
            return Result(Status.SKIP, "no readable out-of-policy target for the race")
        # if the target is directly readable there is no boundary to race past;
        # that is V12's finding, not a race win.
        try:
            fd = os.open(outside, os.O_RDONLY)
            os.close(fd)
            return Result(
                Status.SKIP,
                f"{outside} is directly readable; no boundary to race (see V12)",
            )
        except OSError:
            pass
        inside = os.path.join(ctx.scratch, "race-inside")
        with open(inside, "w") as handle:
            handle.write("INSIDE")
        link = os.path.join(ctx.scratch, "race-link")

        stop = threading.Event()
        errors = []

        def flip():
            while not stop.is_set():
                tmp = link + ".tmp"
                try:
                    if os.path.lexists(tmp):
                        os.unlink(tmp)
                    os.symlink(outside, tmp)
                    os.rename(tmp, link)
                    if os.path.lexists(tmp):
                        os.unlink(tmp)
                    os.symlink(inside, tmp)
                    os.rename(tmp, link)
                except OSError:
                    pass

        thread = threading.Thread(target=flip, daemon=True)
        thread.start()
        wins = 0
        attempts = 0
        deadline = time.time() + 3.0
        try:
            while time.time() < deadline and wins == 0:
                attempts += 1
                try:
                    with open(link, "rb") as handle:
                        data = handle.read(16)
                except OSError:
                    continue
                if data.startswith(b"ROCKET") or data.startswith(b"root:"):
                    wins += 1
        finally:
            stop.set()
            thread.join(timeout=1.0)
            try:
                os.unlink(link)
            except OSError:
                pass

        if wins:
            return Result(Status.FAIL, f"read out-of-policy content through the race ({outside})")
        return Result(
            Status.PASS,
            f"{attempts} opens during the swap; none returned out-of-policy content",
            {"outside": outside},
        )


VECTOR = ToctouRaceVector()
