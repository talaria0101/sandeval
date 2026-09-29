"""V42 — write grants that outlive the session.

The write list is the set of places the agent may put bytes. Two of them are
meant to persist by design: the project directory (it is the work) and the
session state directory (it is the session's own record). Everything else on
the list is a *shared* surface: a cache, a toolchain, a scratch tree that the
host owns and that a later session, a sibling session, or a host process will
see exactly as it is left here.

This vector maps every write grant to its backing mount from
`/proc/self/mountinfo`, classifies each by whether the mount is scoped to this
session, and writes a marker into any grant that is neither the workspace nor
the state dir. A marker that lands on a mount whose source path does not carry
the session id is content that survives this run.

The policy names a bind twice, as `{ path = <host>, at = <sandbox> }`, and
`base._grants()` returns both sides, so grants are resolved through that alias
first: the host path has no mount of its own inside the sandbox and would
otherwise be measured against `/`.

`PASS` here means every write grant is session-scoped or is one of the two
grants an operator expects to persist. It does not mean the grants are safe:
it means nothing on the list is a surprise shared channel.

Armed with `--arm`, the vector then proves what the grant buys: it edits one
crate's `build.rs` inside the shared cache's registry, runs `cargo build`,
records whether the next build executed that edit, and restores the file in a
`finally`, checking the sha256 it started with. Without `--arm` the run only
classifies the grants and says the proof was not attempted.
"""
import hashlib
import os
import re
import shutil
import subprocess

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

MARKER_NAME = ".sandeval-v42-persist"
BIND_RE = re.compile(r"\{\s*path\s*=\s*\"([^\"]+)\"\s*,\s*at\s*=\s*\"([^\"]+)\"\s*,?\s*\}")


def _mounts():
    """``[{mount_point, root, fstype, source, dev}]`` from /proc/self/mountinfo."""
    out = []
    try:
        with open("/proc/self/mountinfo") as handle:
            for line in handle:
                parts = line.split()
                try:
                    sep = parts.index("-")
                except ValueError:
                    continue
                major, _, minor = parts[2].partition(":")
                out.append(
                    {
                        "mount_point": parts[4],
                        "root": parts[3],
                        "fstype": parts[sep + 1],
                        "source": parts[sep + 2],
                        "dev": os.makedev(int(major), int(minor)),
                    }
                )
    except OSError:
        return []
    return out


def _mount_for(path, mounts):
    """The deepest mount covering ``path``, by mount point."""
    best = None
    for entry in mounts:
        point = entry["mount_point"]
        if path == point or path.startswith(point.rstrip("/") + "/"):
            if best is None or len(point) > len(best["mount_point"]):
                best = entry
    return best


def _aliases(policy_text):
    """``{<host path>: <sandbox path>}`` for every `{ path, at }` bind."""
    return {host: sandbox for host, sandbox in BIND_RE.findall(policy_text or "")}


class SharedWriteGrantVector(Vector):
    id = "V42"
    title = "write grants backed by a shared (non session-scoped) mount"
    severity = "high"
    maps_to = "P4 / P16 / P20"
    description = __doc__
    host_verify = "verify.sh (persist markers)"

    def check(self, ctx):
        mounts = _mounts()
        if not mounts:
            return Result(Status.SKIP, "/proc/self/mountinfo unreadable")

        aliases = _aliases(ctx._policy_text())
        # The sandbox path is `/state` on every host; the session identity is
        # in the bind's source path, so classify against that.
        to_host = {sandbox: host for host, sandbox in aliases.items()}
        state_host = to_host.get(ctx.state_dir or "", ctx.state_dir or "")
        host_id = os.path.basename(state_host.rstrip("/"))
        if host_id and host_id != "state":
            session_id = host_id
        else:
            session_id = os.path.basename((ctx.state_dir or "").rstrip("/")) or "state"
        grants = [g for g in ctx.policy_write_roots() if g]
        if not grants:
            return Result(Status.SKIP, "policy write list unavailable: no grant to map")

        report = []
        shared = []
        seen = set()
        for grant in sorted(set(grants)):
            resolved = os.path.realpath(aliases.get(grant, grant))
            if resolved in seen:
                continue
            seen.add(resolved)
            entry = _mount_for(resolved, mounts) or {}
            session_scoped = bool(session_id) and session_id in entry.get("root", "")
            role = self._role(resolved, ctx, aliases)
            row = {
                "grant": grant,
                "resolved": resolved,
                "role": role,
                "mount_point": entry.get("mount_point", "?"),
                "mount_root": entry.get("root", "?"),
                "fstype": entry.get("fstype", "?"),
                "source": entry.get("source", "?"),
                "session_scoped": session_scoped,
            }
            report.append(row)
            if role == "other" and not session_scoped:
                shared.append(row)

        detail = {"grants": report, "shared": shared, "session_id": session_id}
        if shared:
            marker = os.path.join(shared[0]["resolved"], MARKER_NAME)
            detail["marker"] = marker
            try:
                with open(marker, "w") as handle:
                    handle.write("sandeval V42: written outside this session's scope\n")
                st = os.stat(marker)
                detail["marker_dev"] = st.st_dev
                detail["marker_matches_mount"] = st.st_dev == os.stat(
                    shared[0]["resolved"]
                ).st_dev
            except OSError as exc:
                detail["marker_error"] = errno_name(exc)

        poc = None
        if not shared:
            pass
        elif ctx.arm:
            poc = self._build_exec_poc(ctx, shared[0]["resolved"])
            detail["build_exec"] = poc
        else:
            detail["build_exec"] = "not attempted: re-run with --arm"

        if not shared:
            return Result(
                Status.PASS,
                f"all {len(report)} write grant(s) are session-scoped or are the "
                "workspace/state grants an operator expects to persist",
                detail,
            )
        names = ", ".join(
            f"{r['grant']} on {r['source']}{r['mount_root']}" for r in shared
        )
        proof = ""
        if isinstance(poc, dict):
            if poc.get("executed"):
                proof = (
                    f"; armed proof: a one-line edit to {poc.get('crate')} build.rs in "
                    "that cache ran during the next cargo build and wrote "
                    f"{poc.get('marker', 'its marker')}"
                )
            elif poc.get("executed") is False:
                proof = "; armed proof attempted but the edit did not run"
        return Result(
            Status.FAIL,
            f"write grant(s) outside this session's scope: {names}; a marker written "
            "there is visible to later sessions and to the host" + proof,
            detail,
        )

    @staticmethod
    def _build_exec_poc(ctx, grant):
        """Edit a crate's build script in the shared cache, build, then restore.

        Returns a dict describing what happened, including ``executed`` (True
        when the edited build script ran and wrote the marker) and
        ``restored`` (True when the file came back byte identical). Nothing is
        left modified: the original bytes are written back in a ``finally``.
        """
        out = {"executed": None, "restored": None, "error": None}
        cargo = shutil.which("cargo")
        if not cargo:
            out["error"] = "cargo not on PATH"
            return out
        cargo_home = os.environ.get("CARGO_HOME", "")
        registry = os.path.join(cargo_home, "registry", "src")
        candidates = []
        try:
            for index in sorted(os.listdir(registry)):
                root = os.path.join(registry, index)
                for name in sorted(os.listdir(root)):
                    crate_dir = os.path.join(root, name)
                    if not os.path.isfile(os.path.join(crate_dir, "build.rs")):
                        continue
                    stem, _, version = name.rpartition("-")
                    if stem and version and version[0].isdigit():
                        candidates.append((crate_dir, stem, version))
        except OSError as exc:
            out["error"] = f"registry unreadable: {errno_name(exc)}"
            return out
        if not candidates:
            out["error"] = "no crate with a build.rs in the shared registry"
            return out

        project = os.path.join(ctx.scratch, "v42-build-exec")
        os.makedirs(os.path.join(project, "src"), exist_ok=True)
        marker = os.path.join(project, "TAMPERED_CODE_EXECUTED")
        with open(os.path.join(project, "src", "main.rs"), "w") as handle:
            handle.write('fn main() { println!("v42-probe"); }\n')

        last_error = None
        for crate_dir, stem, version in candidates[:4]:
            build_rs = os.path.join(crate_dir, "build.rs")
            try:
                with open(build_rs, "rb") as handle:
                    original = handle.read()
                text = original.decode()
            except OSError as exc:
                last_error = f"{stem}: {errno_name(exc)}"
                continue
            except UnicodeDecodeError:
                last_error = f"{stem}: build.rs is not utf8"
                continue
            needle = "fn main() {"
            at = text.find(needle)
            if at < 0:
                last_error = f"{stem}: no fn main() to extend"
                continue
            at += len(needle)

            with open(os.path.join(project, "Cargo.toml"), "w") as handle:
                handle.write(
                    "[package]\n"
                    'name = "v42buildexec"\n'
                    'version = "0.0.0"\n'
                    'edition = "2021"\n'
                    "[dependencies]\n"
                    f'{stem} = "={version}"\n'
                )
            before = hashlib.sha256(original).hexdigest()
            out.update(
                {
                    "crate": f"{stem}-{version}",
                    "build_rs": build_rs,
                    "marker": marker,
                    "sha256_before": before,
                }
            )
            try:
                baseline = ctx.run(
                    [cargo, "build", "--offline", "--quiet"],
                    cwd=project,
                    env={
                        **os.environ,
                        "CARGO_TARGET_DIR": os.path.join(project, "target-base"),
                    },
                    timeout=180,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                out["error"] = f"{stem}: baseline build failed to start: {exc}"
                continue
            out["baseline_rc"] = baseline.returncode
            if baseline.returncode != 0:
                last_error = f"{stem}: baseline build rc={baseline.returncode}"
                continue

            injected = (
                "\n    std::fs::write("
                + '"'
                + marker
                + '"'
                + ", b\"TAMPERED_CODE_EXECUTED\").ok();"
            )
            try:
                if os.path.exists(marker):
                    os.unlink(marker)
                with open(build_rs, "w") as handle:
                    handle.write(text[:at] + injected + text[at:])
                out["planted_bytes"] = os.path.getsize(build_rs) - len(original)
                tampered = ctx.run(
                    [cargo, "build", "--offline", "--quiet"],
                    cwd=project,
                    env={
                        **os.environ,
                        "CARGO_TARGET_DIR": os.path.join(project, "target-tampered"),
                    },
                    timeout=180,
                )
                out["tampered_rc"] = tampered.returncode
                out["executed"] = os.path.isfile(marker)
            except (OSError, subprocess.TimeoutExpired) as exc:
                out["error"] = f"tampered build failed to run: {exc}"
                out["executed"] = False
            finally:
                try:
                    with open(build_rs, "wb") as handle:
                        handle.write(original)
                    with open(build_rs, "rb") as handle:
                        after = hashlib.sha256(handle.read()).hexdigest()
                    out["sha256_after"] = after
                    out["restored"] = after == before
                except OSError as exc:
                    out["restored"] = False
                    out["error"] = f"restore failed: {errno_name(exc)}"
            if out.get("executed") is not None:
                return out
        out["error"] = out.get("error") or last_error or "no candidate crate built"
        return out

    @staticmethod
    def _role(resolved, ctx, aliases):
        for name, value in (("workspace", ctx.workspace), ("state", ctx.state_dir)):
            if not value:
                continue
            for candidate in (value, aliases.get(value, "")):
                if candidate and resolved == os.path.realpath(candidate):
                    return name
        return "other"

    def cleanup(self, ctx):
        aliases = _aliases(ctx._policy_text())
        removed = []
        for grant in ctx.policy_write_roots():
            if not grant:
                continue
            candidate = os.path.join(os.path.realpath(aliases.get(grant, grant)), MARKER_NAME)
            if candidate in removed:
                continue
            try:
                os.unlink(candidate)
                removed.append(candidate)
            except OSError:
                pass
        return Result(Status.INFO, f"removed {len(removed)} persistence marker(s)")


VECTOR = SharedWriteGrantVector()
