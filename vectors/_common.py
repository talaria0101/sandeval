"""Shared helpers for vector modules (not itself a vector: `_` prefix)."""
import ctypes
import os
from datetime import datetime, timezone

try:  # loaded by the runner as a top-level module
    import base as _base
except ImportError:  # pragma: no cover - loaded as sandeval.base
    from sandeval import base as _base


def errno_name(code):
    """`EPERM`-style name for a raw errno number (0 -> `ok`)."""
    import errno as errno_mod
    if not code:
        return "ok"
    try:
        return errno_mod.errorcode[code]
    except KeyError:
        return f"errno={code}"


#: the marker left in any file this harness writes content into (V29, V30).
#: host-verify/verify.sh greps for this exact string host-side.
MARKER = "SAND_EVAL_POC"

#: readlink targets that are not real filesystem paths (V29/V30 eligibility).
ANON_PREFIXES = ("socket:", "pipe:", "anon_inode:", "memfd:")

_LIBC = None


def libc():
    """A shared `ctypes.CDLL(None)`; vectors use it for raw syscalls."""
    global _LIBC
    if _LIBC is None:
        _LIBC = ctypes.CDLL(None, use_errno=True)
    return _LIBC


def raw_syscall(num, *args):
    """`syscall(2)` through libc. Returns ``(result, errno)``."""
    lib = libc()
    lib.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    return lib.syscall(ctypes.c_long(num), *args), ctypes.get_errno()


def marker_line(name, extra=""):
    """One content-marker line, e.g. `SAND_EVAL_POC V30 2026-... target=/etc/x`."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = f"{MARKER} {name} {ts}"
    if extra:
        body += f" {extra}"
    return body + "\n"


def visible_pids(limit=64, exclude=()):
    """Other pids visible in /proc, self excluded, sorted, capped."""
    out = []
    try:
        for entry in sorted(os.listdir("/proc")):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid != os.getpid() and pid not in exclude:
                out.append(pid)
            if len(out) >= limit:
                break
    except OSError:
        pass
    return out


def fd_inventory(pid):
    """`[{fd, target, flags}]` for one pid, from /proc/<pid>/fd + fdinfo.

    `target` is the readlink text (a path for regular files, `[pipe]` or
    `socket:[..]` for the rest); `flags` is the octal `flags:` line of
    fdinfo, so a vector can know the open mode before duplicating anything.
    """
    inv = []
    try:
        names = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return inv
    for name in sorted(names):
        if not name.isdigit():
            continue
        fd = int(name)
        try:
            target = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        flags = None
        try:
            with open(f"/proc/{pid}/fdinfo/{fd}") as handle:
                for line in handle:
                    if line.startswith("flags:"):
                        flags = int(line.split()[1], 8)
                        break
        except OSError:
            pass
        inv.append({"fd": fd, "target": target, "flags": flags})
    return inv


def is_regular_path(target):
    """True when a /proc/<pid>/fd readlink names an existing regular file."""
    if target.startswith(ANON_PREFIXES) or target.startswith("["):
        return False
    try:
        return os.path.isfile(target)
    except OSError:
        return False


def writable_by_us(st):
    """Inode-permission view: would the VFS let our euid write this file?"""
    mode = st.st_mode & 0o777
    if st.st_uid == os.geteuid() and mode & 0o200:
        return True
    if mode & 0o002:
        return True
    try:
        groups = set(os.getgroups())
    except OSError:
        groups = set()
    return bool(mode & 0o020 and st.st_gid in groups)


def safe_name(path: str) -> str:
    return path.replace("/", "_").lstrip("_")


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(_base.__file__)))


def tools_dir() -> str:
    return os.path.join(repo_root(), "tools")


def marker(name: str) -> str:
    return f"SANDEVAL_POC_{name}"


def daemon_write_file_sources(pid_limit=8):
    """Regular-file paths held open for write by other visible processes.

    Target discovery for V29/V30: the daemon's own open files are where a
    duplicated or re-linked descriptor lands with real impact.
    """
    sources = []
    seen = set()
    for pid in visible_pids(limit=pid_limit, exclude={os.getpid()}):
        for entry in fd_inventory(pid):
            target = entry["target"]
            if not is_regular_path(target) or target in seen:
                continue
            flags = entry["flags"]
            if flags is None:
                continue
            if (flags & os.O_ACCMODE) in (os.O_WRONLY, os.O_RDWR):
                seen.add(target)
                sources.append({"pid": pid, "fd": entry["fd"], "path": target, "flags": flags})
    return sources
