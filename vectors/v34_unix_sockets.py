"""V34 — unix-socket IPC reach: the control plane Landlock does not see.

Landlock (ABI 1-3) has no access right for AF_UNIX connects; ABI 4 added TCP
bind/connect but left unix domains alone. A same-uid unix socket is therefore
connectable from inside the sandbox whatever the path policy says, and the
interesting ones are the control planes: docker/containerd sockets are a
container escape, ssh/gpg-agent sockets are a signing oracle for the host's
keys. This vector enumerates socket paths from /proc/net/unix and from
socket-shaped environment entries (SSH_AUTH_SOCK, GPG_AGENT_INFO,
DOCKER_HOST) of the daemon, connects each once and closes immediately
(no bytes are sent), and checks whether the socket's parent directory is
writable, which would let a later run replace the socket and interpose on
the IPC.
"""
import os
import re
import socket
import stat as stat_mod

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

ENV_SOCKET_VARS = ("SSH_AUTH_SOCK", "GPG_AGENT_INFO", "DOCKER_HOST")
CRITICAL = re.compile(r"(docker|containerd|podman|buildkit|lxd|lxc)", re.I)
SIGNING = re.compile(r"(ssh-agent|gpg-agent|agent\.sock|keyring|pkcs11)", re.I)


def env_entries(pid=None):
    """Socket paths from socket-shaped env vars (own env + the daemon's)."""
    paths = []
    envs = [os.environ]
    if pid and os.path.exists(f"/proc/{pid}/environ"):
        try:
            with open(f"/proc/{pid}/environ", "rb") as handle:
                data = handle.read()
            envs.append(dict(line.split(b"=", 1) for line in data.split(b"\0") if b"=" in line))
        except (OSError, ValueError):
            pass
    for env in envs:
        for name in ENV_SOCKET_VARS:
            value = env.get(name)
            if not value:
                continue
            if isinstance(value, bytes):
                value = value.decode("utf-8", "replace")
            value = value.replace("unix://", "")
            if value.startswith("/"):
                paths.append((value, name))
    return paths


def proc_net_unix_paths():
    paths = []
    try:
        with open("/proc/net/unix") as handle:
            lines = handle.readlines()[1:]
    except OSError:
        return paths
    for line in lines:
        cols = line.split()
        if len(cols) >= 8 and cols[-1].startswith("/"):
            paths.append((cols[-1], "/proc/net/unix"))
    return paths


class UnixSocketReachVector(Vector):
    id = "V34"
    title = "unix-socket IPC reach (docker/agent sockets, hijack surface)"
    severity = "ship-blocker"
    maps_to = "P5 / P12 / P8"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        candidates = {}
        for path, origin in env_entries(1) + env_entries() + proc_net_unix_paths():
            candidates.setdefault(path, origin)
        if not candidates:
            return Result(Status.SKIP, "no unix socket path visible")

        reachable, denied, hijackable, gone = [], {}, [], 0
        for path, origin in sorted(candidates.items()):
            if not os.path.exists(path):
                gone += 1
                continue
            try:
                st = os.stat(path)
            except OSError as exc:
                denied[path] = f"stat: {errno_name(exc)}"
                continue
            if not stat_mod.S_ISSOCK(st.st_mode):
                continue
            entry = {"path": path, "origin": origin, "uid": st.st_uid}
            ok, err = self._connect_once(path)
            if ok:
                parent = os.path.dirname(path)
                entry["hijack"] = self._dir_writable(parent)
                reachable.append(entry)
                if entry["hijack"]:
                    hijackable.append(path)
            else:
                denied[path] = f"connect: {err}"

        detail = {
            "candidates": len(candidates),
            "reachable": reachable,
            "denied": denied,
            "hijackable": hijackable,
            "gone": gone,
            "note": "single connect + close per socket, no bytes sent",
        }
        if not reachable:
            return Result(
                Status.PASS,
                f"every visible unix socket refused connect ({list(denied)[:2]})",
                detail,
            )
        critical = [r for r in reachable if CRITICAL.search(r["path"])]
        if critical:
            return Result(
                Status.FAIL,
                "container-runtime socket reachable from inside the sandbox: "
                + ", ".join(r["path"] for r in critical[:3])
                + " - this is a host/container escape primitive",
                detail,
            )
        signing = [r for r in reachable if SIGNING.search(r["path"])]
        shown = ", ".join(r["path"] for r in (signing or reachable)[:4])
        hij = f"; {len(hijackable)} hijackable (parent dir writable)" if hijackable else ""
        if signing:
            return Result(
                Status.FAIL,
                f"credential-agent socket(s) connectable: {shown}{hij}",
                detail,
            )
        return Result(
            Status.SUSPECTED,
            f"{len(reachable)} non-agent unix socket(s) connectable (IPC reach): {shown}{hij}",
            detail,
        )

    @staticmethod
    def _connect_once(path):
        conn = None
        try:
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.settimeout(2)
            conn.connect(path)
            return True, "ok"
        except OSError as exc:
            return False, errno_name(exc)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

    @staticmethod
    def _dir_writable(directory):
        """Create+unlink a probe file; the honest writability test."""
        probe = os.path.join(directory, f".sandeval-v34-{os.getpid()}")
        try:
            with open(probe, "w") as handle:
                handle.write("x")
            os.unlink(probe)
            return True
        except OSError:
            return False


VECTOR = UnixSocketReachVector()
