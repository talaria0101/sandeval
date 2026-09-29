"""V41 — the abstract unix namespace: an endpoint with no path to match.

Landlock rules are attached to paths. An abstract unix socket (`bind` on a
name beginning with NUL) lives in a kernel namespace with no path, no inode in
the policy's tree and no file to grant or deny, so a sandbox that declares
`reset = true` over the filesystem still has to say what it means about
listening and about IPC with whatever else shares the network namespace.

This vector binds an abstract name, and when the bind lands it listens and
connects to itself, so the report distinguishes "the name is reserved" from
"traffic actually flows". It then repeats the handshake with a **second
process**: the listener is a forked child, so the evidence is cross-process
IPC through a namespace that carries no path, not a socket talking to itself
in one address space. It also lists any abstract endpoints already visible
in `/proc/net/unix`, because those are the ones a host service could be
reached through without any filesystem route at all.

Nothing outside the probe is contacted; both sockets close in `cleanup()` and
the abstract name disappears with them.
"""
import os
import socket

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore


def _abstract_names():
    """Abstract names visible in /proc/net/unix, without the leading NUL."""
    names = []
    try:
        with open("/proc/net/unix") as handle:
            next(handle, None)
            for line in handle:
                parts = line.split()
                if len(parts) >= 8 and parts[7].startswith("@"):
                    names.append(parts[7][1:])
                elif len(parts) >= 8 and parts[7].startswith("\0"):
                    names.append(parts[7][1:])
    except OSError:
        return []
    return names


class AbstractSocketVector(Vector):
    id = "V41"
    title = "abstract unix socket listen/connect (path-less IPC surface)"
    severity = "high"
    maps_to = "P5 / P12"
    description = __doc__
    host_verify = "verify.sh (none): on the host, `ss -xl` shows the abstract name while held"

    def check(self, ctx):
        detail = {"visible_abstract": _abstract_names()}

        stream = self._probe(socket.SOCK_STREAM, detail, connect=True)
        dgram = self._probe(socket.SOCK_DGRAM, detail, connect=False)
        detail["stream"] = stream
        detail["dgram"] = dgram

        xproc = self._cross_process()
        detail["cross_process"] = xproc

        if stream["bind"] and stream["bind"].startswith("ok"):
            extra = ""
            if xproc.get("echo_ok"):
                extra = (
                    f"; a second process (pid {xproc.get('child_pid')}) served the "
                    f"name and echoed the parent's nonce"
                )
            return Result(
                Status.FAIL,
                "abstract unix bind succeeded and the endpoint accepts a connection: "
                "a path-less listen surface the policy's filesystem rules cannot name"
                + extra,
                detail,
            )
        if stream["bind"] == "unsupported":
            return Result(Status.SKIP, "AF_UNIX sockets unavailable in this sandbox", detail)
        return Result(
            Status.PASS,
            f"abstract unix bind refused ({stream['bind']}); the path-less IPC surface is closed",
            detail,
        )

    @staticmethod
    def _probe(kind, detail, connect=True):
        """Bind one abstract name; optionally complete a stream handshake.

        A datagram ``connect`` would succeed against a name nobody serves, so
        only the stream route is used as evidence that traffic can flow.
        """
        out = {"bind": "unsupported", "connect": "not attempted"}
        try:
            listener = socket.socket(socket.AF_UNIX, kind)
        except OSError as exc:
            out["bind"] = errno_name(exc)
            return out
        name = f"\0sandeval-v41-{os.getpid()}-{kind}"
        try:
            listener.bind(name)
        except OSError as exc:
            out["bind"] = errno_name(exc)
            listener.close()
            return out
        out["bind"] = "ok"
        try:
            if not connect:
                out["connect"] = "not attempted (datagram connect is not traffic proof)"
                return out
            listener.listen(1)
            peer = socket.socket(socket.AF_UNIX, kind)
            try:
                peer.settimeout(1.0)
                peer.connect(name)
                out["connect"] = "ok"
            except OSError as exc:
                out["connect"] = errno_name(exc)
            finally:
                peer.close()
        finally:
            listener.close()
        return out

    @staticmethod
    def _cross_process():
        """Serve an abstract name from a child process and echo a nonce back.

        Returns ``{connected, echo_ok, child_pid, error}``. The child exits on
        its own once the handshake is done, so no listener is left behind.
        """
        out = {
            "connected": False,
            "echo_ok": False,
            "child_pid": None,
            "error": None,
        }
        nonce = os.urandom(8)
        name = f"\0sandeval-v41-xproc-{os.getpid()}"
        pid = os.fork()
        if pid == 0:
            code = 1
            listener = None
            try:
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(name)
                listener.listen(1)
                listener.settimeout(3.0)
                conn, _ = listener.accept()
                with conn:
                    got = conn.recv(64)
                    conn.sendall(got)
                code = 0 if got == nonce else 2
            except Exception:  # noqa: BLE001 - the child reports through its exit code
                code = 3
            finally:
                if listener is not None:
                    listener.close()
            os._exit(code)

        out["child_pid"] = pid
        peer = None
        try:
            peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            peer.settimeout(3.0)
            import time as _time

            deadline = 3.0
            while True:
                try:
                    peer.connect(name)
                    break
                except OSError:
                    deadline -= 0.05
                    if deadline <= 0:
                        raise
                    _time.sleep(0.05)
            out["connected"] = True
            peer.sendall(nonce)
            out["echo_ok"] = peer.recv(64) == nonce
        except OSError as exc:
            out["error"] = errno_name(exc)
        finally:
            if peer is not None:
                peer.close()
        try:
            _, status = os.waitpid(pid, 0)
            out["child_rc"] = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            pass
        return out

    def cleanup(self, ctx):
        return Result(Status.INFO, "abstract sockets closed: the names vanish with them")


VECTOR = AbstractSocketVector()
