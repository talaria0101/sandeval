"""V41 — the abstract unix namespace: an endpoint with no path to match.

Landlock rules are attached to paths. An abstract unix socket (`bind` on a
name beginning with NUL) lives in a kernel namespace with no path, no inode in
the policy's tree and no file to grant or deny, so a sandbox that declares
`reset = true` over the filesystem still has to say what it means about
listening and about IPC with whatever else shares the network namespace.

This vector binds an abstract name, and when the bind lands it listens and
connects to itself, so the report distinguishes "the name is reserved" from
"traffic actually flows". It also lists any abstract endpoints already
visible in `/proc/net/unix`, because those are the ones a host service could
be reached through without any filesystem route at all.

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

        if stream["bind"] and stream["bind"].startswith("ok"):
            return Result(
                Status.FAIL,
                "abstract unix bind succeeded and the endpoint accepts a connection: "
                "a path-less listen surface the policy's filesystem rules cannot name",
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

    def cleanup(self, ctx):
        return Result(Status.INFO, "abstract sockets closed: the names vanish with them")


VECTOR = AbstractSocketVector()
