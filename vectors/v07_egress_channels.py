"""V7 — egress is filtered by TCP port only; UDP and other ports are open.

A TCP-port allowlist (443) is not an egress control. UDP has no equivalent
filter, so DNS-style exfiltration over UDP to any host and port works, and any
TCP port that happens to be in the allowlist reaches any host. The vector
compares what actually connects against the declared allowlist
(`SANDEVAL_ALLOWED_TCP`, `SANDEVAL_ALLOWED_UDP`).
"""
import os
import socket

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore


def _allowed(name, default):
    raw = os.environ.get(name, default)
    out = set()
    for token in raw.split(","):
        token = token.strip()
        if token.isdigit():
            out.add(int(token))
    return out


def _tcp(host, port, timeout=2.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True, "connected"
    except OSError as exc:
        return False, errno_name(exc)
    finally:
        sock.close()


def _udp(host, port, timeout=2.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"sandeval", (host, port))
        return True, "sendto"
    except OSError as exc:
        return False, errno_name(exc)
    finally:
        sock.close()


class EgressChannelsVector(Vector):
    id = "V7"
    title = "egress reachable beyond the declared TCP allowlist (esp. UDP)"
    severity = "high"
    maps_to = "P5 / P6 / sweep §11"
    description = __doc__
    host_verify = ""

    def check(self, ctx):
        host, _port = (ctx.canary or "1.1.1.1:443").split(":", 1)
        allowed_tcp = _allowed("SANDEVAL_ALLOWED_TCP", "443")
        allowed_udp = _allowed("SANDEVAL_ALLOWED_UDP", "")
        tcp_ports = sorted(allowed_tcp | {80, 443, 8443})
        udp_ports = sorted(allowed_udp | {53, 123})
        findings = []
        observed = {"tcp": {}, "udp": {}}
        for port in tcp_ports:
            ok, why = _tcp(host, port)
            observed["tcp"][port] = why if not ok else "open"
            if ok and port not in allowed_tcp:
                findings.append(f"tcp/{port} open but not allowed")
        for port in udp_ports:
            ok, why = _udp(host, port)
            observed["udp"][port] = why if not ok else "sendto"
            if ok and port not in allowed_udp:
                findings.append(f"udp/{port} reachable but not allowed")
        if findings:
            return Result(Status.FAIL, "; ".join(findings), {"observed": observed, "host": host})
        return Result(Status.PASS, f"egress matches allowlist on {host}", {"observed": observed})


VECTOR = EgressChannelsVector()
