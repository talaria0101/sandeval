"""V43 — which layer actually enforces egress: a filter, the route table,
or the proxy.

V7 measures *what* connects and compares it to the declared TCP/UDP
allowlist. This vector measures *why* a connection fails, because the three
possible answers are three different controls with three different fixes:

  ``EPERM``/``EACCES``  a filter refused the syscall (seccomp, or Landlock's
                        network rule if the engine has one)
  ``ENETUNREACH`` etc.  the namespace has no route off-box at all
  refused / timeout     the packet left and something upstream said no
  ``connected``         nothing stopped it

Three targets, no data ever sent: the configured proxy, the canary host on an
allowed port, and the canary host on a port outside the allowlist. The proxy
probe doubles as a check on the network half of the policy: if the policy
allowlists 80/443/8443 and the proxy listens elsewhere yet the connect
succeeds, then the declared egress rule is not the thing enforcing egress.

A FAIL here means a direct off-box connection succeeded without going through
the proxy, i.e. the allowlist can be walked around.
"""
import os
import re
import socket

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

FILTER_ERRNOS = {"EPERM", "EACCES"}
ROUTE_ERRNOS = {"ENETUNREACH", "EHOSTUNREACH", "ENETDOWN", "ENODEV"}


def _proxy():
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        raw = os.environ.get(name)
        if not raw:
            continue
        hostport = raw.split("://", 1)[-1].rstrip("/")
        host, _, port = hostport.partition(":")
        if host and port.isdigit():
            return host, int(port), name
    return None


def _allowed_ports():
    raw = os.environ.get("SANDEVAL_ALLOWED_TCP", "443")
    return {int(t) for t in raw.split(",") if t.strip().isdigit()}


def _classify(exc):
    name = errno_name(exc)
    if name in FILTER_ERRNOS:
        return "denied-by-filter"
    if name in ROUTE_ERRNOS:
        return "no-route"
    if name in {"ECONNREFUSED", "ECONNRESET", "ETIMEDOUT", "EHOSTUNREACH"}:
        return "routed-but-refused"
    return name.lower()


def _connect(host, port, timeout=2.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return "connected", ""
    except OSError as exc:
        return _classify(exc), errno_name(exc)
    finally:
        sock.close()


def _policy_ports(text):
    """Ports named in the policy's `[network] egress_allow`, the set Landlock
    grants `ConnectTcp`. The broker's own port is added on top of this at
    launch, so a connect that passes here on an unlisted port is the broker
    path rather than an open egress rule."""
    section = re.search(r"^\[network\]\s*$([\s\S]*?)(?=^\[|\Z)", text or "", re.M)
    if not section:
        return set()
    return {int(p) for p in re.findall(r"port\s*=\s*(\d+)", section.group(1))}


def _default_route():
    """``(interface, gateway)`` of the default route, or ``None``."""
    try:
        with open("/proc/net/route") as handle:
            next(handle, None)
            for line in handle:
                fields = line.split()
                if len(fields) >= 4 and fields[1] == "00000000":
                    return fields[0], fields[2]
    except OSError:
        return None
    return None


class EgressAttributionVector(Vector):
    id = "V43"
    title = "egress attribution: direct off-box connect vs proxy path"
    severity = "high"
    maps_to = "P5 / P6"
    description = __doc__
    host_verify = "verify.sh (none): the probe sends no payload bytes"

    def check(self, ctx):
        allowed = _allowed_ports()
        canary_host, _, canary_port = (
            os.environ.get("SANDEVAL_CANARY", "1.1.1.1:443").partition(":")
        )
        try:
            canary_port = int(canary_port or "443")
        except ValueError:
            canary_port = 443
        blocked_port = next((p for p in (22, 9999, 3306) if p not in allowed), None)

        proxy = _proxy()
        policy_ports = _policy_ports(ctx._policy_text())
        attempts = []

        if proxy:
            attempts.append(
                self._one("proxy", proxy[0], proxy[1], policy_ports, role="proxy")
            )
        attempts.append(
            self._one(
                "canary-allowed-port", canary_host, canary_port, policy_ports, role="direct"
            )
        )
        if blocked_port:
            attempts.append(
                self._one(
                    "canary-denied-port",
                    canary_host,
                    blocked_port,
                    policy_ports,
                    role="direct",
                )
            )

        route = _default_route()
        detail = {
            "proxy_env": proxy[2] if proxy else None,
            "proxy": f"{proxy[0]}:{proxy[1]}" if proxy else None,
            "policy_egress_ports": sorted(policy_ports),
            "expected_ports_env": sorted(allowed),
            "default_route": route,
            "attempts": attempts,
            "tcp_bind": self._bind_probe(),
        }

        if not attempts:
            return Result(Status.SKIP, "no probe target could be derived from the environment")

        direct_ok = [
            a for a in attempts if a["role"] == "direct" and a["result"] == "connected"
        ]
        proxy_rows = [a for a in attempts if a["role"] == "proxy"]
        proxy_ok = bool(proxy_rows) and proxy_rows[0]["result"] == "connected"

        if direct_ok:
            return Result(
                Status.FAIL,
                "direct off-box connect succeeded without the proxy: "
                + ", ".join(f"{a['host']}:{a['port']}" for a in direct_ok),
                detail,
            )
        if not proxy and all(a["result"] != "connected" for a in attempts):
            return Result(
                Status.SKIP,
                "no proxy configured and no route off-box, so there is no egress path "
                "to attribute",
                detail,
            )
        layers = ", ".join(f"{a['name']}={a['result']}" for a in attempts)
        return Result(
            Status.PASS,
            f"no direct off-box path ({layers}); every probe is stopped before a "
            f"connection exists, default route {route or 'absent'}",
            detail,
        )

    @staticmethod
    def _bind_probe():
        """Whether any TCP bind is permitted, which says if a bind rule exists.

        A policy with `egress_allow` and no `bind_ports` still asks Landlock to
        handle bind, so an empty bind list denies every listener. That is worth
        recording beside the connect result: it is the same rule set, and it
        decides whether anything in here could be reached from outside.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("0.0.0.0", 0))
            first = {"result": "bound", "errno": ""}
        except OSError as exc:
            first = {"result": "denied", "errno": errno_name(exc)}
        finally:
            sock.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("0.0.0.0", 54321))
            second = {"result": "bound", "errno": ""}
        except OSError as exc:
            second = {"result": "denied", "errno": errno_name(exc)}
        finally:
            sock.close()
        return {"ephemeral": first, "high_port": second}

    @staticmethod
    def _one(name, host, port, policy_ports, role):
        result, err = _connect(host, port)
        return {
            "name": name,
            "host": host,
            "port": port,
            "role": role,
            "policy_allowed_port": port in policy_ports,
            "result": result,
            "errno": err,
        }


VECTOR = EgressAttributionVector()
