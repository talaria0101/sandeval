"""V27 — socket families a TCP-port allowlist never mentions.

Port-based egress policy says nothing about socket classes that have no port:
AF_INET/SOCK_RAW carries ICMP (kernel fills the checksum, so raw ICMP egress
is a ready-made unported channel), AF_PACKET puts the interface into
promiscuous L2 reach, and AF_NETLINK with NETLINK_KOBJECT_UEVENT can bind
into the kernel's device-event multicast group: a live feed of host hardware
events, and with CAP_NET_ADMIN the classic spoofing surface. This vector
creates each family, acts only where the action is reversible (one ICMP echo,
a passive bind), and reports every class that answers.
"""
import os
import socket
import struct

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

IPPROTO_ICMP = 1
AF_PACKET = 17
AF_NETLINK = 16
NETLINK_KOBJECT_UEVENT = 15
NETLINK_ROUTE = 0


class SocketFamiliesVector(Vector):
    id = "V27"
    title = "exotic socket families (raw/packet/netlink) beyond the port policy"
    severity = "high"
    maps_to = "P5 / P6 / V7"
    description = __doc__
    host_verify = ""

    @staticmethod
    def _try(family, stype, proto):
        try:
            s = socket.socket(family, stype, proto)
            return s, None
        except OSError as exc:
            return None, errno_name(exc)

    def check(self, ctx):
        host = (ctx.canary or "1.1.1.1:443").rsplit(":", 1)[0]
        findings, detail = [], {"capabilities_note": "CapEff from /proc/self/status"}

        # ICMP raw egress: an unported channel by construction
        s, err = self._try(socket.AF_INET, socket.SOCK_RAW, IPPROTO_ICMP)
        if s is None:
            detail["icmp_raw"] = f"denied ({err})"
        else:
            try:
                pkt = struct.pack("!BBHHH", 8, 0, 0, os.getpid() & 0xFFFF, 1) + b"sandeval"
                s.sendto(pkt, (host, 0))
                findings.append(f"raw ICMP egress to {host} succeeded (no port policy applies)")
                detail["icmp_raw"] = "sent"
            except OSError as exc:
                detail["icmp_raw"] = f"socket ok, sendto denied ({errno_name(exc)})"
            finally:
                s.close()

        # AF_PACKET: L2 sniff/inject reach
        s, err = self._try(AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # ETH_P_ALL
        if s is None:
            detail["af_packet"] = f"denied ({err})"
        else:
            s.close()
            findings.append("AF_PACKET raw socket created: L2 sniffing/injection reach")
            detail["af_packet"] = "created"

        # netlink uevent: bind into the kernel device-event multicast group
        s, err = self._try(AF_NETLINK, socket.SOCK_RAW, NETLINK_KOBJECT_UEVENT)
        if s is None:
            detail["netlink_uevent"] = f"denied ({err})"
        else:
            try:
                s.bind((0, 1))  # pid auto, group 1 = kernel uevents
                findings.append(
                    "bound AF_NETLINK/KOBJECT_UEVENT into the kernel uevent group: "
                    "host device-event feed reachable (and spoofable with CAP_NET_ADMIN)"
                )
                detail["netlink_uevent"] = "bound to group 1"
            except OSError as exc:
                detail["netlink_uevent"] = f"socket ok, bind denied ({errno_name(exc)})"
            finally:
                s.close()

        # netlink route: recon-grade, recorded but not a finding
        s, err = self._try(AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        detail["netlink_route"] = "created" if s is not None else f"denied ({err})"
        if s is not None:
            s.close()

        try:
            with open("/proc/self/status") as fh:
                for line in fh:
                    if line.startswith("CapEff:"):
                        detail["capabilities_note"] = line.strip()
                        break
        except OSError:
            pass

        if findings:
            return Result(
                Status.SUSPECTED if len(findings) == 1 and "uevent" in findings[0] else Status.FAIL,
                "; ".join(findings),
                detail,
            )
        return Result(
            Status.PASS,
            "every exotic socket class was denied: no unported egress or L2/netlink reach",
            detail,
        )


VECTOR = SocketFamiliesVector()
