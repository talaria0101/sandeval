"""sandeval — core types for the vector harness.

A *vector* is one scripted attempt to make a sandbox do something its policy
forbids. Each vector reports a verdict:

    PASS       the control held; the attempt was denied or had no effect
    FAIL       the control was bypassed; a policy-forbidden effect occurred
    SUSPECTED  the vector is reachable / armed but cannot be scored from
               inside the sandbox (host-side proof lives in host-verify/)
    SKIP       a precondition was missing, so the probe is not meaningful
    INFO       measurement, not a pass/fail (maps to sweep `want=info`)

Scoring rule, inherited from the sweep: SKIP is never a pass. A vector that
cannot decide because a precondition is absent must say SKIP, not PASS.

Everything here is standard library only so the harness runs against any
replica that has Python 3.8+ and bash.
"""
from __future__ import annotations

import errno as errno_mod
import os
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

__version__ = "6.0.0"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SUSPECTED = "SUSPECTED"
    SKIP = "SKIP"
    INFO = "INFO"


SEVERITY_ORDER = {
    "ship-blocker": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass
class Result:
    """The outcome of one vector run."""

    status: Status
    evidence: str = ""
    detail: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        out: Dict[str, object] = {"status": self.status.value, "evidence": self.evidence}
        if self.detail:
            out["detail"] = self.detail
        return out


class Vector:
    """Base class. Subclass, set the metadata, implement :meth:`check`."""

    id: str = "V?"
    title: str = "unnamed vector"
    severity: str = "info"
    maps_to: str = ""
    description: str = ""
    #: name of the host-side verifier that confirms this vector's effect,
    #: relative to host-verify/ (informational for the operator report)
    host_verify: str = ""

    def check(self, ctx: "Context") -> Result:  # pragma: no cover - abstract
        raise NotImplementedError


def errno_name(exc: BaseException) -> str:
    """`EACCES` for an OSError with an errno, else the class name."""
    if isinstance(exc, OSError) and exc.errno is not None:
        try:
            return errno_mod.errorcode[exc.errno]
        except KeyError:
            return f"errno={exc.errno}"
    return type(exc).__name__


@dataclass
class Context:
    """Everything a vector is allowed to touch, resolved once by the runner."""

    in_dir: str
    out_dir: str
    scratch: str
    safe: bool = False
    arm: bool = False
    verbose: bool = False
    canary: Optional[str] = None
    seed: Optional[str] = None
    host_files: List[str] = field(default_factory=list)
    workspace: str = "/workspace"
    state_dir: str = "/state"
    policy_file: Optional[str] = None
    log_fn: Callable[[str], None] = lambda _m: None

    # ---- helpers vectors share -------------------------------------------------

    def log(self, message: str) -> None:
        self.log_fn(message)

    def run(self, argv: List[str], **kwargs) -> subprocess.CompletedProcess:
        """Run a command, capturing output, never raising on non-zero."""
        if self.verbose:
            self.log("$ " + " ".join(argv))
        return subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            **kwargs,
        )

    def try_call(self, fn: Callable[..., object], *args, **kwargs) -> Tuple[bool, object, str]:
        """Call ``fn`` and report ``(ok, value, explanation)`` without raising."""
        try:
            return True, fn(*args, **kwargs), "ok"
        except OSError as exc:
            return False, None, errno_name(exc)
        except Exception as exc:  # noqa: BLE001 - a probe must never crash the run
            return False, None, type(exc).__name__

    def policy_read_roots(self) -> List[str]:
        """Paths the policy grants read on (host paths, as written)."""
        return _grants(self._policy_text(), "read")

    def policy_write_roots(self) -> List[str]:
        return _grants(self._policy_text(), "write")

    def _policy_text(self) -> str:
        if self.policy_file and os.path.exists(self.policy_file):
            try:
                with open(self.policy_file, "r", errors="replace") as handle:
                    return handle.read()
            except OSError:
                return ""
        return ""

    def policy_writable(self, path: str) -> bool:
        """Best-effort: is ``path`` inside a write-granted prefix?

        Reads the bailey policy when it is available; otherwise falls back to
        the harness's own ``in_dir``/``out_dir`` convention. The result is used
        only to decide whether a successful write is a *finding*, so a wrong
        answer degrades to SUSPECTED, never to a false PASS.
        """
        candidate = os.path.realpath(path)
        for grant in self.policy_write_roots():
            root = os.path.realpath(grant)
            if candidate == root or candidate.startswith(root.rstrip("/") + "/"):
                return True
        # no policy file: treat the harness's own scratch as the only grant
        scratch_root = os.path.realpath(self.in_dir)
        return candidate == scratch_root or candidate.startswith(scratch_root.rstrip("/") + "/")


def _grants(policy_text: str, section: str) -> List[str]:
    """Pull the quoted paths out of one policy section (read/write/execute).

    The policy is TOML-shaped but small and stable, so this tracks the current
    key rather than pulling in a parser: a ``key = [...]`` line starts
    collecting, continuation lines keep collecting, and a new ``key =`` or
    ``[section]`` switches collection off. Only strings that look like paths
    are kept, so ``{ path = ..., at = ... }`` binds yield both sides.
    """
    grants: List[str] = []
    current: Optional[str] = None
    for raw in policy_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = None
            continue
        if "=" in line:
            key = line.split("=", 1)[0].strip().lower()
            if key in ("read", "write", "execute"):
                current = key
        if current == section:
            grants.extend(_split_toml_strings(line))
    return grants


def _split_toml_strings(line: str) -> List[str]:
    """Extract quoted strings from a TOML-ish line, ignoring keys."""
    out: List[str] = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch in "\"'":
            quote = ch
            j = i + 1
            buf = []
            while j < n and line[j] != quote:
                buf.append(line[j])
                j += 1
            token = "".join(buf)
            if token.startswith("/") or token.startswith("$"):
                out.append(token)
            i = j + 1
        else:
            i += 1
    return out


def first_existing(paths: List[str]) -> Optional[str]:
    for path in paths:
        if path and os.path.exists(path):
            return path
    return None
