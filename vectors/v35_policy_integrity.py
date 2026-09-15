"""V35 — the sandbox's own control files are writable from inside it.

The policy that draws the sandbox boundary (`policy.toml` in the agent state
dir) is a file inside the state dir, and the state dir is write-granted so
the agent can do its job. Nothing enforces a distinction between "agent
workspace files" and "the file that says what the next session may do": if
`open(policy, O_WRONLY)` succeeds, the next instance's read/write lists, egress
rules and limits are chosen by whatever wrote that file last. This vector
proves write-open WITHOUT writing (open + close, no truncate, no bytes), and
leaves a `user.sandeval.V35` xattr marker on the policy file so the host
verifier can confirm the metadata-write half. It then inventories the other
control files at the top of the state dir the same way (names only). A
rewrite is never attempted: a corrupted policy could break the next session,
which is not this harness's call to make.
"""
import os

try:
    from sandeval.base import Result, Status, Vector, errno_name
except ImportError:
    from base import Result, Status, Vector, errno_name  # type: ignore

try:
    from _common import MARKER
except ImportError:
    from _common import MARKER  # type: ignore

XATTR = "user.sandeval.V35"


class PolicyIntegrityVector(Vector):
    id = "V35"
    title = "policy.toml / state control files writable by the sandbox"
    severity = "ship-blocker"
    maps_to = "P2 / P16 / V18"
    description = __doc__
    host_verify = "verify.sh (xattr user.sandeval.V35 on the policy file)"

    def check(self, ctx):
        if not ctx.policy_file or not os.path.isfile(ctx.policy_file):
            return Result(
                Status.SKIP,
                "no policy file discovered; pass --policy or SANDEVAL_POLICY to make this check meaningful",
            )
        policy = ctx.policy_file
        detail = {"policy_file": policy, "state_dir": ctx.state_dir}

        open_ok, open_err = self._write_open(policy)
        detail["policy_write_open"] = open_ok if open_ok else open_err
        xattr_ok, xattr_err = self._set_marker(policy)
        detail["policy_xattr_marker"] = xattr_ok if xattr_ok else xattr_err

        others = self._state_inventory(ctx)
        detail["writable_state_files"] = others

        if open_ok:
            others_note = f"; {len(others)} more writable control file(s)" if others else ""
            return Result(
                Status.FAIL,
                f"the sandbox's own policy file is write-openable from inside: {policy} "
                f"(open O_WRONLY proved without writing, xattr marker: {xattr_ok}{others_note}) - "
                "the next session's boundary is attacker-chosen",
                detail,
            )
        if xattr_ok:
            return Result(
                Status.FAIL,
                f"policy content write-open denied ({open_err}) but metadata writes land: "
                "the xattr marker proves host-side inode writes on the control file",
                detail,
            )
        if others:
            return Result(
                Status.SUSPECTED,
                f"policy file solid, but {len(others)} state-dir control file(s) are write-openable: "
                f"{', '.join(others[:5])}",
                detail,
            )
        return Result(
            Status.PASS,
            f"policy file refuses write-open ({open_err}); state-dir controls are not writable",
            detail,
        )

    def cleanup(self, ctx):
        removed = 0
        if ctx.policy_file and os.path.exists(ctx.policy_file):
            try:
                os.removexattr(ctx.policy_file, XATTR)
                removed += 1
            except OSError:
                pass
        return Result(Status.INFO, f"removed {removed} xattr marker(s)" if removed else "nothing to undo")

    @staticmethod
    def _write_open(path):
        """open O_WRONLY + close. Never writes, never truncates."""
        try:
            fd = os.open(path, os.O_WRONLY)
            os.close(fd)
            return True, "ok"
        except OSError as exc:
            return False, errno_name(exc)

    @staticmethod
    def _set_marker(path):
        try:
            os.setxattr(path, XATTR, f"{MARKER} V35 policy-write-open".encode())
            return True, "ok"
        except OSError as exc:
            return False, errno_name(exc)

    def _state_inventory(self, ctx):
        """Top-level regular files of the state dir that open O_WRONLY."""
        writable = []
        state = ctx.state_dir
        if not state or not os.path.isdir(state):
            return writable
        try:
            entries = sorted(os.listdir(state))
        except OSError:
            return writable
        for name in entries:
            path = os.path.join(state, name)
            if name.startswith("sandeval") or not os.path.isfile(path):
                continue
            ok, _ = self._write_open(path)
            if ok:
                writable.append(name)
        return writable


VECTOR = PolicyIntegrityVector()
