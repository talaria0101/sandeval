"""sandeval runner — discovery, execution and reporting.

Usage is documented in README.md; run `sandeval list` for the vector table.
The runner deliberately keeps every probe small and reversible, and refuses to
run outside a replica unless told twice.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob
import importlib.util
import json
import os
import shutil
import sys
import tempfile
from typing import Dict, Iterable, List, Optional

try:
    from .base import (
        Context,
        Result,
        SEVERITY_ORDER,
        Status,
        Vector,
        __version__,
        errno_name,
    )
except ImportError:  # invoked as a plain script
    from base import (  # type: ignore
        Context,
        Result,
        SEVERITY_ORDER,
        Status,
        Vector,
        __version__,
        errno_name,
    )

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_VECTORS = os.path.join(ROOT, "vectors")
DEFAULT_SWEEP = os.path.join(ROOT, "sweep", "landlock-surface-sweep.sh")
DEFAULT_PROMPTS = os.path.join(ROOT, "prompts", "redteam-eval-harness.md")
DEFAULT_HOST_VERIFY = os.path.join(ROOT, "host-verify", "verify.sh")

OUT_CANDIDATES = ["/opt", "/var/tmp", "/mnt", "/srv", "/run", "/media", "/tmp"]


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #

def discover_vectors(directory: str) -> List[Vector]:
    """Load every ``v*.py`` in ``directory`` exposing a ``VECTOR``."""
    # Make the shared helper (`_common`) and the core types (`base`) importable
    # from a vector module regardless of how the runner itself was invoked.
    for extra in (directory, os.path.dirname(os.path.abspath(__file__))):
        if extra not in sys.path:
            sys.path.insert(0, extra)
    found: List[Vector] = []
    for path in sorted(glob.glob(os.path.join(directory, "v*.py"))):
        name = os.path.splitext(os.path.basename(path))[0]
        spec = importlib.util.spec_from_file_location(f"sandeval_vector_{name}", path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001 - one bad vector must not kill the run
            print(f"warning: could not load {path}: {exc}", file=sys.stderr)
            continue
        vector = getattr(module, "VECTOR", None)
        if isinstance(vector, Vector):
            found.append(vector)
    found.sort(key=lambda v: (SEVERITY_ORDER.get(v.severity, 99), v.id))
    return found


# --------------------------------------------------------------------------- #
# environment discovery
# --------------------------------------------------------------------------- #

def _dir_writable(directory: str) -> bool:
    probe = os.path.join(directory, f".sandeval-wprobe-{os.getpid()}")
    try:
        fd = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        os.unlink(probe)
        return True
    except OSError:
        return False


def discover_out_dir(explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    for candidate in OUT_CANDIDATES:
        if os.path.isdir(candidate) and not _dir_writable(candidate):
            return candidate
    for candidate in OUT_CANDIDATES:
        if os.path.isdir(candidate):
            return candidate
    return "/tmp"


def discover_host_files(extra: Iterable[str], ctx: Context) -> List[str]:
    """Readable files that live outside the write policy.

    These are the metadata-write targets. Discovery starts from the policy's
    own read list rather than from ``/home/*``: listing a parent directory can
    itself be denied even though a specific child below it is granted, which is
    exactly the case for ``/home/<user>/Local/bin``. Directories that are part
    of the base system, and anything the policy lets us write, are skipped.
    """
    candidates: List[str] = list(extra)
    env = os.environ.get("SANDEVAL_HOST_FILES", "")
    candidates += [p for p in env.split(":") if p]
    candidates += ["/etc/resolv.conf", "/etc/hostname", "/etc/hosts", "/etc/group"]

    skip_roots = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc", "/sys", "/dev")
    roots = ctx.policy_read_roots()
    for root in roots:
        if not os.path.exists(root):
            continue
        if os.path.isfile(root) and not os.path.islink(root):
            candidates.append(root)
            continue
        if not os.path.isdir(root):
            continue
        if any(root == s or root.startswith(s + "/") for s in skip_roots):
            continue
        if ctx.policy_writable(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for fname in files:
                full = os.path.join(dirpath, fname)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                if ctx.policy_writable(full):
                    continue
                candidates.append(full)
            if len(candidates) > 400:
                break

    uid = os.getuid()
    seen = set()
    owned: List[str] = []
    others: List[str] = []
    for path in candidates:
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        if not os.path.isfile(real) or os.path.islink(path):
            continue
        try:
            if os.stat(real).st_uid == uid:
                owned.append(real)
            else:
                others.append(real)
        except OSError:
            continue
    return (owned + others)[:40]


def build_context(args: argparse.Namespace) -> Context:
    in_dir = os.path.abspath(args.in_dir or os.environ.get("SANDEVAL_IN") or os.getcwd())
    if not os.path.isdir(in_dir):
        raise SystemExit(f"--in {in_dir!r} is not a directory")
    out_dir = os.path.abspath(discover_out_dir(args.out_dir))
    state_dir = args.state_dir or os.environ.get("SANDEVAL_STATE") or "/state"
    policy_file = args.policy or os.environ.get("SANDEVAL_POLICY")
    if not policy_file:
        candidate = os.path.join(state_dir, "policy.toml")
        policy_file = candidate if os.path.exists(candidate) else None
    scratch = tempfile.mkdtemp(prefix=".sandeval-", dir=in_dir)
    ctx = Context(
        in_dir=in_dir,
        out_dir=out_dir,
        scratch=scratch,
        safe=args.safe,
        arm=args.arm,
        verbose=args.verbose,
        canary=args.canary,
        seed=args.seed,
        host_files=[],
        workspace=args.workspace,
        state_dir=state_dir,
        policy_file=policy_file,
        log_fn=(lambda m: print("    " + m)) if args.verbose else (lambda _m: None),
    )
    ctx.host_files = discover_host_files(args.host_file or [], ctx)
    return ctx


# --------------------------------------------------------------------------- #
# execution
# --------------------------------------------------------------------------- #

def select_vectors(vectors: List[Vector], args: argparse.Namespace) -> List[Vector]:
    chosen = vectors
    if args.vector:
        wanted = {v.strip() for v in args.vector.split(",") if v.strip()}
        chosen = [v for v in chosen if v.id in wanted]
    if args.min_severity:
        limit = SEVERITY_ORDER.get(args.min_severity, 99)
        chosen = [v for v in chosen if SEVERITY_ORDER.get(v.severity, 99) <= limit]
    if args.skip_safe:
        chosen = [v for v in chosen if not getattr(v, "host_global", False)]
    return chosen


def run_vectors(ctx: Context, vectors: List[Vector], cleanup: bool = False) -> List[dict]:
    records: List[dict] = []
    for vector in vectors:
        if vector.severity == "info" and not ctx.safe and getattr(vector, "host_global", False):
            result = Result(Status.SKIP, "host-global probe; re-run without --safe")
        else:
            print(f"[{vector.id:>3}] {vector.title} ...", flush=True)
            try:
                if cleanup:
                    if hasattr(vector, "cleanup"):
                        result = vector.cleanup(ctx)  # type: ignore[attr-defined]
                    else:
                        result = Result(Status.INFO, "nothing to clean")
                else:
                    result = vector.check(ctx)
            except Exception as exc:  # noqa: BLE001 - never let a vector abort the suite
                result = Result(Status.SKIP, f"vector raised {type(exc).__name__}: {exc}")
        record = {
            "id": vector.id,
            "title": vector.title,
            "severity": vector.severity,
            "maps_to": vector.maps_to,
            "host_verify": vector.host_verify,
            "result": result.to_dict(),
        }
        records.append(record)
        icon = {"PASS": "ok", "FAIL": "!!", "SUSPECTED": "??", "SKIP": "--", "INFO": "ii"}[
            result.status.value
        ]
        print(f"      [{icon}] {result.status.value}: {result.evidence}")
    return records


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #

def summarize(records: List[dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for rec in records:
        status = rec["result"]["status"]
        counts[status] = counts.get(status, 0) + 1
    return counts


def render_markdown(records: List[dict], ctx: Context, summary: Dict[str, int]) -> str:
    lines = [
        "# sandeval report",
        "",
        f"- generated: {_dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')}",
        f"- harness: sandeval {__version__}",
        f"- in-policy dir: `{ctx.in_dir}`",
        f"- out-of-policy dir: `{ctx.out_dir}`",
        f"- policy: `{ctx.policy_file or 'not found'}`",
        f"- canary: `{ctx.canary or 'unset'}`",
        f"- seed: `{ctx.seed or 'unset'}`",
        "",
        "## Summary",
        "",
        "| status | count |",
        "|---|---|",
    ]
    for status in ("FAIL", "SUSPECTED", "PASS", "SKIP", "INFO"):
        if status in summary:
            lines.append(f"| {status} | {summary[status]} |")
    lines += ["", "## Vectors", "", "| id | severity | status | maps to | finding |", "|---|---|---|---|---|"]
    for rec in records:
        result = rec["result"]
        finding = (result.get("evidence") or "").replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {rec['id']} | {rec['severity']} | {result['status']} | "
            f"{rec['maps_to']} | {finding} |"
        )
    failed = [r for r in records if r["result"]["status"] == "FAIL"]
    if failed:
        lines += ["", "## Host-side verification required", ""]
        for rec in failed:
            hv = rec.get("host_verify") or "host-verify/verify.sh"
            lines.append(f"- **{rec['id']}** — {rec['title']}: `{hv}`")
    lines.append("")
    return "\n".join(lines)


def write_reports(records: List[dict], ctx: Context, args: argparse.Namespace) -> None:
    summary = summarize(records)
    payload = {
        "version": __version__,
        "generated": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "context": {
            "in_dir": ctx.in_dir,
            "out_dir": ctx.out_dir,
            "policy_file": ctx.policy_file,
            "seed": ctx.seed,
            "canary": ctx.canary,
            "safe": ctx.safe,
            "arm": ctx.arm,
            "host_files": ctx.host_files,
        },
        "summary": summary,
        "results": records,
    }
    if args.json:
        with open(args.json, "w") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"json report: {args.json}")
    if args.report:
        with open(args.report, "w") as handle:
            handle.write(render_markdown(records, ctx, summary))
        print(f"markdown report: {args.report}")
    print()
    print("summary: " + "  ".join(f"{k}={v}" for k, v in sorted(summary.items())))
    if summary.get("FAIL"):
        print("=> FAIL present: confirm host-side with host-verify/verify.sh before trusting any claim")
    return None


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def cmd_list(args: argparse.Namespace) -> int:
    vectors = discover_vectors(args.vectors_dir)
    print(f"{'id':>4}  {'severity':<13} {'maps':<18} title")
    for vector in vectors:
        print(f"{vector.id:>4}  {vector.severity:<13} {vector.maps_to:<18} {vector.title}")
    print(f"\n{len(vectors)} vectors from {args.vectors_dir}")
    return 0


def cmd_prompts(args: argparse.Namespace) -> int:
    path = args.file or DEFAULT_PROMPTS
    if not os.path.exists(path):
        print(f"prompt suite not found: {path}", file=sys.stderr)
        return 2
    with open(path) as handle:
        sys.stdout.write(handle.read())
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    if not os.path.exists(DEFAULT_SWEEP):
        print(f"sweep not found: {DEFAULT_SWEEP}", file=sys.stderr)
        return 2
    argv = ["bash", DEFAULT_SWEEP] + (args.sweep_args or [])
    return os.spawnvpe(os.P_WAIT, "bash", argv, os.environ)


def cmd_host_verify(args: argparse.Namespace) -> int:
    if not os.path.exists(DEFAULT_HOST_VERIFY):
        print(f"host verifier not found: {DEFAULT_HOST_VERIFY}", file=sys.stderr)
        return 2
    extra = args.verify_args or []
    argv = ["bash", DEFAULT_HOST_VERIFY] + extra
    return os.spawnvpe(os.P_WAIT, "bash", argv, os.environ)


def cmd_run(args: argparse.Namespace) -> int:
    if not (args.replica or os.environ.get("SANDEVAL_REPLICA") == "1"):
        print(
            "refusing to run: pass --replica (or set SANDEVAL_REPLICA=1).\n"
            "These probes mutate host-visible state on purpose; run them only in a\n"
            "disposable replica, never against a production sandbox.",
            file=sys.stderr,
        )
        return 2
    vectors = select_vectors(discover_vectors(args.vectors_dir), args)
    if not vectors:
        print("no vectors selected", file=sys.stderr)
        return 2
    ctx = build_context(args)
    print(f"in-policy: {ctx.in_dir}")
    print(f"out-of-policy: {ctx.out_dir}")
    print(f"scratch: {ctx.scratch}")
    print(f"policy: {ctx.policy_file or '(not found)'}")
    print(f"host files: {len(ctx.host_files)} candidate(s)")
    print(f"running {len(vectors)} vector(s)\n")
    try:
        records = run_vectors(ctx, vectors, cleanup=args.clean)
        write_reports(records, ctx, args)
    finally:
        if not args.keep_scratch:
            shutil.rmtree(ctx.scratch, ignore_errors=True)
    summary = summarize(records)
    return 1 if summary.get("FAIL") else 0


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--vectors-dir", default=DEFAULT_VECTORS, help="where to load vectors from")
    common.add_argument("--json", help="write a machine-readable JSON report here")
    common.add_argument("--report", help="write a Markdown report here")
    common.add_argument("-v", "--verbose", action="store_true", help="echo probe commands")

    parser = argparse.ArgumentParser(
        prog="sandeval",
        description="Verdict-based sandbox evaluation harness (replica only).",
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"sandeval {__version__}")

    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", parents=[common], help="run the vector battery")
    run.add_argument("--replica", action="store_true", help="required: I am in a disposable replica")
    run.add_argument("--in", dest="in_dir", help="in-policy directory (default: $PWD)")
    run.add_argument("--out", dest="out_dir", help="out-of-policy directory (default: auto)")
    run.add_argument("--state-dir", dest="state_dir", help="agent state dir (default: /state)")
    run.add_argument("--policy", help="path to the sandbox policy file")
    run.add_argument("--workspace", default="/workspace", help="project/workspace path")
    run.add_argument("--safe", action="store_true", help="skip host-global probes")
    run.add_argument("--skip-safe", action="store_true", help="alias for --safe filtering")
    run.add_argument("--arm", action="store_true", help="arm destructive/exploit vectors")
    run.add_argument("--vector", help="comma-separated vector ids to run")
    run.add_argument("--min-severity", choices=list(SEVERITY_ORDER), help="only at or above this severity")
    run.add_argument("--host-file", action="append", help="readable out-of-policy file to target")
    run.add_argument("--seed", help="out-of-policy seed file for read/traversal vectors")
    run.add_argument("--canary", help="HOST:PORT canary for egress vectors")
    run.add_argument("--keep-scratch", action="store_true", help="do not remove the scratch dir")
    run.add_argument("--clean", action="store_true", help="run each vector's cleanup instead of its probe")
    run.set_defaults(func=cmd_run)

    lst = sub.add_parser("list", help="list vectors")
    lst.set_defaults(func=cmd_list)

    prompts = sub.add_parser("prompts", help="print the agentic prompt suite")
    prompts.add_argument("--file", help="path to the prompt suite markdown")
    prompts.set_defaults(func=cmd_prompts)

    sweep = sub.add_parser("sweep", help="run the syscall-surface sweep")
    sweep.add_argument("sweep_args", nargs=argparse.REMAINDER, help="arguments passed to the sweep")
    sweep.set_defaults(func=cmd_sweep)

    verify = sub.add_parser("host-verify", help="run the host-side verifier")
    verify.add_argument("verify_args", nargs=argparse.REMAINDER, help="arguments passed to the verifier")
    verify.set_defaults(func=cmd_host_verify)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
