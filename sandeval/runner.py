"""sandeval runner — discovery, execution and reporting.

Usage is documented in README.md; run `sandeval list` for the vector table.
The runner deliberately keeps every probe small and reversible.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob
import importlib.util
import json
import os
import shutil
import subprocess
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


def _mount_points() -> List[str]:
    """Candidate mount points, shallowest first, from /proc/self/mountinfo.

    Used to find the agent's state directory on a machine whose layout differs
    from the one this harness was written on: the directory is whichever mount
    holds a ``policy.toml``.
    """
    points: List[str] = []
    try:
        with open("/proc/self/mountinfo") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) > 4:
                    mount = fields[4]
                    if mount.startswith("/") and mount.count("/") <= 3:
                        points.append(mount)
    except OSError:
        pass
    points.sort(key=len)
    return points


def discover_state_dir(explicit: Optional[str]) -> str:
    """Locate the agent state directory without assuming ``/state``."""
    if explicit:
        return explicit
    env = os.environ.get("SANDEVAL_STATE")
    if env:
        return env
    if os.path.exists("/state/policy.toml"):
        return "/state"
    for mount in _mount_points():
        if os.path.exists(os.path.join(mount, "policy.toml")):
            return mount
    return "/state"


def discover_policy_file(explicit: Optional[str], state_dir: str) -> Optional[str]:
    if explicit:
        return explicit
    env = os.environ.get("SANDEVAL_POLICY")
    if env:
        return env if os.path.exists(env) else None
    candidate = os.path.join(state_dir, "policy.toml")
    if os.path.exists(candidate):
        return candidate
    for mount in _mount_points():
        candidate = os.path.join(mount, "policy.toml")
        if os.path.exists(candidate):
            return candidate
    return None


def discover_workspace(explicit: Optional[str], state_dir: str) -> str:
    """Locate the project directory without assuming ``/workspace``."""
    if explicit:
        return os.path.abspath(explicit)
    env = os.environ.get("SANDEVAL_WORKSPACE")
    if env:
        return os.path.abspath(env)
    if os.path.isdir("/workspace"):
        return "/workspace"
    # fall back to a writable directory that is not the state dir
    for candidate in (os.getcwd(), "/workspace"):
        if os.path.isdir(candidate) and os.path.realpath(candidate) != os.path.realpath(state_dir):
            return os.path.abspath(candidate)
    return os.getcwd()


def build_context(args: argparse.Namespace) -> Context:
    in_dir = os.path.abspath(args.in_dir or os.environ.get("SANDEVAL_IN") or os.getcwd())
    if not os.path.isdir(in_dir):
        raise SystemExit(f"--in {in_dir!r} is not a directory")
    out_dir = os.path.abspath(
        args.out_dir or os.environ.get("SANDEVAL_OUT") or discover_out_dir(None)
    )
    state_dir = discover_state_dir(args.state_dir)
    policy_file = discover_policy_file(args.policy, state_dir)
    workspace = discover_workspace(args.workspace, state_dir)
    scratch = tempfile.mkdtemp(prefix=".sandeval-", dir=in_dir)
    ctx = Context(
        in_dir=in_dir,
        out_dir=out_dir,
        scratch=scratch,
        safe=args.safe,
        arm=args.arm,
        verbose=args.verbose,
        canary=args.canary or os.environ.get("SANDEVAL_CANARY") or os.environ.get("LANDSCAN_CANARY"),
        seed=args.seed or os.environ.get("SANDEVAL_SEED"),
        host_files=[],
        workspace=workspace,
        state_dir=state_dir,
        policy_file=policy_file,
        log_fn=(lambda m: print("    " + m)) if args.verbose else (lambda _m: None),
    )
    ctx.host_files = discover_host_files(args.host_file or [], ctx)
    if not ctx.seed:
        ctx.seed = discover_seed(ctx)
    return ctx


def discover_seed(ctx: Context) -> Optional[str]:
    """Find the operator-seeded out-of-policy file, if one was placed."""
    for candidate in (os.path.join(ctx.out_dir, "seedfile"), "/canary/flag.txt"):
        if os.path.exists(candidate) and not ctx.policy_writable(candidate):
            return candidate
    return None


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


def _host_global(vector: Vector) -> bool:
    """Probes whose effect is deliberately visible beyond this sandbox."""
    return bool(getattr(vector, "host_global", False))


def run_vectors(ctx: Context, vectors: List[Vector], cleanup: bool = False) -> List[dict]:
    records: List[dict] = []
    for vector in vectors:
        print(f"[{vector.id:>3}] {vector.title} ...", flush=True)
        if ctx.safe and _host_global(vector):
            result = Result(Status.SKIP, "host-global probe; re-run without --safe")
        else:
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


def _exit_code(summary: Dict[str, int], args: argparse.Namespace) -> int:
    """rc 1 when any record reaches the --fail-on threshold (default FAIL)."""
    threshold = getattr(args, "fail_on", None) or "FAIL"
    if summary.get("FAIL"):
        return 1
    if threshold == "SUSPECTED" and summary.get("SUSPECTED"):
        return 1
    return 0


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
    if getattr(args, "json", None):
        payload = [
            {
                "id": v.id,
                "title": v.title,
                "severity": v.severity,
                "maps_to": v.maps_to,
                "host_verify": v.host_verify,
                "host_global": bool(getattr(v, "host_global", False)),
            }
            for v in vectors
        ]
        with open(args.json, "w") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"{len(payload)} vectors -> {args.json}")
        return 0
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
    return _exit_code(summary, args)


# --------------------------------------------------------------------------- #
# one-shot automation + regression diff
# --------------------------------------------------------------------------- #

def run_sweep(ctx: Context, safe: bool):
    """Run the syscall-surface sweep and return (rc, log, summary_lines)."""
    if not os.path.exists(DEFAULT_SWEEP):
        return 2, "", []
    argv = ["bash", DEFAULT_SWEEP]
    if safe:
        argv.append("--safe")
    argv += [ctx.in_dir, ctx.out_dir]
    try:
        timeout = float(os.environ.get("SANDEVAL_SWEEP_TIMEOUT", "600"))
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=ctx.in_dir,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return 2, f"sweep failed: {exc}", []
    summary = []
    capture = False
    for line in proc.stdout.splitlines():
        if "SUMMARY" in line and line.strip().startswith("==="):
            capture = True
            continue
        if capture:
            if line.strip().startswith("==="):
                break
            if line.strip():
                summary.append(line.rstrip())
    return proc.returncode, proc.stdout, summary


def cmd_auto(args: argparse.Namespace) -> int:
    vectors = select_vectors(discover_vectors(args.vectors_dir), args)
    if not vectors:
        print("no vectors selected", file=sys.stderr)
        return 2
    ctx = build_context(args)
    print(f"in-policy: {ctx.in_dir}")
    print(f"out-of-policy: {ctx.out_dir}")
    print(f"policy: {ctx.policy_file or '(not found)'}")
    print(f"seed: {ctx.seed or '(none – V12/V19 report SKIP)'}")
    print(f"canary: {ctx.canary or '(none)'}")
    print(f"host files: {len(ctx.host_files)}")
    print(f"\nrunning {len(vectors)} vector(s)")
    records = run_vectors(ctx, vectors)
    summary = summarize(records)
    sweep_summary = []
    if not args.no_sweep:
        print("\nrunning syscall-surface sweep ...")
        sweep_rc, sweep_log, sweep_summary = run_sweep(ctx, args.safe)
        print(f"sweep rc={sweep_rc} ({len(sweep_log.splitlines())} lines)")
        if args.sweep_log:
            with open(args.sweep_log, "w") as handle:
                handle.write(sweep_log)
    write_reports(records, ctx, args)
    if args.report and sweep_summary:
        with open(args.report, "a") as handle:
            handle.write("\n## Sweep summary\n\n```\n" + "\n".join(sweep_summary) + "\n```\n")
    print("\nnext: run host-verify on the host, then `sandeval diff old.json new.json`")
    return _exit_code(summary, args)


def cmd_diff(args: argparse.Namespace) -> int:
    try:
        with open(args.old) as handle:
            old = json.load(handle)
        with open(args.new) as handle:
            new = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"could not read reports: {exc}", file=sys.stderr)
        return 2
    oldmap = {r["id"]: r["result"]["status"] for r in old.get("results", [])}
    newmap = {r["id"]: r["result"]["status"] for r in new.get("results", [])}
    order = list(newmap) + [i for i in oldmap if i not in newmap]
    regressions = 0
    movements = 0
    changes = []
    print(f"{'id':>4}  {'old':<11} {'new':<11} verdict")
    for vector_id in order:
        before, after = oldmap.get(vector_id), newmap.get(vector_id)
        if before is None:
            verdict = "NEW"
        elif after is None:
            verdict = "GONE"
        elif before == after:
            verdict = ""
        elif after == "FAIL" and before != "FAIL":
            verdict = "REGRESSION"
            regressions += 1
        elif before == "FAIL" and after != "FAIL":
            verdict = "IMPROVED"
            movements += 1
        else:
            verdict = "CHANGED"
            movements += 1
        if verdict:
            print(f"{vector_id:>4}  {before or '-':<11} {after or '-':<11} {verdict}")
            changes.append({"id": vector_id, "old": before, "new": after, "verdict": verdict})
    print(f"\n{regressions} regression(s), {movements} other movement(s)")
    if getattr(args, "json", None):
        with open(args.json, "w") as handle:
            json.dump(
                {
                    "old": args.old,
                    "new": args.new,
                    "regressions": regressions,
                    "movements": movements,
                    "changes": changes,
                },
                handle,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")
        print(f"diff report: {args.json}")
    return 1 if regressions else 0


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #

def _add_probe_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--in", dest="in_dir", help="in-policy directory (default: $PWD)")
    p.add_argument("--out", dest="out_dir", help="out-of-policy directory (default: auto)")
    p.add_argument("--state-dir", dest="state_dir", help="agent state dir (default: auto-discovered)")
    p.add_argument("--policy", help="path to the sandbox policy file")
    p.add_argument("--workspace", help="project/workspace path (default: auto-discovered)")
    p.add_argument("--safe", action="store_true", help="SKIP host-global probes (visible in the report)")
    p.add_argument("--skip-safe", action="store_true", help="exclude host-global probes from the run entirely")
    p.add_argument("--arm", action="store_true", help="arm destructive/exploit vectors")
    p.add_argument("--vector", help="comma-separated vector ids to run")
    p.add_argument("--min-severity", choices=list(SEVERITY_ORDER), help="only at or above this severity")
    p.add_argument("--host-file", action="append", help="readable out-of-policy file to target")
    p.add_argument("--seed", help="out-of-policy seed file for read/traversal vectors")
    p.add_argument("--canary", help="HOST:PORT canary for egress vectors")
    p.add_argument("--fail-on", choices=("FAIL", "SUSPECTED"), default="FAIL",
                   help="exit 1 when any vector reaches this status or worse (default: FAIL)")
    p.add_argument("--keep-scratch", action="store_true", help="do not remove the scratch dir")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--vectors-dir", default=DEFAULT_VECTORS, help="where to load vectors from")
    common.add_argument("--json", help="write a machine-readable JSON report here")
    common.add_argument("--report", help="write a Markdown report here")
    common.add_argument("-v", "--verbose", action="store_true", help="echo probe commands")

    parser = argparse.ArgumentParser(
        prog="sandeval",
        description="Verdict-based sandbox evaluation harness.",
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"sandeval {__version__}")

    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", parents=[common], help="run the vector battery")
    _add_probe_options(run)
    run.add_argument("--clean", action="store_true", help="run each vector's cleanup instead of its probe")
    run.set_defaults(func=cmd_run)

    auto = sub.add_parser("auto", parents=[common], help="run vectors + sweep and write one report")
    _add_probe_options(auto)
    auto.add_argument("--no-sweep", action="store_true", help="skip the syscall-surface sweep")
    auto.add_argument("--sweep-log", help="write the full sweep log here")
    auto.set_defaults(func=cmd_auto)

    diff = sub.add_parser("diff", help="compare two JSON reports for regressions")
    diff.add_argument("old", help="baseline report.json")
    diff.add_argument("new", help="current report.json")
    diff.add_argument("--json", help="write a machine-readable diff here")
    diff.set_defaults(func=cmd_diff)

    lst = sub.add_parser("list", help="list vectors")
    lst.add_argument("--json", help="write the catalogue as JSON here")
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
