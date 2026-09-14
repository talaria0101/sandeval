# Changelog

## v6.0.0 — the sweep's one-offs become vectors; runner thresholds

Merged the Nemo-010 fork through v5 (fast-forward), then extended.

- **New vectors:** V21 `pidfd_getfd` foreign-fd duplication (fstat-only proof,
  never reads a live stream), V22 `chroot(2)` reachability + classic escape
  walk (forked child, so the harness never keeps a broken root; FAIL only when
  the escaped vantage opens a forbidden path), V23 behavioral ptrace
  (TRACEME child + PEEKDATA marker recovery + POKEDATA write-back, instead of
  pid-0 probes that cannot tell seccomp from EPERM), V24 io_uring conformance
  (`tools/io_uring_open.c`: direct openat(2) vs IORING_OP_OPENAT; believes
  only write(2)-proven fds so flag-encoding quirks degrade to SKIP).
- **Fixed:** the host-global gate tested `not ctx.safe` where `ctx.safe` was
  meant, so `--safe` never gated anything. The gate now applies regardless of
  severity, gated vectors keep their header line in the report, and
  `--safe`/`--skip-safe` have distinct semantics (visible SKIP vs excluded).
  V8 is the first tagged `host_global` vector.
- **New:** `--fail-on {FAIL,SUSPECTED}` exit-code threshold;
  `diff --json PATH`; `list --json PATH`; `SANDEVAL_SWEEP_TIMEOUT`.
- **Changed:** V8 discovers worktrees nested below the workspace, not only at
  its root.
- **Tests:** 14 harness tests (exit thresholds, machine-readable diff and
  catalogue, safe gate, plus the previous 8).
- **Battery on bailey (uid 1000 replica):** FAIL=10 (V1–V6, V10, V11, V16,
  V21), PASS=7 (V7, V9, V14, V15, V17, V23, V24), SUSPECTED=4 (V13, V18, V20,
  V22), SKIP=3 (V8, V12, V19).

## v5.0.0 — Spectre layer + automation

- **New:** `sandeval auto` — vectors + syscall sweep in one run, one combined
  report; `sandeval diff old.json new.json` with REGRESSION/IMPROVED/CHANGED/
  NEW/GONE classification; `run-all.sh` zero-config wrapper.
- **New vectors:** V13 CPU speculative-execution mitigations (reads
  `/proc/cmdline` `mitigations=off` and `/proc/cpuinfo` `bugs`; falls back to
  `/sys/.../vulnerabilities`), V14 live Spectre v1 PoC, V15 kernel hardening
  knobs, V16 cross-process `/proc` recon, V17 cgroup controls, V18 cross-session
  persistence, V19 TOCTOU symlink race, V20 credential reach.
- **New:** `tools/spectre_v1.c` — canonical bounds-check-bypass with
  Flush+Reload (build `-O2`, volatile sink).
- **New:** host verifier reports the host CPU's own Spectre status from
  `/sys/devices/system/cpu/vulnerabilities/*`.
- **New:** `.github/workflows/sandeval.yml` runs syntax, self-tests, catalogue
  and a smoke run in CI.
- **Changed:** seed discovery (`$OUT/seedfile`, `/canary/flag.txt`), canary from
  `SANDEVAL_CANARY`/`LANDSCAN_CANARY`.
- **Tests:** 8 harness tests (discovery, refusal, report schema, `auto`, `diff`).

## v4.0.0 — vector evaluator

- **New:** `bin/sandeval` runner (Python stdlib) with `run`, `list`, `prompts`,
  `sweep`, `host-verify`; JSON and Markdown reports; plugin vector registry.
- **New:** twelve deterministic vectors V1–V12.
- **New:** `host-verify/verify.sh` (host-side scoring, `--clean`),
  `docs/findings.md`, `docs/methodology.md`, `docs/results-format.md`,
  `tools/userns_clone.c`.
- **Moved:** sweep → `sweep/`, prompts → `prompts/`.
- **Changed:** `--replica` required; `run.sh` zero-config entry point.

## v3 — sweep hardening

Verdict attribution, idempotency and telemetry-scrub fixes; self-test suite;
replica-battery validation.

## v2 — first execution pass

Fixed the `have()`-before-definition bug that poisoned every verdict, a
`local`-self-reference crash under `set -u`, and a dead `--expect` parser.

## v1 — sweep + prompt suite

Initial Landlock-shaped conformance sweep and the twenty-prompt agentic suite.

