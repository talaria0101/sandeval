# Changelog

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

