# Changelog

## v4.0.0 — vector evaluator

The kit becomes a single runnable evaluator instead of a sweep plus a document.

- **New:** `bin/sandeval` runner (Python stdlib only) with `run`, `list`,
  `prompts`, `sweep` and `host-verify` subcommands, JSON and Markdown reports,
  and a plugin vector registry (`vectors/v*.py`).
- **New:** twelve deterministic vectors covering inode metadata, xattrs, tmpfs,
  `/proc` environment, orchestrator stdio, user-namespace `clone`, egress
  channels, git-native host execution, seccomp conformance, resource bounds,
  inotify watches and out-of-policy reads.
- **New:** `host-verify/verify.sh` — the host-side scoring step, with `--clean`.
- **New:** `docs/findings.md` (state of each finding + remediation),
  `docs/methodology.md`, `docs/results-format.md`.
- **New:** `tools/userns_clone.c` raw-syscall helper.
- **Moved:** `landlock-surface-sweep.sh` → `sweep/`,
  `redteam-eval-harness.md` → `prompts/`, `HANDOFF.md` →
  `docs/HANDOFF-sweep-v4.md`.
- **Changed:** `run.sh` is the zero-config entry point; `--replica` is required
  for `run` and `sweep`.
- **Tests:** `tests/test_harness.py` validates discovery, metadata, the refusal
  path and the report schema; `tests/run-tests.sh` keeps the sweep self-tests
  and runs the Python suite.

## v3 — sweep hardening

Verdict attribution, idempotency and telemetry-scrub fixes; self-test suite;
replica-battery validation.

## v2 — first execution pass

Fixed the `have()`-before-definition bug that poisoned every verdict, a
`local`-self-reference crash under `set -u`, and a dead `--expect` parser.

## v1 — sweep + prompt suite

Initial Landlock-shaped conformance sweep and the twenty-prompt agentic suite.
