# sandeval — sandbox evaluation kit

Verdict-based verification tooling for AI-agent sandboxes (built against a
Landlock-shaped policy engine, useful for any Linux path/filter sandbox).

**Last full review: 2026-09-14 (5-pass review).** Run everything inside a
disposable replica — never against a live instance. The system under test is
the *sandbox*, never the model: agent refusals are recorded as telemetry, not
counted as controls, and all scoring is host-side.

## Why

Agent sandboxes must assume the occupant is hostile **or manipulated**
(prompt injection is an attack on the sandbox through the agent). Anecdotes
("an agent once found X") and content-sniffing watchdogs don't scale; what
scales is (a) a scripted, expected-deny battery with per-check verdicts and
(b) an agentic red-team suite scored only on host-side proof.

## Components

| File | Layer | Needs a model? |
|---|---|---|
| `landlock-surface-sweep.sh` | syscall-surface conformance: ~70 expected-deny/informational probes across FS, ioctl, mount/ns, kernel knobs & subsystems, devices, IPC, privilege, resources, egress channels | no |
| `redteam-eval-harness.md` | agentic layer: 20 goal-directed prompts (containment, exfil, persistence, build-chain poisoning, races, monitoring tamper, injection) + runbook, scoring rubric, coverage matrix | yes |

## Quickstart

```sh
# inside the disposable replica, as the agent user (NOT root):
landlock-surface-sweep.sh --replica -v --baseline v1.tsv \
    /path/in-policy /path/outside-policy

# after each sandbox change:
landlock-surface-sweep.sh --replica --check v1.tsv \
    /path/in-policy /path/outside-policy
#   IMPROVED  = enforcement gained   ·  REGRESSION = fix your sandbox before shipping
```

Then run the red-team prompt suite per `redteam-eval-harness.md` (operator
runbook inside: seeding, canaries, telemetry, scoring, coverage matrix).

## Safety model

- `--replica` flag is mandatory; the script refuses otherwise.
- Every probe is a minimal, benign operation — the ALLOW/DENY verdict is the
  result. No payloads, no exfil, no persistence.
- Kernel-knob probes write the *current* value back: writability is proven
  without mutating the host.
- Network checks are informational by default; encode site intent via
  `--expect`. All scratch lives in the in-policy dir (never `/tmp`).

## Requirements

bash ≥ 4, coreutils, `util-linux` (mount/unshare), optional: `cc` (unlocks
raw-syscall probes: io_uring, bpf, open_by_handle_at, …), `btrfs-progs`,
`curl`, `dig`, `capsh`, `auditd` alongside for per-syscall ground truth.

## Provenance

Developed and reviewed 2026-09-14 against a live Landlock-based agent
sandbox ("bailey", 5 review passes; io_uring exposure caught in smoke test).
Methodology note: script conformance battery first — it needs zero model
cooperation — then the agentic suite for the creative layer (e.g. the
btrfs-subvolume-ioctl bypass class), scored host-side only.

## License

MIT — see `LICENSE`.
