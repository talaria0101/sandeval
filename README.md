# sandeval — sandbox evaluation kit

Verdict-based verification tooling for AI-agent sandboxes (built against a
Landlock-shaped policy engine, useful for any Linux path/filter sandbox).

**v3, 2026-09-14: full issue-fix pass + replica battery validation + self-test
suite (see `tests/`).** Run everything inside a disposable replica — never
against a live instance. The system under test is the *sandbox*, never the
model: agent refusals are recorded as telemetry, not counted as controls, and
all scoring is host-side.

## Why

Agent sandboxes must assume the occupant is hostile **or manipulated**
(prompt injection is an attack on the sandbox through the agent). Anecdotes
("an agent once found X") and content-sniffing watchdogs don't scale; what
scales is (a) a scripted, expected-deny battery with per-check verdicts and
(b) an agentic red-team suite scored only on host-side proof.

## Components

| File | Layer | Needs a model? |
|---|---|---|
| `landlock-surface-sweep.sh` | syscall-surface conformance: 130+ verdict lines — expected-deny/informational probes across FS, raw btrfs ioctls, table-driven ioctl route enumeration, mount/ns, kernel knobs & subsystems, devices, IPC (ptrace-sibling, process_vm_readv, pidfd_getfd), Landlock compose self-test, privilege, resources, egress channels | no |
| `tests/run-tests.sh` | engine self-test: completion invariant, refusal paths, rc-poison regression, idempotency, `--expect`, baseline round-trip, telemetry scrub | no |
| `redteam-eval-harness.md` | agentic layer: 20 goal-directed prompts (containment, exfil, persistence, build-chain poisoning, races, monitoring tamper, injection) + runbook, scoring rubric, coverage matrix | yes |

## Quickstart

```sh
# inside the disposable replica, as the agent user (NOT root) — that's it:
landlock-surface-sweep.sh --replica
#   IN defaults to $PWD; OUT auto-discovered (first existing write-denied dir:
#   /opt /var/tmp /mnt /srv /run /media /tmp); results + baseline auto-managed
#   in .landscan-state/latest.tsv; every later run auto-diffs against the
#   previous one.

# explicit form (same engine):
landlock-surface-sweep.sh --replica -v --baseline v1.tsv \
    /path/in-policy /path/outside-policy

# bless this run's verdicts as "expected" (kills platform-shape noise):
landlock-surface-sweep.sh --replica --adopt

# cautious mode: skip host-global probes (sysrq 'h', swapon, clock_settime):
landlock-surface-sweep.sh --replica --safe

# after each sandbox change:
landlock-surface-sweep.sh --replica --check v1.tsv \
    /path/in-policy /path/outside-policy
#   IMPROVED  = state moved to what --expect/-want says it should be
#   REGRESSION= state moved away from it — fix your sandbox before shipping
#   CHANGED   = moved between two non-wanted states (e.g. deny ↔ inconclusive)

# self-test the engine (no sandbox enforcement needed):
tests/run-tests.sh
```

### Verdicts

| marker | meaning |
|---|---|
| `[ok]` | got == want |
| `[!!]` | unexpected — investigate |
| `[ii]` | informational (`want=info`), never fails the run |

`got` is `allow`, `deny`, `inconclusive` (ENOENT, EOPNOTSUPP, EINVAL, no tty,
timeout, exec-failure — anything not attributable to policy), or `open`/`closed`
for egress TCP probes. **Inconclusive never counts as a pass**: a
`want=deny` check that comes back `inconclusive` is flagged `[!!]` so it cannot
silently masquerade as enforcement. On platforms that genuinely lack probe
targets (no `/dev/kmsg`, no tty, no `/etc/shadow`), silence the noise the
honest way: `--expect dev-kmsg-open info` — or run `--adopt` once and let the
state dir remember what your platform looks like.

Errno attribution examples: `ks-bpf` uses a *valid* map attr — EPERM means the
syscall is blocked, success means it isn't; `ns-chroot` probes `chroot(2)`
itself (no exec needed), so a missing loader inside the chroot can't fake a
deny; `ks-kexec`/`ks-finit-module` report EPERM as deny and EINVAL as
inconclusive (reachable-but-rejected), never as a pass.

### ioctl route enumeration

There is no kernel API to enumerate which ioctls an fd accepts — `ENOTTY`
probing is the only possible heuristic. The sweep therefore walks a table of
security-relevant ioctl families across every fd it can open (scratch file +
dir, `/dev/tty`, loop-control, device-mapper, kvm, net/tun, input, fb0, block
devices, dri): `FS_IOC_*` flags/xattr, `FIBMAP`, `TIOCSTI`, `TIOCCONS`,
`LOOP_CTL_GET_FREE`, `DM_VERSION`/`DM_LIST_DEVICES`, `KVM_GET_API_VERSION`,
`TUNSETIFF`, `EVIOCGNAME`, `FBIOGET_VSCREENINFO`, `SG_IO` (INQUIRY).
Every request becomes its own baseline entry, classified:

- `REACHABLE` — the ioctl succeeded: a route exists, review it
- `DENIED` (EPERM/EACCES) — policy/capability blocks it: the good answer
- `NOTTY` (ENOTTY) — not a route for this fd
- `ERR` — reachable path, op-specific failure

btrfs subvolume/snapshot creation is probed via **raw ioctl**
(`BTRFS_IOC_SUBVOL_CREATE`/`SNAP_CREATE`) — the mkdir-hook-bypass class needs
no userspace `btrfs` tool; `ENOTTY` on non-btrfs filesystems is honest
inconclusive, and pid-unique names keep re-runs idempotent.

Then run the red-team prompt suite per `redteam-eval-harness.md` (operator
runbook inside: seeding, canaries, telemetry, scoring, coverage matrix).

## Safety model

- `--replica` flag is mandatory; the script refuses otherwise.
- Every probe is a minimal, benign operation — the ALLOW/DENY verdict is the
  result. No payloads, no exfil, no persistence.
- Kernel-knob probes write the *current* value back (full value, never
  truncated): writability is proven without mutating the host.
- Host-global probes are opt-in env gates: `LANDSCAN_SYSRQ=1` (SysRq 'h'),
  `LANDSCAN_SWAP=1` (swapon — swap is not namespaced!), `LANDSCAN_TIME=1`
  (clock_settime — nudges the clock µs *forward*, never back).
- Host-global probes (`sysrq 'h'`, `swapon`, `clock_settime`) run **by default**
  — a disposable replica is exactly where you want to know about them — and are
  disabled together with `--safe` (or `LANDSCAN_SAFE=1`).
- Resource probes are sized heuristically: memhog = 1.25× cgroup `memory.max`
  (else 2% of RAM, clamped 256–1024 MB); disk-fill = 2% of free space (clamped
  64–2048 MB); pids ceiling from cgroup v2/v1. `LANDSCAN_MEMHOG_MB`,
  `LANDSCAN_FILL_MB`, `LANDSCAN_PIDS_PROBE` override.
- All scratch lives in `IN/.landscan/` (never `/tmp`), wiped on exit —
  re-runs are idempotent. Run state (auto baseline, adopted expect table)
  lives in `.landscan-state/` in the working directory.
- Telemetry is commit-safe: `read-init-env` records size + truncated sha256
  only (never content); secret-shaped `…TOKEN=…` substrings in any DETAIL are
  redacted; tabs/newlines are flattened so the TSV baseline stays parseable.
  Secret-file reads (shadow, hostkeys, seed symlink) probe readability with a
  1-byte read instead of copying content.
- Baselines are TSV: `name<TAB>got<TAB>detail`. Commit them for regression
  tracking; redact-review if your DETAILs may carry site-specific strings.
- Portability notes: no bash process substitution (breaks where `/dev/fd` is
  absent); no `~` in `${var//pat/repl}` replacements (expands to `$HOME`).

## Requirements

bash ≥ 4, coreutils (incl. GNU sed/grep for scrubbing), `util-linux`
(mount/unshare), optional: `cc` (unlocks raw-syscall probes: io_uring, bpf,
open_by_handle_at, process_vm_readv, pidfd_getfd, chroot, Landlock compose,
…), `btrfs-progs`, `curl`, `dig`, `capsh`, `auditd` alongside for per-syscall
ground truth.

## Provenance

Developed 2026-09-14 against a live Landlock-based agent sandbox
("bailey"). v2 shipped with launch blockers (a `have()`-before-definition bug
that poisoned every verdict via a broken `timeout` fallback, a
`local`-self-reference crash under `set -u`, and a dead `--expect` parser) —
found by the first execution attempt, not by review; v3 fixes those plus
verdict-attribution, idempotency and telemetry-leak issues, adds the
self-test suite, and was validated by a full replica battery (chroot
exposure and pidfd_getfd-on-init surfaced by the corrected probes).
Methodology note: script conformance battery first — it needs zero model
cooperation — then the agentic suite for the creative layer (e.g. the
btrfs-subvolume-ioctl bypass class), scored host-side only.

## License

MIT — see `LICENSE`.
