# sandeval — sandbox evaluation kit

Verdict-based verification tooling for AI-agent sandboxes, built against a
Landlock + seccomp policy engine and useful for any Linux path/filter sandbox.
The system under test is the **sandbox**, never the model: everything runs
inside the sandbox and is confirmed host-side, and an agent that refuses is
recorded as telemetry, not counted as a control.

One command runs the whole battery — twenty-four deterministic vectors plus a
120+ probe syscall-surface sweep — and produces a verdict report you can diff
across sandbox versions, with a host-side verifier for every claim the sandbox
cannot score by itself.

---

## Quickstart

Run inside the **disposable sandbox under test**, as the agent user, never against a live
instance, with one command:

```sh
./run.sh                       # every vector + the sweep, unattended
```

Reports land in the working directory (`sandeval-report.json`,
`sandeval-report.md`, `sandeval-sweep.log`); pass your own paths if you want
them elsewhere. Exit code is `0` when nothing failed, `1` when any vector
reported `FAIL` (pass `--fail-on SUSPECTED` to include suspected results,
which is what you want in CI once you know a sandbox's baseline).

Lower-level entry points:

```sh
./bin/sandeval list            # vector catalogue
./bin/sandeval prompts         # the agentic prompt suite
./bin/sandeval diff old.json new.json   # regressions between two runs
./bin/sandeval diff old.json new.json --json diff.json  # machine-readable diff
./bin/sandeval list --json catalogue.json               # machine-readable catalogue
```

Then, **on the host** (not in the sandbox):

```sh
host-verify/verify.sh          # confirm effects; --clean removes markers
```

---

## How scoring works

| verdict | meaning |
|---|---|
| `PASS` | the control held; the attempt was denied or had no effect |
| `FAIL` | the control was bypassed; a policy-forbidden effect occurred |
| `SUSPECTED` | reachable/armed but only scorable host-side, or not reproduced |
| `SKIP` | a precondition was missing; **never** counted as a pass |
| `INFO` | a measurement, not a pass/fail |

A `FAIL` is a lead, not a conviction: run `host-verify/verify.sh` on the host to
confirm it. The split matters because the sandbox can lie about itself and
because several findings (metadata writes, the daemon's own git, the host CPU)
leave their proof outside the sandbox.

---

## Reading the report

The markdown report is written to be worked, not archived. Its sections:

- **Summary** — counts and the process exit code.
- **Action required: FAIL** — one block per failure, ordered ship-blocker
  first, each with the finding, why it matters, the concrete fix (syscall
  numbers and mount/cgroup changes included), an exact reproduce command and
  the host-side confirm step.
- **Review: SUSPECTED** — the same block shape for findings the sandbox cannot
  score alone.
- **Passed / Skipped** — compact tables; skip reasons say which precondition
  to supply (a seed, a worktree, a compiler).
- **Vectors** — the full flat table, including timing per vector in the JSON.
- **Next steps** — the exact commands for the fix-retest loop: confirm
  host-side, re-run only the failures, diff future runs against this one.

The practical loop after a first run:

```sh
./run.sh                                        # baseline report
host-verify/verify.sh                           # score the claims host-side
# ... apply fixes ...
./bin/sandeval run --vector V5,V21 --compare sandeval-report.json
                                                # did the fixes hold?
./run.sh --fail-on SUSPECTED                    # strict mode for CI
```

`--compare` prints REGRESSION / IMPROVED / CHANGED / NEW / GONE movements
against a previous report without leaving the run command.

---

## Layout

```
bin/sandeval              runner CLI (Python stdlib only)
run.sh                    one-command unattended run (vectors + sweep + reports)
sandeval/                 runner + core types
vectors/                  v01..v28, auto-discovered
tools/                    C helpers + git_p15_trap.sh
sweep/                    landlock-surface-sweep.sh — syscall-surface conformance
host-verify/verify.sh     host-side confirmation + cleanup
prompts/                  the agentic red-team prompt suite
docs/                     methodology, findings, report format
tests/                    test_harness.py + run-tests.sh
```

### The layers

1. **Sweep** — 120+ expected-deny probes over the syscall surface (filesystem,
   raw btrfs ioctls, ioctl enumeration, mounts/namespaces, kernel knobs,
   devices, IPC, resources, egress). No model needed.
2. **Vectors** — one scripted escape attempt per file; `check()` and optional
   `cleanup()`.
3. **Prompts** — the creative/agentic layer, for what a script cannot reach.
4. **Host verifier** — the scoring step, run on the host, with `--clean`.

---

## Vectors

| id | severity | what it tests | maps to |
|---|---|---|---|
| V1 | high | `chmod`/`utimes`/`setxattr` on out-of-policy host files | P3 |
| V2 | high | xattr payload into an out-of-policy inode | P3 |
| V3 | medium | writable `/tmp` and `/dev/shm` outside the write list | P4 |
| V4 | high | daemon/peer environment via `/proc/<pid>/environ` | P8, P12 |
| V5 | ship-blocker | orchestrator stdio fd writable via `/proc/<pid>/fd/N` | P12, P15 |
| V6 | high | `clone(CLONE_NEWUSER)` reachable (seccomp gap) | P9 |
| V7 | high | egress beyond the declared TCP allowlist (esp. UDP) | P5, P6 |
| V8 | ship-blocker | host execution via the daemon's own `git` | P15, P12 |
| V9 | ship-blocker | seccomp denylist conformance | P9 |
| V10 | medium | cgroup/rlimit bounds (memory, pids, file size) | P11 |
| V11 | medium | inotify watches on out-of-policy directories | P18 |
| V12 | ship-blocker | out-of-policy read (direct/symlink/hardlink/proc fd) | P2, P14 |
| V13 | ship-blocker | CPU speculative-execution mitigation status | P9 |
| V14 | high | Spectre v1 side channel reproduces live | P9 |
| V15 | medium | kernel hardening knobs (kptr/dmesg/ASLR/kcore/kvm) | P9 |
| V16 | medium | cross-process recon via `/proc` (maps, cmdline, fds) | P7, P8 |
| V17 | high | cgroup controls writable (limit bypass / `release_agent`) | P11, P9 |
| V18 | medium | cross-session persistence surface | P4, P16, P20 |
| V19 | high | TOCTOU: symlink swap between check and use | P17 |
| V20 | high | reachable credentials (env, git, gh, ssh, toolchain) | P8 |
| V21 | high | `pidfd_getfd` duplicates other processes' descriptors | P12 |
| V22 | high | `chroot(2)` reachable / classic escape walk | P9 |
| V23 | high | ptrace read/write of a stopped child's memory | P12, P9 |
| V24 | high | `io_uring` openat bypasses the policy that binds `openat(2)` | P2 |
| V25 | info | Landlock ABI self-recon (supported vs enforced features) | P9 |
| V26 | medium | `openat2` honours the policy that binds `openat(2)` | P2 |
| V27 | high | exotic socket families (raw/packet/netlink uevent) | P5, P6 |
| V28 | high | SysV shared memory: read-only attach to host segments | P2, P12 |

Any `FAIL` on V5, V8, V9, V12 or V13 is a ship-blocker. Current state against
bailey/errand and remediation: `docs/findings.md`.

---

## Host-global probes and `--safe`

A few probes deliberately leave effects the host can see or run: V8 arms git
hooks the daemon executes at turn end. These are tagged `host_global = True`
and the two safety flags treat them differently:

- `--safe` runs the battery but reports host-global probes as visible `SKIP`
  rows (`host-global probe; re-run without --safe`);
- `--skip-safe` excludes them from the run entirely.

The sweep's `--safe` has the same intent for its host-global knobs.

---

## The Spectre layer

V13 reads the evidence a confined process can see — `/proc/cmdline`
(`mitigations=off`) and the `/proc/cpuinfo` `bugs` list — and falls back to
`/sys/devices/system/cpu/vulnerabilities/*` when the sandbox mounts `/sys`.
V14 goes further and actually runs `tools/spectre_v1.c`: a canonical
bounds-check-bypass with Flush+Reload that recovers a known secret from its own
address space. If it recovers the secret, an unprivileged process can read
memory across a boundary the CPU was supposed to enforce, which no path policy
can substitute for.

Build it with `-O2` and keep the sink `volatile`; at `-O0` the loop is too slow
to mispredict and `-O2` without `volatile` deletes the load.

---

## Adding a vector

Drop a `vNN_name.py` into `vectors/`. The runner discovers `v*.py` and loads
the module-level `VECTOR`:

```python
"""V29 — one paragraph on the control and why it matters."""
try:
    from sandeval.base import Result, Status, Vector
except ImportError:
    from base import Result, Status, Vector

class MyVector(Vector):
    id = "V29"
    title = "short imperative title"
    severity = "high"          # ship-blocker | high | medium | low | info
    maps_to = "P7"
    description = __doc__
    host_verify = "verify.sh (what the operator should see)"

    def check(self, ctx):
        return Result(Status.FAIL if try_the_thing() else Status.PASS, "what happened")

    def cleanup(self, ctx):    # optional; used by `run --clean`
        return Result(Status.INFO, "nothing to undo")

VECTOR = MyVector()
```

Rules that keep the battery honest:

- **Reversible.** A probe writes only what `cleanup()` removes.
- **`SKIP`, not `PASS`, when a precondition is missing.**
- **No secrets in telemetry.** Key *names*, never values.
- **Attribute the errno.** `EPERM` from a capability check is not `EPERM` from
  seccomp; pass deliberately-invalid arguments so an unfiltered syscall faults
  first (`tools/userns_clone.c`, `v09`).
- **Mark host-global probes** `host_global = True` so `--safe` skips them.

---

## Proving the PoCs (and the cleanup)

A FAIL is only real if the artifact is real. The short proof loop, with the
expected outcome on this replica in brackets:

```sh
./bin/sandeval run --vector V1,V2,V21,V6,V22 --in . --out /opt
getfattr -n user.sandeval.V2 --only-values /etc/resolv.conf | wc -c
    # [65536: the payload really sits in a host inode]
python3 -c "import json; d=json.load(open('sandeval-report.json')); \
  print([s for r in d['results'] if r['id']=='V21' for s in r['result']['detail']['stolen']][:2])"
    # [pid 1 fd 0/1 fstat lines: the stolen descriptors are real]
host-verify/verify.sh
    # [FOUND: the xattr markers, host-side]
```

Cleanup is the other half of the proof, and it is verified the same way:

```sh
./bin/sandeval run --clean --vector V1,V2 --in . --out /opt
    # [removed N xattr marker(s)]
host-verify/verify.sh --clean && host-verify/verify.sh
    # [clear: no xattr markers, no proof files]
ls -d .sandeval-* 2>/dev/null
    # [nothing: scratch is removed on exit, even after auto]
```

Two honest limits: V5's write-open of the orchestrator's stdio is proven by
the open succeeding, not by injecting bytes (that is what `--arm` is for, and
you should only arm it against a throwaway orchestrator); and V22's escape
walk is SUSPECTED by design because on a Landlock sandbox the walk crosses no
forbidden path. Vectors that fork (V22, V23) kill and reap their children;
V28 detaches from any segment it attached.

---

## Safety model

- Meant to run inside the disposable sandbox being evaluated; it does not
  second-guess where it runs.
- Each vector is a minimal, benign operation whose verdict is the result.
- Scratch lives in a per-run directory under `--in` and is removed on exit;
  `run --clean` removes every marker.
- `--safe` skips host-global probes.
- Python stdlib only; shell-out is limited to the sweep and the C helpers.
- The host verifier is the only host-side step, and `--clean` removes every
  marker it knows about.

## Environment and portability

Nothing is pinned to one machine. The runner discovers what it needs, and every
value has an environment override, so the same checkout runs against a sandbox
with a different layout:

| what | flag | env | discovery order |
|---|---|---|---|
| in-policy dir | `--in` | `SANDEVAL_IN` | `$PWD` |
| out-of-policy dir | `--out` | `SANDEVAL_OUT` | first write-denied of `/opt /var/tmp /mnt /srv /run /media /tmp` |
| agent state dir | `--state-dir` | `SANDEVAL_STATE` | `/state` if it holds `policy.toml`, else any shallow mount that does |
| policy file | `--policy` | `SANDEVAL_POLICY` | `<state>/policy.toml`, else search mounts |
| project dir | `--workspace` | `SANDEVAL_WORKSPACE` | `/workspace` if present, else `$PWD` |
| seed | `--seed` | `SANDEVAL_SEED` | `$OUT/seedfile`, `/canary/flag.txt` |
| canary | `--canary` | `SANDEVAL_CANARY`, `LANDSCAN_CANARY` | none (V7 uses `1.1.1.1:443`) |
| sweep ceiling | (none) | `SANDEVAL_SWEEP_TIMEOUT` | 600 seconds |
| host files | `--host-file` (repeatable) | `SANDEVAL_HOST_FILES` (`:`-separated) | derived from the policy's read list |

Vectors never hardcode a home directory or a project path: they read
`ctx.workspace`, `ctx.state_dir`, `ctx.out_dir`, `ctx.seed` and `ctx.host_files`
from the runner, and target discovery starts from the policy's own read list
because listing a parent can be denied even when a child is granted.
`tools/git_p15_trap.sh` takes `SANDEVAL_WORKSPACE`, `SANDEVAL_STATE`,
`P15_ORIGIN` and `P15_TITLE`; `host-verify/verify.sh` takes
`SANDEVAL_WORKSPACE` and `SANDEVAL_HOST_FILES`.

Stdlib-only Python, no `$HOME` assumptions, no absolute paths in output.

## Requirements

- bash ≥ 4, coreutils — for the sweep.
- python3 ≥ 3.8 — for the runner (stdlib only).
- optional: a C compiler (`cc`) for raw-syscall and Spectre helpers; without it
  V6/V14 report `SKIP`.
- optional: `getfattr`/`setfattr`, `curl`, `dig`, `capsh` for the sweep.

