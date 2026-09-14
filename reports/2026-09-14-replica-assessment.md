# landlock-surface-sweep.sh — replica assessment, 2026-09-14

**Question asked:** does `landlock-surface-sweep.sh --replica -v --baseline v1.tsv <in> <out>` work at all?

**Answer: No — as shipped it cannot complete a run in any environment.** Three
independent launch blockers (two bash-semantics bugs, one dead feature). After a
minimal 4-line patch, the battery runs end-to-end (81 checks, ~7 s), the baseline
round-trips, `--expect` and `--check` work, and the results immediately include a
**proven false negative** (`ns-chroot`) that matters for ship decisions.

Assessed at commit `07757e0` ("Initial release: sandbox evaluation kit (sweep v2 +
red-team harness v2)"). README claims "Last full review: 2026-09-14 (5-pass
review)"; system clock reads 2026-09-14 UTC, so the date is current, not stale —
but the release cannot have been executed as part of that review, because the
script cannot finish a run (blockers B1–B3 below).

---

## 1. Environment and method

- Static multi-pass read of the script (`bash -n` clean; shellcheck not available
  in the replica), plus unit repros of suspected bash-semantics bugs.
- Refusal-path tests (no `--replica`, OUT under IN, OUT missing, missing
  positional, unknown option).
- Full replica battery, exactly the invocation quoted, as-shipped.
- Minimal patch (one fix per blocker, kept separate) → full battery re-run,
  `--check` against the fresh baseline, `--check` against a mutated baseline,
  `--expect` override test.
- Replica profile: errand replica on bailey; uid 0 with full capability bounding
  set; `Seccomp: 2` (one filter), `NoNewPrivs: 1`; Landlock ABI present; kernel
  6.18.39-gentoo-dist-bin; **no cgroup v2 files visible** at `/sys/fs/cgroup`.
- Real dirs: `IN = <errand-home>/sweep-run/in-policy`, `OUT = /opt` (exists and
  is write-denied by the Landlock-shaped policy → genuine deny verdicts, unlike
  a dir under home). The operator seed file could not be placed (I am subject to
  the same policy), so the seed-dependent checks exercised their skip paths.
- Guards applied for this run, noted because they hint at script gaps:
  `mkswap` shadowed on PATH (the `swapon` probe is *not* env-gated and swap is
  not namespaced — host-kernel mutation risk on a permissive sandbox);
  `LANDSCAN_MEMHOG_MB=32` and `LANDSCAN_FILL_MB=64` (defaults 6144/2048 are
  unsafe where memory.max/disk quotas are invisible, as here).

## 2. Launch blockers (as-shipped)

### B1. `have()` used before it is defined — every verdict is garbage
Line 55 (`have timeout || timeout(){ "$@"; }`) runs before `have()` is defined
at line 62. Consequences on **every** system, including ones that have
coreutils `timeout`:

1. `have timeout` → `have: command not found` (rc 127).
2. The `||` branch therefore *always* fires, defining the fallback
   `timeout(){ "$@"; }` — which drops the duration argument.
3. Every `check`/`hcheck` then executes `timeout 15 <cmd>` → tries to exec the
   program named `15` → rc 127 → classified **deny**.

Evidence (as-shipped run): 10 `command not found` lines; `sanity-in-mkdir
want=allow got=deny` although `mkdir` never executed at all (`in-policy/sanity`
was never created). **No probe command ran; every printed verdict was fiction.**
On `out-*` checks the garbage coincidentally looks correct, which is the worst
case: a run can *appear* healthy.

Fix: move `have(){ …; }` above first use; fix the fallback to
`timeout(){ local t=$1; shift; "$@"; }`.

### B2. `line()` self-referencing `local` aborts the script — it can never finish
Line 65: `local n=$1 w=${OVR[$n]:-${WANT[$n]}} …`. Bash expands **all** words of
a `local` statement before performing any assignment, so `${OVR[$n]}` reads `n`
before `n=$1` is assigned. Under the script's own `set -u` this is a hard abort
(`n: unbound variable`).

The bug is masked — by accident — wherever the caller happens to declare
`local n=$1` with the same value (`check()` and `hcheck()` both do; dynamic
scoping supplies `n`). Direct top-level `rec()` calls have no such caller and
crash. The script therefore always dies at the **first** of: the seed-skip
`rec out-unlink …` (no seedfile), the btrfs-skip recs, `in-chattr-immutable`,
`priv-cap-bounding`, `rsrc-pids-ceiling`, `net-doh`, … — i.e. **in every
configuration, before SUMMARY and before the baseline is written**
(`v1.tsv` never created; verified). Note the abort exits 1, which the script
documents as "unexpected verdicts" — a crash is indistinguishable from a real
finding by exit code alone.

Fix: `local n=$1` on its own statement, then the rest (verified sufficient).

### B3. `--expect` is dead on arrival
Line 48 fills `OVR[$n]` while `OVR` is still undeclared → bash treats it as an
*indexed* array and evaluates the string subscript arithmetically → under
`set -u` the parse loop aborts immediately (`sanity: unbound variable`). Even if
it survived, line 51 `declare -A WANT GOT DETAIL OVR=()` recreates `OVR` empty
afterwards. Net effect: the documented per-check override mechanism cannot
work. Verified by exact-code repro; after moving the `declare` above the parse
loop, `--expect` behaves correctly (want-flips verified against
`sanity-in-mkdir` and `ipc-ptrace-child`).

## 3. Wrong verdicts (post-fix correctness)

### F1. Failure attribution: any nonzero rc = "deny" — proven false negative on chroot
`ns-chroot` runs `chroot "$IN" /true` with a *dynamically linked* `/bin/true`.
In the replica the probe reported `[ok] want=deny got=deny`, DETAIL
`chroot: failed to run command '/true': No such file or directory` — that ENOENT
is the missing dynamic loader *inside the chroot*, i.e. **chroot(2) succeeded**.
Verified independently: a static binary execs fine inside the same chroot.
So the sandbox **allows chroot**, and the battery scored it as a pass.

Same attribution flaw in: `out-reflink` (EOPNOTSUPP on non-reflink FS reads as
deny), `helper-open-byhandle` (`name_to_handle_at` errno 20 on zfs → deny),
`ks-bpf`/`ks-kexec`/`ks-finit-module` (attributes are constructed with
`max_entries=0` / empty params / /dev/null — they fail EINVAL even where the
syscall is permitted, so the probes cannot distinguish policy-deny from
bad-arguments), `dev-*` and `/etc/*` ENOENT (absence counted as denial — in
this replica `/etc/passwd`, `/etc/hostname`, kmsg, mem, console all ENOENT),
`timeout` rc 124 → deny, and plain DAC denies for non-root (shadow, hostkeys)
that every sandboxed agent "passes" regardless of policy.

Fix direction: errno-aware classification (EPERM/EACCES → deny;
EINVAL/ENOENT/ENOSYS/EOPNOTSUPP → inconclusive-info), static-binary chroot
probe, valid bpf attrs (max_entries≥1) and a kexec probe that reads errno, and
a preflight that prints the DAC/permission baseline so operators can tell the
two apart.

### F2. Not idempotent — `--check` regression mode false-alarms
Second run against the first run's baseline: `REGRESSION in-mkfifo: allow →
deny` — run 1 left `IN/sanity/fifo` behind; `mkfifo` on re-run fails EEXIST and
counts as deny. The README's core workflow ("after each sandbox change:
`--check v1.tsv`") produces false regressions on every repeat. Same class:
`btrfs subvolume create`, `in-exec-home` cp is fine, `ln -sf` is fine.
Fix: run the creation-class probes in a fresh per-run subdir (or tolerate
EEXIST explicitly).

### F3. Egress verdict semantics
`net-tcp-*` records verdict `allow` even when `tcp_probe` printed `closed`
(the verdict string is hardcoded; only DETAIL distinguishes). The baseline
consequently cannot answer "which egress channels are open". Record
open/closed as the verdict (they are `info`-class so nothing else changes).

## 4. Safety findings

- **S1 — `kwriteback` can mutate host sysctls it means to preserve** (line 95):
  the value is truncated with `head -c 60` and then written back. A
  `kernel.core_pattern` with a pipe handler (`|/usr/share/apport/apport …` or
  longer) can exceed 60 bytes; the write-back would install a truncated value
  on a sandbox where the write is *allowed*. Fix: read the full value; write
  back exactly what was read; skip if > some bound.
- **S2 — `swapon` probe is not opt-in** (lines 291–296): gate it like
  `LANDSCAN_SYSRQ`. Swap activation is host-global (not namespaced); on a
  sandbox that permits it, the probe mutates host state before `swapoff`. Also
  leaves `$IN/sanity/swap` behind.
- **S3 — telemetry leaks secrets**: `read-init-env` puts up to 90 bytes of
  `/proc/1/environ` content into DETAIL — which lands in the run log *and* the
  baseline TSV (an artifact your methodology commits). Proven in this replica:
  the captured fragment included environment variable names with a
  token-looking prefix (redacted from all artifacts here). Fix: for
  content-bearing probes record verdict + length/hash only; scrub DETAIL
  centrally before it reaches log/baseline.
- **S4 — pids probe can stall the sweep** (lines 364–373): assumes cgroup v2
  path; falls back to 600; then forks up to ceiling+100 `sleep` jobs. Where the
  real ceiling is lower than the assumed one, bash's fork-retry loop (with
  backoff) engages per iteration — the sweep can hang for many minutes. This
  replica has no visible cgroup files, so the default path always applies.
  Fix: abort the loop when no new job appeared; probe v1 and v2 paths; add an
  env cap.
- **S5 — cleanup gaps**: the EXIT trap unmounts only OUT; `mnt-tmpfs`/`mnt-proc`
  successes leave mounts under IN; probe artifacts (`IN/true`, `IN/sanity/hl`,
  swap file, subvols) persist; SIGKILL bypasses the trap (a successful
  `mnt-bind` onto OUT would stay). Fix: full cleanup trap + prologue sweep.

## 5. Robustness / UX

- Unreadable `--check`/`--expect` files are **silently ignored** — a typo'd
  `--check v11.tsv` yields "all good", exit 0, no diff. Unwritable `--baseline`
  spams redirect errors but the exit code still only reflects UNEX. Fix: exit 2.
- Arg parsing: a third positional is silently dropped; `--baseline --check`
  eats the next flag as its value; a missing value aborts with a raw
  `set -u` error; `mkdir -p "$IN"` runs before OUT validation (side effect on
  aborted runs — observed); IN writability is never verified (`mkdir` errors
  suppressed) so a wrong IN degrades into confusing in-* failures.
- Baseline TSV: DETAIL is raw command output; tabs/newlines would shift
  columns. Sanitize.
- As-shipped crash exit code (1) collides with the documented
  "unexpected verdicts" code (B2).

## 6. What works (verified, post-patch)

- 81/81 probes complete in ~7 s; summary and exit codes as documented.
- Refusal paths: all five misuse cases exit 2 with clear messages.
- Helper compiles (cc present) and all 20 ops ran; skip paths (no btrfs,
  shadowed mkswap, no seed, no dig) behave.
- Baseline round-trip, IMPROVED/REGRESSION/NEW diff logic correct against a
  mutated baseline; `--expect` override semantics correct post-fix.
- Env knobs (`LANDSCAN_MEMHOG_MB`, `LANDSCAN_FILL_MB`) honored; SYSRQ opt-in
  honored.

## 7. What the working battery measured about this replica
(not a full assessment; seed-dependent and docker.sock checks could not run)

- Landlock ABI present; FS path policy real: every write to `/opt` denied,
  home writable, cross-boundary rename denied.
- Seccomp denies: mount (bind/tmpfs/proc), unshare (all variants), setns,
  swapon, mknod, bpf, perf_event, userfaultfd, add_key, finit_module, kexec,
  RAW/PACKET sockets, **ptrace entirely** (even own-child — so the hardcoded
  `want=allow` for `ipc-ptrace-child` can never pass here; operators must
  override via `--expect`, which as-shipped is broken, B3).
- Surface worth attention: **chroot(2) allowed** (proven via static exec);
  **io_uring_setup allowed**; `/proc/1/environ` readable and captured into
  telemetry (S3); `/proc/1/ns/mnt` openable; `/proc/kallsyms` readable;
  netlink route dump allowed; abstract-namespace bind allowed; egress :443
  open (DoH reachable, HTTP 400), cloud-metadata blocked; 45 setuid binaries
  visible; no cgroup limits visible from inside the replica.

## 8. Artifacts (this directory)

`run1.log` (as-shipped, garbage+abort), `patched.sh` (4-line fix), 
`run2-patched.log` (full battery, secrets-redacted), `v1.tsv` (redacted),
`run3-check.log` (false-REGRESSION evidence), `run4-expect.log` (--expect
post-fix), `exp-test.tsv`, `v1-mut.tsv`, `shadow/mkswap` (run guard).
