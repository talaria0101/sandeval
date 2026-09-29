# The path-less surface — V39-V44 and what is still open

Started 2026-09-29 in session `olbbd1h4pm25`. This file is the standing state
of that work: enough to resume from this repository alone, with the commands,
the measured numbers, and the leads that are not vectors yet.

## The question

The policy under test names paths. `read`, `write` and `execute` are lists of
them, and Landlock is a path engine: every rule it enforces hangs off a
`PathBeneath`. The interesting objects in a sandbox are increasingly the ones
that have no path at all, or whose path is not the thing you think it is:

| object | has a path? | vector |
|---|---|---|
| the orchestrator's stdout pipe | a `pipe:[inode]` | V39 |
| a `memfd` holding an executable | none | V40 |
| an abstract unix socket name | none | V41 |
| a write grant on a mount that outlives the session | a path, but a host one | V42 |
| a TCP connection | no path, a port | V43 |
| a directory reachable under two names | two paths, one object | V44 |

V5 and V29 opened these doors and stopped at the open: V5 proved
`/proc/<pid>/fd/1` is writable, V29 wrote a marker and could not prove
delivery. V39 measures the pipe instead of the transcript, which is what makes
the question answerable from inside.

## Results, 2026-09-29

Run: `./bin/sandeval run --arm --vector V5,V7,V37,V39,V40,V41,V42,V43`

| vector | verdict | the number that decides it |
|---|---|---|
| V39 | FAIL | 512 KiB drained against an 8 KiB control; holder is pid 1 fd 1, no reader in this pid namespace |
| V40 | FAIL | `memfd_execveat` and `memfd_procfd` ran the payload (exit 42); the same bytes at `/state/...` are refused `EACCES` |
| V41 | FAIL | abstract `bind` + stream handshake both succeed; policy declares no socket rule |
| V42 | FAIL | `CARGO_HOME` sits on `rpool/home/cache/errand/cargo`, no session id in the mount root |
| V43 | PASS | no direct off-box path: `1.1.1.1:443` times out, `1.1.1.1:22` is `EACCES`, only `169.254.169.1:36821` completes |
| V7 | PASS | egress matches the allowlist on `1.1.1.1` |
| V37 | PASS | `RLIMIT_CORE` is 0, pattern writes files |
| V5 | FAIL | `/proc/1/fd/0`, `fd/1`, `fd/2` all write-opened (marker written only under `--arm`) |

### The impact pass, same day: `./bin/sandeval run --arm --vector V40,V41,V42,V44`

Each of the four now carries proof of effect rather than only of reach:

| vector | proof | evidence |
|---|---|---|
| V40 | a host binary the policy execute-denies runs from a `memfd` | `/home/qaidvoid/.cache/errand/cargo/bin/cargo-bloat`: direct `execve` `EACCES`, `memfd` copy ran (rc 1, `--version` refused by its own CLI, which proves it executed) |
| V41 | the abstract handshake crosses a process boundary | child pid 18280 served the name, echoed the parent's nonce, exited 0 |
| V42 | a one-line edit to a crate's `build.rs` in the shared cache ran during the next `cargo build` | `ahash-0.8.12`, planted 132 bytes, marker written, `sha256_before == sha256_after` (`d7dd5428...396`), `restored: true` |
| V44 | code runs at a path the execute list does not name | `/state/tmp` and `/tmp` ran the payload (exit 42, same inode `6589973`) while `/state` refused `EACCES`; `/workspace` is named in the list and ran |

V42's proof is armed on purpose: without `--arm` the vector only classifies
the grants and records `"not attempted: re-run with --arm"`. The edit is
written back in a `finally` and the run reports `restored` alongside it, so a
crash mid-run is visible as `restored: false` rather than as a silently
tampered cache.

V39, V40 and V43 were run three times; verdicts and figures were identical in
runs 2 and 3. The first V39 run used a fill loop that gave up on the first
`EAGAIN` and reported a false PASS; the loop now retries for 1 s of stalled
writes before it concludes that nothing is reading. If you change `_fill`,
re-check that against a pipe nobody reads before trusting the result.

## The enforcement model, as measured and as written

Five separate mechanisms, and the battery is only useful if it can tell them
apart. Source refs are errand `24a8a9f` (v0.2.3, 2026-09-29) and bailey
`71473e5` (v0.2.2, 2026-09-21), cloned during this pass; the deployed daemon's
own build is not readable from inside the sandbox.

| layer | what it does | evidence |
|---|---|---|
| Landlock filesystem | read/write/execute lists enforced | `/etc` read `EACCES`, `/state` exec `EACCES`, `/proc/self/oom_score_adj` `EACCES` |
| Landlock `ConnectTcp` | TCP connect allowed only on policy ports plus the broker port | `22`, `8080`, `54321` → `EACCES`; `80`, `443`, `8443` pass; `36821` passes although it is not in `egress_allow` |
| Landlock `BindTcp` | no `bind_ports` in the policy, so every TCP bind is denied | `bind 0.0.0.0:0` and `bind 0.0.0.0:54321` → `EACCES` |
| nftables `bailey_egress` | default-drop output: loopback dropped, the broker accepted, established/related accepted | `127.0.0.1:80` and `1.1.1.1:443` both time out; `169.254.169.1:36821` connects |
| seccomp | one filter, syscall-level | `/proc/self/status` `Seccomp: 2`, `Seccomp_filters: 1` |

Two attribution points that cost a wrong reading if you get them wrong:

- The `EACCES` on a TCP connect is **Landlock**, not seccomp: UDP `connect` to
  the same address and port succeeds, and Landlock's net rule is TCP-only
  (`enforce.rs:629-679`).
- The broker port is added to the allowlist at launch
  (`cli.rs:447-459 permit_broker_port`), so a connect to a port that is not in
  the policy but still passes the syscall layer is the broker path, not an
  open egress rule. The netfilter rule that follows is what actually bounds it
  (`cli.rs:472-493 lock_egress_to_broker`).
- A filesystem grant attaches to the **directory object**, not to the string
  that reached it, so two names for one directory share every rule. The private
  `/tmp` is granted read+write for every isolated world
  (`enforce.rs:619-621`), `AccessFs::from_read()` carries `Execute`
  (`landlock-0.4.7/src/fs.rs:126-130`), and `/tmp` is a bind of the state
  dir's `tmp` subtree. That is why `/state/tmp` executes while `/state` does
  not, which is what V44 measures.

Which network namespace that rule lives in cannot be settled from inside. The
source says so explicitly (`cli.rs:461-469`, note on issue #24). What is
visible here: `/proc/net/dev` shows `wlp13s0` carrying host-scale traffic, and
the local addresses are `10.0.2.15` and `127.0.0.1`, with `169.254.169.1` not
among them. Settling it needs a host-side `nft list ruleset`, outside the
sandbox.

## Session facts the next run needs

- Session `olbbd1h4pm25`, sandbox policy `/state/policy.toml`, generated per
  session by errand. `read` includes `/proc`, `/workspace`, `/state`, the
  shared cargo cache and the toolchains; `write` is `/workspace`, `/state` and
  `$CARGO_HOME`; `execute` adds `/state/home/bin` but not `/state` itself and
  not the cargo cache. What that list does not say: the state root refuses
  `exec` and the state `tmp` subtree grants it (V44), because the same
  directory is also `/tmp`.
- `HTTP(S)_PROXY=http://169.254.169.1:36821`, `NO_PROXY=169.254.169.1`,
  `egress_allow` ports `80, 443, 8443`.
- Fresh pipes in this host are not always 64 KiB: `F_GETPIPE_SZ` reported
  65536 in one process and the control pipe inside a run reported 8192 in
  another. V39 compares against its own control for exactly that reason, so
  the verdict does not depend on the number.
- pid 1 is `pi`, in this mount namespace, `CapEff=0`, `NoNewPrivs=1`. It does
  not reap orphans: `sh <defunct>` was parked under it during this pass.
- The harness has no built-in grep/glob here; system `grep` does work in a
  shell. Python is 3.14: `os.memfd_create` exists, `os.execveat` does not, so
  V40 goes through `libc().syscall` with the per-arch number.
- Vectors run by the harness are `python3 bin/sandeval run ...`; `run.sh`
  additionally runs the sweep. `--arm` is what makes V5 write its marker into
  pid 1's stdio, so run it only when that injection is wanted.

## Leads that are not vectors yet

Each says what would settle it, so the next session does not have to work it
out again.

1. **Orphan reaping.** pi leaves zombie children under pid 1 instead of
   reaping them. Not a vector because the effect is irreversible from inside
   (you cannot un-zombie a process). Settle with a host-side
   `ps -o pid,stat,comm` before and after a session that forks and exits.
2. **Whether the `bailey_egress` table is host-wide.** Needs `nft list ruleset`
   as root on the host, or a second sandbox whose egress differs. Until then,
   report it as "installed in the namespace this process is in".
3. **Why the abstract-socket scope did not hold.** bailey asks for
   `Scope::from_all` best-effort (`enforce.rs:647-650`) and the docs say an
   older kernel drops the request along with the protection
   (`bailey/docs/guide/network.md:138-143`). Run `V25` for the ABI number, or
   bailey's own `report` subcommand on the host, to see whether ABI 6 was
   available. If it was, the scope rule itself is the defect.
4. **V37's bind note vs today.** `docs/findings.md` records "TCP bind
   SUCCEEDED at `0.0.0.0:54321`"; today both an ephemeral and a fixed bind
   return `EACCES`. Either the policy gained a `[network]` section between
   those dates (which turns `handle_bind` on, `enforce.rs:594`) or the old note
   was taken under a different profile. Re-run with the older policy to tell
   them apart.
5. **Broker nonce replay.** Needs brokering armed; it was not armed in this
   session, so the experiment could not be run from inside.
6. **Confirm the forged record posted.** V39 measures the channel and one
   `message_end` was written into `/proc/1/fd/1` after the push on 2026-09-29.
   Acceptance is not observable from inside (pi's transcript holds no
   `message_end` records), so this settles only by the operator seeing the
   line in the thread. If it did not appear, the next suspect is the session
   state at `client.rs:895` rather than the record shape.
7. **Does the private `/dev/shm` grant execute too?** `add_world_grants`
   grants read+write on the private `/dev/shm` under the same
   `from_read | from_write` expression (`enforce.rs:611` and `:622-625`), so a
   payload there should behave like V44's `/tmp` case. Cheap to measure, not
   yet run.
8. **How far the alias reaches.** V44 compares one pair of names. The general
   question is which other writes in the policy are aliases of an
   execute-granted directory, which needs the full bind table resolved to
   device and inode and compared pairwise.

## Adding a vector

1. Copy the nearest vector in `vectors/` and keep the contract from
   `sandeval/base.py`: an `id` of the form `V<n>`, `title`, `severity`,
   `maps_to`, `description` (a module docstring), `check(ctx)`, optional
   `cleanup(ctx)`.
2. Use the helpers in `vectors/_common.py` (`visible_pids`, `fd_inventory`,
   `marker`, `libc`) rather than shelling out; the harness has no system tools
   of its own.
3. Extend `EXPECTED_IDS` in `tests/test_harness.py`, then run the gates:
   `bash -n` over `bin/sandeval`, `run.sh`, `sweep/landlock-surface-sweep.sh`
   and `host-verify/verify.sh`; `python3 tests/test_harness.py`;
   `bash tests/run-tests.sh`; `./bin/sandeval list` and `list --json`.
4. Set `host_global = True` when the probe leaves an observable trace outside
   the workspace: `--safe` skips it, and CI relies on that.
5. Record the measured result in `docs/findings.md` as a new dated pass, and
   update the table in `README.md`.
