# Gap analysis — bailey + errand, source-grounded (2026-09-15, revised 2026-09-29)

Written after reading the current errand and bailey sources and the deployed
behaviour of this host, with sandeval's battery as the probe set. This is the
answer to "what is still left": what is fixed, what is by design, and what
remains open, ranked by blast radius.

The 2026-09-29 revision re-ran the battery (V5, V7, V37 and the new V39-V43)
and re-read the sources at errand `24a8a9f` (v0.2.3) and bailey `71473e5`
(v0.2.2). Sections 2 and 4 changed as a result; section 5 gained the
path-less leads. `docs/path-less-surface.md` carries that pass in detail.

## Deployed versions

- Sources read at errand `24a8a9fcade4504162b5103b97e64c54997ed453` (v0.2.3,
  2026-09-29) and bailey `71473e540ba19c41a5d287ba93d57b84e8cc1bc2` (v0.2.2,
  2026-09-21). The build actually running as the daemon is not readable from
  inside the sandbox, so behaviour below is measured, not assumed from these
  commits.
- Still not decidable from inside: whether `92fa57e` (map the caller's uid) is
  deployed. Host-side check: the agent's uid inside the cage should equal the
  daemon user's uid on the host.

## 1. The GitHub token is the blast radius (high, actionable)

`github.ts` says: "Treat the token as known to the agent, and scope it on
that basis." Measured: the token errand hands the session carries
`repo, workflow` on the bot's user account. Consequences, none of which
require escaping the sandbox:

- `repo` is read/write on every repository the account can access, public
  and private. One prompt injection in any repository the agent works on
  (a poisoned build file, a malicious README the agent reads) converts into
  disclosure or destruction of the operator's whole GitHub footprint.
- `workflow` allows rewriting GitHub Actions workflows, which is arbitrary
  code execution on the account's runners, where org-level secrets live.

The sandbox holds; the credential walks out through egress that is allowed
by design (443, host=*). Fix: errand should mint a per-session fine-grained
token (or a GitHub App installation token) scoped to the one repository the
session works on, contents:read/write, expiring with the session. The
credential helper already reads an env var; swapping the value it gets is a
small change. sandeval now measures this on every run (V20 reports the
scope names and flags high-blast scopes).

## 2. The provider credential no longer rides in the sandbox env (fixed, verified 2026-09-29)

This section said `ZAI_CODING_CN_API_KEY` was in the session environment.
Measured on 2026-09-29: it is not. `[env] pass` is `GH_TOKEN`, `GIT_AUTHOR_*`,
`GIT_COMMITTER_*` and `PI_OFFLINE`; `~/.pi/agent/auth.json` and
`models-store.json` are both `{}`; no provider key appears anywhere in the
environment. Upstream's af33d66/1c2946e fix is what this looked like from the
other side. No action.

Residual, unrunnable from inside: the broker nonce-replay experiment needs
brokering armed, and it was not armed in this session.

## 3. The pull-request gate is a request, not a wall (accepted, document it)

`pull-request.txt` in the agent-writable state dir, upstream read from the
agent's own origin: the agent can point origin at any public repository and
have the bot fork it and open a pull request whose body is the agent's
commit message. One per turn, gated by a file the agent writes itself. The
source is explicit that this is a request, not a wall; the residual risk is
bot-identity abuse on third-party repositories. Worth an operator-facing
note, not a code change.

## 4. Fixed and now empirically verified by sandeval (no action)

- errand#2 / V8: `pushWork` pushes from a fresh `--shared --bare` clone in
  a temp dir; SAFE_CONFIG strips hooks, credential helpers, fsmonitor;
  SAFE_ENV strips global/system config. The trap armed at 2026-09-15T03:25Z
  did not fire; the request file was consumed and no hook ran.
- x32/int-0x80 seccomp bypass: refused (EPERM), arch guard live.
- New mount API (open_tree/move_mount/fsopen/fsconfig/mount_setattr):
  denied. Classic mount(2): denied.
- Direct egress: no direct path, and the layers are now told apart (V43,
  2026-09-29). TCP connect to a port outside the allowlist is refused
  `EACCES` by Landlock `ConnectTcp` (`enforce.rs:629-679`), not by seccomp;
  allowed ports pass the syscall layer and are then dropped by the
  `bailey_egress` nftables chain (`cli.rs:472-493`); UDP `connect` is
  unfiltered, as bailey documents. Every TCP `bind` is denied because the
  policy has no `bind_ports`. The broker port is added to the allowlist at
  launch (`cli.rs:447-459`), so a passing connect to an unlisted port is the
  broker path, not open egress.
- PID/UTS namespaces: the errand daemon is invisible from inside, which
  retires the V29/V32/V33 process-control class on this deployment (the
  vectors remain for sandboxes without a PID namespace). What is still
  visible is the sandbox's own orchestrator: pid 1 is `pi`, in this mount
  namespace, and its stdio descriptors are reachable through `/proc` (V5,
  V39).
- btrfs subvolume ioctls: denied (587fc6f).

## 5. Remaining leads, ranked

1. The write channel into the orchestrator's stdout pipe (V39, ship-blocker):
   measured delivery, and the code path from a forged line to a host effect is
   read at `client.rs:708`. Fix is structural - keep the orchestrator out of
   the sandbox's `/proc`, or give it a socket rather than a pipe.
2. The execute list does not cover `memfd` execution (V40): fix with seccomp
   on `memfd_create`, `execveat(AT_EMPTY_PATH)` and `execve` under
   `/proc/*/fd`.
3. Token scoping (this document, section 1) - still the only finding with
   account-level blast radius.
4. The shared `$CARGO_HOME` write grant (V42): one tree across sessions, and
   code written there runs on the next build.
5. Abstract unix sockets bind and accept (V41): check the Landlock ABI, or
   isolate the network namespace.
6. Host-side: confirm the bailey build is >= v0.1.4, that the daemon user is
   not root (the cage's uid 0 should map from the daemon uid), and
   `nft list ruleset` to see which namespace holds `bailey_egress`.
7. Re-run with the pre-`[network]` policy to settle whether V37's recorded bind
   success or today's `EACCES` is the older state.
8. sandeval: keep V8/V31/V33-style regression vectors armed; the battery is
   now the check that deployed == source where it matters.
