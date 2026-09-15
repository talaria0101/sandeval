# Gap analysis — bailey + errand, source-grounded (2026-09-15)

Written after reading the current errand and bailey sources and the deployed
behaviour of this host, with sandeval's battery as the probe set. This is the
answer to "what is still left": what is fixed, what is by design, and what
remains open, ranked by blast radius.

## Deployed versions, inferred empirically

- bailey includes 572899a (new mount API denied: open_tree/move_mount EPERM),
  51a30ab (x32/int-0x80 syscalls refused with EPERM, measured), bbccb4a
  (UTS namespace), 6bccff8+ (private netns). Whether 92fa57e (map the
  caller's uid) is deployed is not decidable from inside: the cage runs as
  uid 0, which the fix forbids unless the daemon itself runs as root.
  Host-side check: the agent's uid inside the cage should equal the daemon
  user's uid on the host.
- errand includes aabf107 (the pull-request push runs from a fresh bare
  clone, `pushWork`; the pre-push trap did not fire at the last turn end,
  and the request file was consumed). It predates af33d66/1c2946e: the
  provider credential is still passed into the sandbox (`[env] pass`),
  where the egress broker would keep it out.

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

## 2. The provider credential still rides in the sandbox env (medium, deploy)

`ZAI_CODING_CN_API_KEY` is in the session environment. Upstream errand
already fixed this class (af33d66 "keep the provider credential out of the
sandbox", 1c2946e/384a7ee brokered provider egress), but the deployed
daemon predates it. Deploy current errand and the sandbox stops holding a
second spendable secret.

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
- Direct egress: every TCP connect denied at the seccomp/connect level,
  both families; all egress rides the proxy, which enforces the port
  allowlist (CONNECT 22/9999 refused, 443 allowed). Loopback inside the
  cage answers from the proxy catch-all, not the host.
- PID/UTS namespaces: the errand daemon is invisible from inside, which
  retires the V29/V32/V33 process-control class on this deployment (the
  vectors remain for sandboxes without a PID namespace).
- btrfs subvolume ioctls: denied (587fc6f).

## 5. Remaining leads, ranked

1. Token scoping (this document, section 1) - the only finding with
   account-level blast radius.
2. Deploy errand past af33d66 so the provider credential leaves the env.
3. Host-side: confirm the bailey build is >= v0.1.4 and that the daemon
   user is not root (the cage's uid 0 should map from the daemon uid).
4. sandeval: keep V8/V31/V33-style regression vectors armed; the battery is
   now the check that deployed == source where it matters.
