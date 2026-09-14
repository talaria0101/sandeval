"""Actionable advice per vector, rendered into reports.

Kept centrally (rather than in each vector class) so the operator-facing
wording lives in one place and stays consistent across the markdown and JSON
reports. Every entry answers the two questions a report must answer after a
FAIL or SUSPECTED: why should someone care, and what changes makes it go away.
Advice is keyed by vector id; unknown ids fall back to a generic entry so a
new vector never breaks report rendering.
"""

ADVICE = {
    "V1": {
        "why": "Landlock has no access right for chmod/utimes/setxattr, so the agent can rewrite host file metadata and stash bytes in host inodes even where it cannot write content.",
        "fix": "Mount the read roots read-only (bind-mount ro or drop the write bit on the host dirs). No sandbox rule fixes this; it is a mount-time property.",
    },
    "V2": {
        "why": "A 64 KiB payload per file is a covert storage channel in host inodes that survives the session and bypasses content audits.",
        "fix": "Same as V1: read-only mounts for every host path the policy lets the agent read. host-verify/verify.sh --clean removes this vector's markers.",
    },
    "V3": {
        "why": "World-writable /tmp and /dev/shm are staging areas and cross-session drop boxes outside the declared write list.",
        "fix": "Mount a private tmpfs over /tmp and /dev/shm per sandbox instance, or add them to the write list deliberately if shared temp is intended.",
    },
    "V4": {
        "why": "Any /proc/<pid>/environ read exposes every secret the daemon carries; token-shaped names were found here.",
        "fix": "Keep secrets out of the daemon's environment (file-based secret store the policy cannot read), and run the daemon under a different uid than the agent so its /proc files are not same-uid readable.",
    },
    "V5": {
        "why": "Write access to the orchestrator's stdio means the agent can inject output into the control channel the operator sees.",
        "fix": "Have the daemon set PR_SET_DUMPABLE(0) so its /proc/<pid>/fd entries become root-owned, or run it in a separate pid namespace / uid from the agent.",
    },
    "V6": {
        "why": "clone(CLONE_NEWUSER) hands the caller a full capability set inside a new namespace: the standard launchpad for container escapes.",
        "fix": "Seccomp-deny namespace creation: clone/clone3 with CLONE_NEWUSER in the flag mask (plus unshare/setns, already denied here).",
    },
    "V7": {
        "why": "A TCP-port allowlist without UDP filtering still allows DNS-style exfiltration to arbitrary hosts.",
        "fix": "Enforce the allowlist in netfilter for both protocols, then encode it here with SANDEVAL_ALLOWED_TCP/UDP and confirm against a canary.",
    },
    "V8": {
        "why": "The daemon executes the repo's git hooks and credential helpers on the host: a writable workspace is host code execution at turn end.",
        "fix": "Run the daemon's git with --no-verify and a hooks path outside the workspace (core.hooksPath to a root-owned dir), a clean global config (GIT_CONFIG_GLOBAL), and keep pull-request gating outside the agent-writable state dir.",
    },
    "V9": {
        "why": "The denylist is the last line against kernel-interface attacks; a silent gap here invalidates every other denial.",
        "fix": "None needed while it passes; re-run after every kernel or filter change.",
    },
    "V10": {
        "why": "Without memory and pid ceilings a runaway or malicious agent can OOM the host or exhaust pids for everything else on it.",
        "fix": "Set cgroup v2 memory.max and pids.max for the sandbox subtree; add RLIMIT_NPROC/RLIMIT_AS as an in-process backstop.",
    },
    "V11": {
        "why": "inotify watches on out-of-policy trees leak file names and activity timing to the agent.",
        "fix": "Landlock has no inotify right; if the leak matters, move sensitive trees onto a mount the policy denies entirely, or accept it as known telemetry.",
    },
    "V12": {
        "why": "Content reads of denied files are the direct confidentiality break; everything else is a stepping stone to this.",
        "fix": "On FAIL: tighten the read list to exact subtrees, reject symlinked targets, and re-test with an operator-seeded file (--seed /path) so the vector stops skipping.",
    },
    "V13": {
        "why": "Speculative-execution gaps let a process read memory across sandbox boundaries; no path policy can substitute for the kernel mitigations.",
        "fix": "Keep default mitigations (never boot shared hosts with mitigations=off) and keep CPU microcode current.",
    },
    "V14": {
        "why": "A reproduced bounds-check bypass means the CPU leaks memory the policy assumes is separated.",
        "fix": "Platform problem, not policy: apply kernel/microcode updates and isolate untrusted workloads from anything secret on the same core package.",
    },
    "V15": {
        "why": "Relaxed kernel knobs (kptr, dmesg, ASLR) turn small leaks into exploit primitives.",
        "fix": "On the host: kernel.kptr_restrict=2, kernel.dmesg_restrict=1, randomize_va_space=2. The sandbox cannot set these for itself.",
    },
    "V16": {
        "why": "Readable peer memory maps give an attacker exact targets for the read/write primitives other vectors prove.",
        "fix": "Run the agent under its own uid and mount procfs with hidepid=2 and subset=pid so same-uid peers are not enumerated.",
    },
    "V17": {
        "why": "Writable cgroup controls are a known root-escape path (release_agent) and allow the agent to re-aim resource limits.",
        "fix": "Mount the cgroup filesystem read-only inside the sandbox; grant write on cgroup keys only to the host-side manager.",
    },
    "V18": {
        "why": "Anything planted in a persistent location executes or influences the next session, even if this session behaved.",
        "fix": "Give caches and the workspace fresh storage per session, or integrity-check them (hash pinning) before the next instance trusts them.",
    },
    "V19": {
        "why": "A check-then-use window would let a symlink swap redirect a privileged open.",
        "fix": "None needed while Landlock resolves at operation time; keep in the battery as a regression check.",
    },
    "V20": {
        "why": "Readable credential files are one config mistake away from full token theft.",
        "fix": "Mount a scrubbed HOME inside the sandbox (no .gitconfig/gh/netrc), or use a credential helper whose socket the policy denies; keep the daemon's tokens out of shared config entirely.",
    },
    "V21": {
        "why": "pidfd_getfd duplicates any same-uid process's descriptors silently: stdio, sockets, config files become the agent's to read or write.",
        "fix": "Seccomp-deny pidfd_open (434) and pidfd_getfd (438); alternatively run the daemon under a different uid or set PR_SET_DUMPABLE(0).",
    },
    "V22": {
        "why": "chroot(2) plus a descriptor outside the cage is the classic root-escape walk; it is harmless only while Landlock is the real control.",
        "fix": "Seccomp-deny chroot (161) unless something in the sandbox genuinely needs it, and never rely on a changed root as the confinement boundary.",
    },
    "V23": {
        "why": "Working ptrace means arbitrary code injection into and memory reads of same-uid peers.",
        "fix": "None needed while filtered; keep ptrace (101/117) in the denylist alongside process_vm_readv/writev.",
    },
    "V24": {
        "why": "Async I/O paths have historically lagged policy hooks, so an io_uring bypass would void the file policy while looking identical to openat.",
        "fix": "While it holds, re-test after every kernel upgrade. On FAIL: seccomp-deny io_uring_setup (425) and io_uring_enter (426), or set /proc/sys/kernel/io_uring_disabled=2 (kernel 6.6+).",
    },
}

DEFAULT = {
    "why": "",
    "fix": "Review the finding and re-run this vector after any control change.",
}


def for_id(vector_id: str) -> dict:
    entry = dict(ADVICE.get(vector_id, DEFAULT))
    entry.setdefault("why", DEFAULT["why"])
    entry.setdefault("fix", DEFAULT["fix"])
    return entry
