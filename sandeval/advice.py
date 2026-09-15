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
        "why": "Without memory and pid ceilings a runaway or malicious agent can OOM the host or exhaust pids for everything else on it; unbounded RLIMIT_MEMLOCK lets it pin host memory, and the free-space figure says how much disk one turn can fill.",
        "fix": "Set cgroup v2 memory.max and pids.max for the sandbox subtree; add RLIMIT_NPROC/RLIMIT_AS/RLIMIT_MEMLOCK as in-process backstops; give the writable path a size quota (sized filesystem or loopback image).",
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
    "V25": {
        "why": "The gap between what the Landlock kernel supports (net hooks, ioctl right) and what the policy uses is exactly where the policy is thinnest; this is the map an attacker draws first.",
        "fix": "Measurement, not a break: on a kernel with ABI >= 4 add Landlock TCP bind/connect rules to the policy so network confinement stops depending on seccomp alone.",
    },
    "V26": {
        "why": "openat2 is the newer VFS entry point; a filter or hook covering only openat leaves the replacement path wide open.",
        "fix": "On FAIL: add openat2 (437) to the seccomp denylist, or rely on the LSM file-open hook (which covers both) after verifying with this vector.",
    },
    "V27": {
        "why": "Raw, packet and netlink sockets have no port for a TCP allowlist to filter: raw ICMP is a ready exfil channel, AF_PACKET grants L2 sniffing, and a uevent-group bind is a live feed of host device events (spoofable with CAP_NET_ADMIN).",
        "fix": "Drop CAP_NET_RAW and CAP_NET_ADMIN from the sandbox, and seccomp-deny socket() for AF_PACKET and AF_NETLINK plus SOCK_RAW; keep egress enforcement in netfilter for all protocols.",
    },
    "V28": {
        "why": "SysV IPC has no namespace by default, so on a shared kernel the agent can attach same-uid (or, as root, any) host segments and read live process memory through an interface no path policy mediates.",
        "fix": "Create the sandbox in a new IPC namespace (clone(CLONE_NEWIPC)/unshare -i) or seccomp-deny shmget/shmat; prefer POSIX shm under a policy-controlled directory.",
    },
    "V29": {
        "why": "A duplicated foreign write descriptor lets the agent write into the orchestrator's own stdout pipe: the control plane consumes attacker bytes. Delivery to the operator transcript depends on daemon framing - verify.sh greps the session log for the marker; on the reference deployment the pipe accepted the write but no injected line was observed in the transcript.",
        "fix": "Run the agent in its own PID namespace, or drop the daemon's privileges so its fds are not ptrace-reachable from the agent uid; seccomp-deny pidfd_open/pidfd_getfd as a belt-and-braces.",
    },
    "V30": {
        "why": "link(2) governs the destination directory, so a hardlink re-roots a foreign inode inside the write-granted tree: reads and appends through the new name are workspace operations on a host file. One EPERM (fs.protected_hardlinks) is the only thing stopping this on most hosts.",
        "fix": "Keep fs.protected_hardlinks=1 host-wide; put the workspace on its own filesystem so cross-boundary links fail with EXDEV structurally; keep read-granted host trees on a different filesystem than the workspace.",
    },
    "V31": {
        "why": "open_tree/move_mount are the new mount API: they need only CAP_SYS_ADMIN over the owning user namespace, and where clone(CLONE_NEWUSER) succeeds they re-root a foreign file inside the workspace so Landlock grants what it refused at the original path.",
        "fix": "Seccomp-deny clone/clone3 with CLONE_NEW* flags (the V6 fix - it removes the capability source), and deny open_tree/move_mount/fsopen/fsmount/fspick/mount_setattr by number so the new API cannot be reached even from a privileged namespace.",
    },
    "V32": {
        "why": "Same-uid process control is outside every path policy: SIGSTOP, nice and OOM-tuning against the orchestrator are one syscall each, and with a pipe core_pattern the crash chains to host-root code (V37).",
        "fix": "Run the daemon under a different uid than the agent (or in its own PID namespace); seccomp-deny kill/tgkill/pidfd_send_signal and setpriority toward other processes if the uid split is impossible.",
    },
    "V33": {
        "why": "Reading the daemon's memory is the strongest confidentiality primitive at the same uid: on the reference deployment it re-recovers the sandbox's own credential from the stack through /proc/1/mem alone (route-independent of the environ read), and a 100MB+ scan found no additional secrets - the primitive is proven; the extra payload depends on what the daemon keeps only in memory.",
        "fix": "Set the daemon non-dumpable (PR_SET_DUMPABLE(0)) or run it as another uid; keep yama ptrace_scope >= 1; seccomp-deny process_vm_readv/writev AND consider filtering open of /proc/<pid>/mem via a supervisor, since seccomp cannot inspect the path.",
    },
    "V34": {
        "why": "AF_UNIX connects are not mediated by Landlock (ABI 1-3 have no socket right at all): docker/containerd sockets are a container escape, ssh/gpg agent sockets are signing oracles for host keys, and a writable parent directory lets the next run replace the socket entirely.",
        "fix": "Move runtime and agent sockets out of directories the sandbox can see or write; run container runtimes on a root-owned socket (never the agent uid); keep agent sockets in per-session directories with 0700.",
    },
    "V35": {
        "why": "The file that draws the sandbox boundary lives inside the boundary and is write-openable: a tamper primitive, not yet a control swap. errand regenerates the file per session (observed), so persistence is unproven - the attack window is whatever gap exists between generation and the sandbox's read of it.",
        "fix": "Serve the policy to the sandbox from outside the write-granted set (a bind-mounted ro file, a root-owned location, or an in-memory config); never store the effective policy in the agent's state dir.",
    },
    "V36": {
        "why": "perf_event_open at paranoid<=0 measures other processes: a timing side channel aimed at the orchestrator, and the missing ingredient for a practical exploit against an unmitigated CPU (V13/V14). Keyring, userfaultfd and bpf are the other standard escalation doors.",
        "fix": "Keep kernel.perf_event_paranoid >= 2, vm.unprivileged_userfaultfd = 0; deny perf_event_open, bpf, add_key/keyctl and userfaultfd in the filter (they are never needed by build tooling).",
    },
    "V37": {
        "why": "A pipe core_pattern runs a host-root handler on every crash of any process; the daemon is crashable from inside when V32 holds. The chain turns a DoS primitive into host-root code execution with the daemon's memory as input.",
        "fix": "Point kernel.core_pattern at a file path (not a pipe) on shared hosts, or ensure the daemon is not signallable from the agent uid (V32's fix); keep RLIMIT_CORE at 0 inside the sandbox.",
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
