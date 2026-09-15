#!/usr/bin/env bash
# landlock-surface-sweep.sh — v3, exhaustive bailey/Landlock policy battery.
#
# PURPOSE
#   Verify (not attack) sandbox enforcement. Every probe is a minimal, benign
#   operation whose ALLOW/DENY verdict is the entire result. Designed to run
#   INSIDE THE DISPOSABLE SANDBOX UNDER TEST, with auditd/strace alongside for
#   per-syscall ground truth. Pair with redteam-eval-harness.md for the
#   agentic layer.
#
# SAFETY
#   * All scratch lives under the in-policy dir — never /tmp — in a fresh
#     per-run ".landscan" subdir that is removed on exit (idempotent re-runs).
#   * Kernel-knob probes write the CURRENT value back: proves writability
#     without mutating host kernel state (full value, never truncated).
#   * Network checks are informational by default (they measure channel
#     openness, not enforcement). Encode site intent with --expect.
#   * swapon / SysRq / clock_settime probes are opt-in env gates (they are
#     host-global mutations if a sandbox allows them).
#   * Run AS THE AGENT USER, never root — root makes many deny-checks
#     meaningless (running as root is itself a finding).
#
# VERDICTS
#   allow / deny / inconclusive (ENOENT, EOPNOTSUPP, EINVAL, exec-failure,
#   timeout ... — anything that cannot be attributed to policy). Inconclusive
#   NEVER counts as a pass: want=deny/allow vs inconclusive is flagged [??].
#   Silence inconclusive-noise for paths your platform lacks via --expect.
#   Egress TCP probes record open/closed as the verdict.
#   DETAIL text is scrubbed: tabs/newlines flattened, secret-shaped
#   "…TOKEN=…" values redacted (baselines are committed artifacts).
#
# USAGE
#   landlock-surface-sweep.sh [IN] [OUT] [opts]   # everything else is automatic
#     IN   optional: defaults to $PWD (or LANDSCAN_IN)
#     OUT  optional: auto-discovered — first existing write-denied dir
#          (candidates: /opt /var/tmp /mnt /srv /run /media /tmp), else /tmp
#     --safe           skip host-global probes (sysrq 'h', swapon, clock_settime)
#     --adopt          bless this run's verdicts as the expected baseline (kills
#                      platform-shape noise on future runs)
#     --baseline FILE  default: auto-managed .landscan-state/latest.tsv in $PWD
#     --check FILE     default: auto-diffs against the previous run's baseline
#     --expect FILE    default: .landscan-state/expect.tsv when present
#     -v               echo each probe command
#   Env overrides: LANDSCAN_IN OUT STATE SAFE CANARY MEMHOG_MB FILL_MB PIDS_PROBE
#   Heuristics (no flags needed): memhog = 1.25x cgroup memory.max (else 2% of
#   RAM, clamped 256-1024MB); disk-fill = 2% of free space (64-2048MB); pids
#   ceiling from cgroup v2/v1; egress canary defaults to canary.invalid.
#
# EXIT: 0 all as expected · 1 unexpected/inconclusive verdicts · 2 usage/setup error

set -u
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"   # fresh agents love `sh script`: refuse dash, re-exec bash
die(){ echo "ERROR: $*" >&2; exit 2; }
have(){ command -v "$1" >/dev/null 2>&1; }
sec(){ echo; echo "=== $* ==="; }

IN=""; OUT=""; BASELINE=""; CHECK=""; EXPECT=""; VERBOSE=0; SAFE=${LANDSCAN_SAFE:-0}; ADOPT=0
usage(){ grep -m1 -A110 '^# USAGE' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
while [ $# -gt 0 ]; do case "$1" in
  -v|--verbose) VERBOSE=1;;
  --safe) SAFE=1;; --adopt) ADOPT=1;;
  --baseline) [ $# -ge 2 ] || usage; BASELINE="$2"; shift;;
  --check)    [ $# -ge 2 ] || usage; CHECK="$2"; shift;;
  --expect)   [ $# -ge 2 ] || usage; EXPECT="$2"; shift;;
  -h|--help) usage;;
  -*) echo "unknown opt $1" >&2; usage;;
  *) if [ -z "$IN" ]; then IN="$1"; elif [ -z "$OUT" ]; then OUT="$1"; else die "unexpected argument: $1"; fi;;
esac; shift; done
# --- defaults & heuristics: zero flags must work ---
STATE=${LANDSCAN_STATE:-$PWD/.landscan-state}
[ -z "$IN" ] && IN=${LANDSCAN_IN:-$PWD}
if [ -z "$OUT" ]; then
  OUT=${LANDSCAN_OUT:-}
  if [ -z "$OUT" ]; then
    for c in /opt /var/tmp /mnt /srv /run /media /tmp; do   # auto-discover a real out-of-policy boundary
      [ -d "$c" ] || continue
      if ! touch "$c/.ls-probe" 2>/dev/null; then OUT=$c; break; fi
      rm -f "$c/.ls-probe" 2>/dev/null
    done
    [ -z "$OUT" ] && { OUT=/tmp; echo "NOTE: no write-denied dir found — OUT=/tmp; out-of-policy checks will show allows (that IS the finding)." >&2; }
  fi
fi
if [ -z "$EXPECT" ] && [ -f "$STATE/expect.tsv" ]; then EXPECT="$STATE/expect.tsv"; fi
if [ -z "$BASELINE" ]; then
  mkdir -p "$STATE" 2>/dev/null
  if [ -f "$STATE/latest.tsv" ] && [ -z "$CHECK" ]; then CHECK="$STATE/latest.tsv"; fi
  BASELINE="$STATE/latest.tsv"
fi
RIN=$(readlink -m "$IN" 2>/dev/null || echo "$IN")
ROUT=$(readlink -m "$OUT" 2>/dev/null || echo "$OUT")
case "$ROUT" in "$RIN"|"$RIN"/*) die "OUT must be outside the policy (not under IN)";; esac
[ -d "$OUT" ] || die "outside-policy dir '$OUT' must already exist"

declare -A WANT GOT DETAIL OVR=() OLD=()
ORDER=(); UNEX=0; UNEXLIST=""
if [ -n "$EXPECT" ]; then
  [ -r "$EXPECT" ] || die "--expect file '$EXPECT' not readable"
  while read -r n w; do [ -n "${n:-}" ] && OVR[$n]="$w"; done < "$EXPECT"
fi
if [ -n "$CHECK" ]; then
  [ -r "$CHECK" ] || die "--check baseline '$CHECK' not readable (typo? see --baseline to create one)"
  while IFS=$'\t' read -r n g d; do [ -n "${n:-}" ] && OLD[$n]="$g"; done < "$CHECK"   # load pre-run: baseline may be overwritten after
fi
if [ -n "$BASELINE" ]; then
  : > "$BASELINE" || die "--baseline '$BASELINE' not writable"
fi
# validation done — only now touch the filesystem
mkdir -p "$IN" || die "cannot create in-policy dir '$IN'"
[ -d "$IN" ] && [ -w "$IN" ] || die "in-policy dir '$IN' is not writable by $(id -u 2>/dev/null)"

SCRATCH="$IN/.landscan"                          # fresh per run; removed by trap
SAN="$SCRATCH/sanity"                            # creation-class probes live here (idempotent)
HELPER="$SCRATCH/helper"
PATH="$PATH:/sbin:/usr/sbin"                     # btrfs/mkswap/swapoff often live here
have timeout || timeout(){ local t=$1; shift; "$@"; }   # degrade gracefully w/o coreutils-timeout
OUT_WAS_MNT=0; mountpoint -q "$OUT" 2>/dev/null && OUT_WAS_MNT=1  # never unmount pre-existing mounts
SEED="$OUT/seedfile"                             # operator-seeded out-of-policy file (see README)
# REVIEW NOTE: run this script AS THE AGENT USER, never root — root makes every
# deny-check meaningless (running as root is itself a finding; see README).

line(){ # $1=name — classify using override if present
  local n=$1
  local w=${OVR[$n]:-${WANT[$n]}} g=${GOT[$n]} s
  if [ "$w" = info ]; then s="[ii]"
  elif [ "$g" = "$w" ]; then s="[ok]"
  else s="[!!]"; UNEX=$((UNEX+1)); UNEXLIST="$UNEXLIST $n"; fi
  printf '%s %-28s want=%-12s got=%-12s %s\n' "$s" "$n" "$w" "$g" "${DETAIL[$n]:-}"
}
rec(){ # name want got detail — DETAIL flattened + secret-scrubbed (baselines get committed)
  local n=$1
  ORDER+=("$n"); WANT[$n]="$2"; GOT[$n]="$3"
  DETAIL[$n]=$(printf '%s' "${4:-}" | tr '\t\n\r' '   ' \
    | sed -E 's/([A-Za-z0-9_]*(token|secret|key|passwd|password|credential|auth)[A-Za-z0-9_]*=)[^ ]*/\1[REDACTED]/Ig')
  line "$n"
}
check(){ # name want cmd... — verdict from rc + errno-shaped output sniffing
  local n=$1 want=$2; shift 2
  [ $VERBOSE = 1 ] && echo "  \$ $*"
  local out rc got d
  out=$(timeout 15 "$@" 2>&1); rc=$?
  got=inconclusive; d=""
  if [ $rc -eq 0 ]; then got=allow
  elif [ $rc -eq 124 ] || [ $rc -eq 137 ]; then d="timeout-or-killed"
  elif [ $rc -eq 126 ] || [ $rc -eq 127 ]; then d="exec-failure(cmd missing?)"
  elif printf '%s' "$out" | grep -qiE 'permission denied|operation not permitted|not permitted|read-only file system'; then got=deny
  elif printf '%s' "$out" | grep -qiE 'no such file or directory|invalid argument|operation not supported|not supported|function not implemented|file exists|is a directory|not a directory|invalid superblock|unknown filesystem|device or resource busy|resource temporarily unavailable|exec format error|no space left|disk quota exceeded'; then : # stays inconclusive
  else got=deny; d="unattributed-rc$rc"           # failed with unrecognizable error: treat as deny
  fi
  local tailmsg; tailmsg="$(printf '%s' "$out" | tail -n1 | head -c 90)"
  d="${d:+$d }$tailmsg"
  rec "$n" "$want" "$got" "$d"
}
hcheck(){ # name want helper-args... — verdict = first word of helper output
  local n=$1 want=$2; shift 2
  if [ ! -x "$HELPER" ]; then rec "$n" info skip "helper-unavailable(no cc)"; return; fi
  [ $VERBOSE = 1 ] && echo "  \$ helper $*"
  local out got
  out=$(timeout 25 "$HELPER" "$@" 2>&1)
  got=$(printf '%s' "$out" | awk '{print tolower($1);exit}')
  case "$got" in allow|deny|inconclusive) ;; *) got=inconclusive; out="unparseable: $out";; esac
  rec "$n" "$want" "$got" "$out"
}
kwriteback(){ # name path — write FULL current value back; writability w/o mutation
  local n=$1 p=$2 cur
  cur=$(cat "$p" 2>/dev/null; printf x); cur=${cur%x}   # preserves trailing newline
  if [ -z "$cur" ]; then rec "$n" deny inconclusive "unreadable-empty-cannot-test"; return; fi
  if [ ${#cur} -gt 4096 ]; then rec "$n" deny inconclusive "value>${#cur}B-skipped"; return; fi
  if printf '%s' "$cur" > "$p" 2>/dev/null; then rec "$n" deny allow "write-back-same-value(${#cur}B)"
  else rec "$n" deny deny "write-back refused"; fi
}
# heuristic resource sizing — env overrides still win
mem_target_mb(){
  local mm mt
  mm=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo max)
  case "$mm" in ''|max|*[!0-9]*) mm=0;; esac
  [ "$mm" -gt 137438953472 ] 2>/dev/null && mm=0            # absurd cap = unlimited
  if [ "$mm" -gt 0 ] 2>/dev/null; then
    mt=$(( mm / 1048576 * 125 / 100 ))                       # 1.25x the limit: must exceed it to see the kill
    echo $(( mt < 64 ? 64 : mt > 8192 ? 8192 : mt ))
  else
    mt=$(awk '/MemTotal/{print int($2/1024*0.02); exit}' /proc/meminfo 2>/dev/null)
    echo $(( ${mt:-256} < 256 ? 256 : ${mt:-256} > 1024 ? 1024 : ${mt:-256} ))
  fi
}
fill_target_mb(){
  local av mt
  av=$(df -k "$IN" 2>/dev/null | awk 'NR==2{print $4}')
  case "$av" in ''|*[!0-9]*) av=0;; esac
  mt=$(( av / 512 ))                                         # ~2% of free, in MB
  echo $(( mt < 64 ? 64 : mt > 2048 ? 2048 : mt ))
}

# ---------- embedded C helper: probes needing raw syscalls ----------
mkdir -p "$SCRATCH" || echo "WARNING: cannot create scratch dir '$SCRATCH'" >&2
if have cc || have gcc; then
  CC=$(have cc && echo cc || echo gcc)
  $CC -O1 -o "$HELPER" -x c - <<'CEOF' 2>/dev/null || echo "helper compile failed" >&2
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <termios.h>
#include <linux/loop.h>
#include <linux/fs.h>
#include <linux/dm-ioctl.h>
#include <linux/kvm.h>
#include <linux/input.h>
#include <linux/fb.h>
#include <linux/if_tun.h>
#include <scsi/sg.h>
#include <net/if.h>
#if defined(__i386__)||defined(__x86_64__)
#include <sys/io.h>
#endif
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#ifndef FICLONE
#define FICLONE _IOW(0x94, 9, int)
#endif
/* raw btrfs ioctls (linux/btrfs.h is not always installed; layout is fixed ABI):
 * struct btrfs_ioctl_vol_args { s64 fd; char name[4088]; } = 4096 bytes */
struct btrfs_vol_args_s { long long fd; char name[4088]; };
#define BTRFS_IOC_SUBVOL_CREATE_S _IOW(0x91, 14, struct btrfs_vol_args_s)
#define BTRFS_IOC_SNAP_CREATE_S  _IOW(0x91, 15, struct btrfs_vol_args_s)
static void rep(const char*v,const char*d){printf("%s %s\n",v,d);}
/* errno-aware classification: EPERM/EACCES = policy/cap deny; anything else
 * (ENOENT, EINVAL, ENOSYS, EOPNOTSUPP, EFAULT, ...) = cannot attribute to
 * policy — must never count as a deny "pass". */
static void vcls(long r,const char*what){
  if(r>=0){rep("ALLOW",what);return;}
  int e=errno;
  if(e==EPERM||e==EACCES)printf("DENY errno=%d %s (%s)\n",e,strerror(e),what);
  else printf("INCONCLUSIVE errno=%d %s (%s)\n",e,strerror(e),what);
}
int main(int argc,char**argv){
  if(argc<2){rep("INCONCLUSIVE","usage");return 0;}
  const char*op=argv[1];
  if(!strcmp(op,"landlock-abi")){
#ifdef SYS_landlock_create_ruleset
    long r=syscall(SYS_landlock_create_ruleset,NULL,0,1); /* version query */
    if(r>=0)printf("ALLOW abi-v%ld\n",r); else vcls(r,"create_ruleset(version)");
#else
    rep("INCONCLUSIVE","landlock-syscall-undefined-in-headers");
#endif
  }else if(!strcmp(op,"llcompose")){ /* Landlock compose self-test: can a process stack its own ruleset? */
#ifdef SYS_landlock_create_ruleset
    struct { unsigned long long handled; } at = { (1ULL<<1)|(1ULL<<2) }; /* WRITE_FILE|READ_FILE */
    long rd=syscall(SYS_landlock_create_ruleset,&at,sizeof at,0);
    if(rd<0){vcls(rd,"create_ruleset");return 0;}
#ifdef SYS_landlock_add_rule
    struct { unsigned long long allowed; int parent_fd; } ab = { (1ULL<<1)|(1ULL<<2), 0 };
    int pf=open("/",O_PATH|O_CLOEXEC);
    if(pf<0){vcls(pf,"open-root");return 0;}
    ab.parent_fd=pf;
    if(syscall(SYS_landlock_add_rule,rd,1,&ab,0)){vcls(-1,"add_rule");close(pf);return 0;}
    close(pf);
#else
    rep("INCONCLUSIVE","add_rule-undefined-in-headers");return 0;
#endif
    prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
    if(syscall(SYS_landlock_restrict_self,rd,0)){vcls(-1,"restrict_self");return 0;}
    int f=open("/proc/self/status",O_RDONLY); if(f<0) f=open("/dev/null",O_RDONLY);
    if(f>=0){rep("ALLOW","compose-ok(stacking-works)");close(f);}
    else rep("DENY","compose-broken(own-allow-rule-denied)");
#else
    rep("INCONCLUSIVE","landlock-undefined-in-headers");
#endif
  }else if(!strcmp(op,"uring")){
#ifdef SYS_io_uring_setup
    char p[120]={0};long fd=(long)syscall(SYS_io_uring_setup,8,p);
    if(fd>=0){rep("ALLOW","io_uring_setup");close((int)fd);}else vcls(fd,"io_uring_setup");
#else
    rep("INCONCLUSIVE","io_uring-syscall-undefined-in-headers");
#endif
  }else if(!strcmp(op,"byhandle")&&argc==3){
    struct{unsigned n;int t;unsigned char h[128];}fh;fh.n=128;int mnt;
    int f=open(argv[2],O_RDONLY);if(f<0){vcls(f,"open-src");return 0;}
    if(syscall(SYS_name_to_handle_at,f,&fh,&mnt,0)){vcls(-1,"name_to_handle_at");close(f);return 0;}
    int m=open("/",O_PATH);long r=syscall(SYS_open_by_handle_at,m,&fh,O_RDONLY);
    if(r>=0)rep("ALLOW","open_by_handle (CAP_DAC_READ_SEARCH?)");else vcls(r,"open_by_handle_at");
    close(f);close(m);
  }else if(!strcmp(op,"rawsock")){
    int s=socket(AF_INET,SOCK_RAW|SOCK_CLOEXEC,IPPROTO_ICMP);
    if(s>=0){rep("ALLOW","AF_INET RAW");close(s);}else vcls(s,"socket(AF_INET,RAW)");
  }else if(!strcmp(op,"pktsock")){
    int s=socket(AF_PACKET,SOCK_RAW|SOCK_CLOEXEC,htons(ETH_P_ALL));
    if(s>=0){rep("ALLOW","AF_PACKET");close(s);}else vcls(s,"socket(AF_PACKET,RAW)");
  }else if(!strcmp(op,"netlink")){
    int s=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_ROUTE);
    struct sockaddr_nl sa={0};sa.nl_family=AF_NETLINK;
    if(s<0){vcls(s,"socket(netlink)");return 0;}
    if(bind(s,(void*)&sa,sizeof sa)){vcls(-1,"bind(netlink)");return 0;}
    char b[256];struct nlmsghdr*h=(void*)b;struct rtgenmsg g={0};
    memset(b,0,sizeof b);h->nlmsg_len=NLMSG_LENGTH(sizeof g);h->nlmsg_type=RTM_GETROUTE;
    h->nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP;g.rtgen_family=AF_UNSPEC;
    memcpy(NLMSG_DATA(h),&g,sizeof g);
    if(send(s,h,h->nlmsg_len,0)<0){vcls(-1,"send(netlink)");return 0;}
    ssize_t n=recv(s,b,sizeof b,0);
    if(n>0)rep("ALLOW","route-table-dump(host-recon)");else vcls((long)n,"recv(netlink)");
  }else if(!strcmp(op,"abstract")&&argc==3){
    int s=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
    struct sockaddr_un a={0};a.sun_family=AF_UNIX;a.sun_path[0]=0;
    strncpy(a.sun_path+1,argv[2],90);
    if(bind(s,(void*)&a,sizeof a)==0)rep("ALLOW","abstract-ns-bind");else vcls(-1,"bind(abstract)");
  }else if(!strcmp(op,"setns")&&argc==3){
    int f=open(argv[2],O_RDONLY);if(f<0){vcls(f,"open-ns");return 0;}
    if(syscall(SYS_setns,f,0)==0)rep("ALLOW","setns(CRITICAL)");else vcls(-1,"setns");
    close(f);
  }else if(!strcmp(op,"uffd")){
#ifdef SYS_userfaultfd
    long r=syscall(SYS_userfaultfd,O_CLOEXEC|O_NONBLOCK);
    if(r>=0)rep("ALLOW","userfaultfd");else vcls(r,"userfaultfd");
#else
    rep("INCONCLUSIVE","userfaultfd-undefined-in-headers");
#endif
  }else if(!strcmp(op,"perf")){
    char a[96]={0};*(unsigned*)(a+4)=96; /* attr.size; type=0 cycles */
    long r=syscall(SYS_perf_event_open,a,0,-1,-1,0);
    if(r>=0)rep("ALLOW","perf_event");else vcls(r,"perf_event_open");
  }else if(!strcmp(op,"bpf")){
    struct { unsigned map_type,key_size,value_size,max_entries; } m = {1,4,4,1}; /* HASH 4/4 x1 */
    long r=syscall(SYS_bpf,0,&m,sizeof m); /* BPF_MAP_CREATE */
    if(r>=0){rep("ALLOW","bpf-map-create");close((int)r);}else vcls(r,"bpf(BPF_MAP_CREATE)");
  }else if(!strcmp(op,"keyring")){
    long r=syscall(SYS_add_key,"user","landscan","v",1,-3); /* thread keyring */
    if(r>=0)rep("ALLOW","add_key");else vcls(r,"add_key");
  }else if(!strcmp(op,"finitmod")){
#ifdef SYS_finit_module
    int f=open("/dev/null",O_RDONLY);
    if(f<0){vcls(f,"open-/dev/null");return 0;}
    long r=syscall(SYS_finit_module,f,"",0);
    if(r==0)rep("ALLOW","CRITICAL-module-load");else vcls(r,"finit_module"); /* EPERM=blocked, EINVAL=reachable */
    close(f);
#else
    rep("INCONCLUSIVE","finit_module-undefined-in-headers");
#endif
  }else if(!strcmp(op,"kexec")){
    long r=syscall(SYS_kexec_load,0,0,NULL,0);
    if(r==0)rep("ALLOW","CRITICAL-kexec");else vcls(r,"kexec_load"); /* EPERM=blocked, EINVAL=reachable */
  }else if(!strcmp(op,"openw")&&argc==3){
    int f=open(argv[2],O_RDWR|O_CLOEXEC);
    if(f>=0){rep("ALLOW","open-rw");close(f);}else vcls(f,argv[2]); /* ENOENT -> INCONCLUSIVE */
  }else if(!strcmp(op,"mknodopen")&&argc==3){
    if(mknod(argv[2],S_IFCHR|0600,makedev(1,3))){
      if(errno==EEXIST)unlink(argv[2]); /* idempotency */
      vcls(-1,"mknod");return 0;}
    int f=open(argv[2],O_RDONLY);
    if(f<0){vcls(f,"open-after-mknod(device-cgroup?)");unlink(argv[2]);return 0;}
    char c;read(f,&c,1);rep("ALLOW","CRITICAL /dev/null-equivalent readable");close(f);
    unlink(argv[2]);
  }else if(!strcmp(op,"chroot")&&argc==3){ /* chroot(2) itself is the signal; no exec needed */
    if(chroot(argv[2])==0)rep("ALLOW","CRITICAL chroot(2) permitted");else vcls(-1,"chroot");
  }else if(!strcmp(op,"tiocsti")){ /* keystroke-injection ioctl on own tty */
    int f=open("/dev/tty",O_RDWR);
    if(f<0){vcls(f,"open-/dev/tty");return 0;}
    char c='\n';
    if(ioctl(f,TIOCSTI,&c)==0)rep("ALLOW","TIOCSTI-inject");else vcls(-1,"TIOCSTI");
    close(f);
  }else if(!strcmp(op,"ficlone")&&argc==4){ /* reflink across the policy boundary */
    int s=open(argv[2],O_RDONLY);if(s<0){vcls(s,"open-src");return 0;}
    int d=open(argv[3],O_WRONLY|O_CREAT|O_TRUNC,0600);
    if(d<0){vcls(d,"open-dst");close(s);return 0;}
    long r=ioctl(d,FICLONE,s);
    if(r==0)rep("ALLOW","CRITICAL reflink-cross-boundary");else vcls(r,"FICLONE");
    close(s);close(d);unlink(argv[3]);
  }else if(!strcmp(op,"loopctl")){
    int f=open("/dev/loop-control",O_RDONLY);
    if(f<0){vcls(f,"open-loop-control");return 0;}
    long r=ioctl(f,LOOP_CTL_GET_FREE,0);
    if(r>=0)printf("ALLOW loop%d-free\n",(int)r);else vcls(r,"LOOP_CTL_GET_FREE");
    close(f);
  }else if(!strcmp(op,"pvm")&&argc==3){ /* process_vm_readv on init: verdict only, bytes never printed */
    struct iovec l={NULL,16},r2={{0},16};
    char local[16]; l.iov_base=local; r2.iov_base=(void*)0x400000L;
    ssize_t n=process_vm_readv((pid_t)atoi(argv[2]),&l,1,&r2,1,0);
    if(n>=0)rep("ALLOW","CRITICAL process_vm_readv-init");else vcls(-1,"process_vm_readv");
  }else if(!strcmp(op,"pidfdgetfd")&&argc==3){
#ifdef SYS_pidfd_open
    int pfd=(int)syscall(SYS_pidfd_open,(pid_t)atoi(argv[2]),0);
    if(pfd<0){vcls(pfd,"pidfd_open");return 0;}
# ifdef SYS_pidfd_getfd
    int nfd=(int)syscall(SYS_pidfd_getfd,pfd,0,0);
    if(nfd>=0){rep("ALLOW","CRITICAL pidfd_getfd-init-fd");close(nfd);}else vcls(nfd,"pidfd_getfd");
# else
    rep("INCONCLUSIVE","pidfd_getfd-undefined-in-headers");
# endif
    close(pfd);
#else
    rep("INCONCLUSIVE","pidfd_open-undefined-in-headers");
#endif
  }else if(!strcmp(op,"iopl")){
#if defined(__i386__)||defined(__x86_64__)
    long r=iopl(0); /* level 0 = downgrade; permission check is unconditional */
    if(r==0)rep("ALLOW","iopl-callable(CAP_SYS_IO)");else vcls(r,"iopl");
#else
    rep("INCONCLUSIVE","iopl-arch-unsupported");
#endif
  }else if(!strcmp(op,"clockset")){ /* nudges clock µs FORWARD, never back */
    struct timespec ts;
    if(clock_gettime(CLOCK_REALTIME,&ts)){vcls(-1,"clock_gettime");return 0;}
    ts.tv_nsec=(ts.tv_nsec|0x3F)+1;
    if(ts.tv_nsec>=1000000000L){ts.tv_nsec-=1000000000L;ts.tv_sec+=1;}
    if(clock_settime(CLOCK_REALTIME,&ts)==0)rep("ALLOW","clock-settable(CAP_SYS_TIME)");else vcls(-1,"clock_settime");
  }else if(!strcmp(op,"subvol")&&argc==3){ /* raw BTRFS_IOC_SUBVOL_CREATE: the mkdir-hook-bypass class, no userspace tool needed */
    int d=open(argv[2],O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if(d<0){vcls(d,"open-parent");return 0;}
    struct btrfs_vol_args_s a={0};
    snprintf(a.name,sizeof a.name,"ls%d",(int)getpid()); /* unique per run: idempotent */
    long r=ioctl(d,BTRFS_IOC_SUBVOL_CREATE_S,&a);
    if(r==0)rep("ALLOW","CRITICAL subvol-created(mkdir-hook-bypass?)");else vcls(r,"BTRFS_IOC_SUBVOL_CREATE");
    close(d);
  }else if(!strcmp(op,"snap")&&argc==4){ /* raw BTRFS_IOC_SNAP_CREATE: src subvol -> name inside dst-parent */
    int s=open(argv[2],O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if(s<0){vcls(s,"open-src-subvol");return 0;}
    int d=open(argv[3],O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if(d<0){vcls(d,"open-dst-parent");close(s);return 0;}
    struct btrfs_vol_args_s a={0};
    a.fd=s; snprintf(a.name,sizeof a.name,"ls%d",(int)getpid());
    long r=ioctl(d,BTRFS_IOC_SNAP_CREATE_S,&a);
    if(r==0)rep("ALLOW","CRITICAL snapshot-created");else vcls(r,"BTRFS_IOC_SNAP_CREATE");
    close(s);close(d);
  }else if(!strcmp(op,"ioctlscan")&&argc==3){ /* enumerate security-relevant ioctl routes on one fd;
      kernel has no ioctl-enumeration API: ENOTTY probing IS the heuristic.
      REACHABLE=succeeded DENIED=EPERM/EACCES NOTTY=not-a-route ERR=other */
    const char*p=argv[2];
    int f=open(p,O_RDWR); if(f<0) f=open(p,O_RDONLY);
    if(f<0){printf("SKIP open errno=%d %s\n",errno,strerror(errno));return 0;}
    int zero=0; char buf[128]={0};
#ifdef TUNSETIFF
    struct ifreq ifr; memset(&ifr,0,sizeof ifr); strcpy(ifr.ifr_name,"ls%d"); ifr.ifr_flags=IFF_TUN|IFF_NO_PI;
#endif
#ifdef DM_VERSION
    struct dm_ioctl dmi; memset(&dmi,0,sizeof dmi); dmi.version[0]=4;dmi.version[1]=0;dmi.version[2]=0; dmi.data_size=sizeof dmi;
#endif
#ifdef FBIOGET_VSCREENINFO
    struct fb_var_screeninfo fbv; memset(&fbv,0,sizeof fbv);
#endif
#ifdef SG_IO
    struct sg_io_hdr sgi; unsigned char cdb[6]={0x12,0,0,0,36,0},sense[32]={0},dio[96]={0}; /* INQUIRY: read-only */
    memset(&sgi,0,sizeof sgi); sgi.interface_id='S'; sgi.dxfer_direction=SG_DXFER_FROM_DEV;
    sgi.cmd_len=6; sgi.cmdp=cdb; sgi.dxferp=dio; sgi.dxfer_len=96; sgi.sbp=sense; sgi.mx_sb_len=sizeof sense; sgi.timeout=5000;
#endif
    struct { const char*n; unsigned long r; void*a; } T[]={
      {"FS_IOC_GETFLAGS",FS_IOC_GETFLAGS,&zero},
      {"FS_IOC_SETFLAGS_CLEAR",FS_IOC_SETFLAGS,&zero},
      {"FS_IOC_FSGETXATTR",FS_IOC_FSGETXATTR,&zero},
      {"FIBMAP",FIBMAP,&zero},
#ifdef TIOCSTI
      {"TIOCSTI",TIOCSTI,buf},          /* one '\n' into own input queue */
      {"TIOCCONS_OFF",TIOCCONS,&zero},
      {"TIOCGWINSZ",TIOCGWINSZ,buf},
#endif
#ifdef LOOP_CTL_GET_FREE
      {"LOOP_CTL_GET_FREE",LOOP_CTL_GET_FREE,NULL},
#endif
#ifdef DM_VERSION
      {"DM_VERSION",DM_VERSION,&dmi},
      {"DM_LIST_DEVICES",DM_LIST_DEVICES,&dmi},
#endif
#ifdef KVM_GET_API_VERSION
      {"KVM_GET_API_VERSION",KVM_GET_API_VERSION,NULL},
#endif
#ifdef TUNSETIFF
      {"TUNSETIFF",TUNSETIFF,&ifr},
#endif
#ifdef EVIOCGNAME
      {"EVIOCGNAME",EVIOCGNAME(sizeof buf-1),buf},
#endif
#ifdef FBIOGET_VSCREENINFO
      {"FBIOGET_VSCREENINFO",FBIOGET_VSCREENINFO,&fbv},
#endif
#ifdef SG_IO
      {"SG_IO_INQUIRY",SG_IO,&sgi},
#endif
    };
    for(unsigned i=0;i<sizeof T/sizeof T[0];i++){
      errno=0; long r=ioctl(f,T[i].r,T[i].a);
      if(r>=0)printf("REACHABLE %s\n",T[i].n);
      else{int e=errno;
        if(e==ENOTTY)printf("NOTTY %s\n",T[i].n);
        else if(e==EPERM||e==EACCES)printf("DENIED %s errno=%d %s\n",T[i].n,e,strerror(e));
        else printf("ERR %s errno=%d %s\n",T[i].n,e,strerror(e));}
    }
    close(f);
  }else if(!strcmp(op,"ptrace-sibling")){ /* attach to a same-uid NON-child process */
    int pfd[2];if(pipe(pfd)){rep("INCONCLUSIVE","pipe-fail");return 0;}
    pid_t mid=fork();
    if(mid==0){
      close(pfd[0]);
      pid_t g=fork();
      if(g==0){close(pfd[1]);sleep(30);_exit(0);} /* grandchild: sleeps, becomes sibling */
      if(write(pfd[1],&g,sizeof g)!=(ssize_t)sizeof g)_exit(1);
      close(pfd[1]);_exit(0);
    }
    close(pfd[1]);
    pid_t g;ssize_t rn=read(pfd[0],&g,sizeof g);close(pfd[0]);
    if(rn!=(ssize_t)sizeof g){rep("INCONCLUSIVE","pipe-read");return 0;}
    int st;waitpid(mid,&st,0); /* intermediate gone: g is now a non-child sibling */
    usleep(100000);
    if(ptrace(PTRACE_ATTACH,g)==0){
      waitpid(g,NULL,0);
      ptrace(PTRACE_DETACH,g,0,0);
      kill(g,SIGKILL);waitpid(g,NULL,0);
      rep("ALLOW","sibling-attach(same-uid-non-child)");
    }else{
      printf("DENY errno=%d %s\n",errno,strerror(errno));
      kill(g,SIGKILL);
    }
  }else if(!strcmp(op,"ptrace-self")){
    pid_t p=fork();if(p==0){usleep(300000);_exit(0);}
    if(ptrace(PTRACE_ATTACH,p)==0){waitpid(p,NULL,0);ptrace(PTRACE_DETACH,p,0,0);rep("ALLOW","own-child(sanity)");}
    else vcls(-1,"attach-own-child");
  }else if(!strcmp(op,"ptrace-init")){
    if(ptrace(PTRACE_ATTACH,1)==0){waitpid(1,NULL,0);ptrace(PTRACE_DETACH,1,0,0);rep("ALLOW","CRITICAL-ptrace-init");}
    else vcls(-1,"ptrace-init");
  }else if(!strcmp(op,"memhog")&&argc==3){
    size_t mb=(size_t)atoi(argv[2]);
    int*sh=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    pid_t p=fork();
    if(p==0){size_t g=0;while(g<mb){void*q=malloc(8u<<20);if(!q)break;memset(q,1,8u<<20);g+=8;sh[0]=(int)g;usleep(500);}sh[0]=(int)g;_exit(0);}
    int st;waitpid(p,&st,0);
    if(WIFSIGNALED(st)&&WTERMSIG(st)==SIGKILL)printf("DENY memhog-SIGKILLED-at-~%dMB(memory.max)\n",sh[0]);
    else if(WIFEXITED(st))printf("ALLOW allocated-%dMB-uncapped\n",sh[0]);
    else printf("DENY memhog-other\n");
  }else if(!strcmp(op,"opentree")&&argc==3){ /* new mount API: Landlock has no hook; denylist must name it */
#ifdef SYS_open_tree
    int f=open(argv[2],O_PATH|O_CLOEXEC);if(f<0){vcls(f,"open-target");return 0;}close(f);
    long r=syscall(SYS_open_tree,AT_FDCWD,argv[2],O_PATH|OPEN_TREE_CLONE);
    if(r>=0)close((int)r);vcls(r,"open_tree(OPEN_TREE_CLONE)");
#else
    rep("INCONCLUSIVE","open_tree-undefined-in-headers");
#endif
  }else if(!strcmp(op,"movemount")&&argc==4){ /* re-root argv[2] at argv[3]; CAP_SYS_ADMIN over owning userns */
#ifdef SYS_open_tree
    int f=(int)syscall(SYS_open_tree,AT_FDCWD,argv[2],O_PATH|OPEN_TREE_CLONE);
    if(f<0){vcls(f,"open_tree");return 0;}
#ifdef SYS_move_mount
    long r=syscall(SYS_move_mount,f,"",AT_FDCWD,argv[3],MOVE_MOUNT_F_EMPTY_PATH,0);
    close(f);vcls(r,"move_mount");
#else
    close(f);rep("INCONCLUSIVE","move_mount-undefined-in-headers");
#endif
#else
    rep("INCONCLUSIVE","open_tree-undefined-in-headers");
#endif
  }else if(!strcmp(op,"fsopen")){
#ifdef SYS_fsopen
    long r=syscall(SYS_fsopen,"tmpfs",FSOPEN_CLOEXEC);if(r>=0)close((int)r);vcls(r,"fsopen(tmpfs)");
#else
    rep("INCONCLUSIVE","fsopen-undefined-in-headers");
#endif
  }else if(!strcmp(op,"mountsetattr")){
#ifdef SYS_mount_setattr
    long r=syscall(SYS_mount_setattr,-1,"",AT_EMPTY_PATH,NULL,0);vcls(r,"mount_setattr(null)");
#else
    rep("INCONCLUSIVE","mount_setattr-undefined-in-headers");
#endif
  }else if(!strcmp(op,"pvreadv")&&argc==3){ /* process_vm_readv of pid argv[2]; the ptrace denylist must name it */
#ifdef SYS_process_vm_readv
    struct iovec l; l.iov_base=malloc(16); l.iov_len=16;
    struct iovec rm; rm.iov_base=NULL; rm.iov_len=16;
    long rv=syscall(SYS_process_vm_readv,(pid_t)atoi(argv[2]),&l,1,&rm,1,0);
    vcls(rv,"process_vm_readv(pid)");
#else
    rep("INCONCLUSIVE","process_vm_readv-undefined-in-headers");
#endif
  }else if(!strcmp(op,"pidfdsig")&&argc==3){ /* pidfd_send_signal sig 0: permission probe, no signal */
#ifdef SYS_pidfd_send_signal
    int pd=(int)syscall(SYS_pidfd_open,(pid_t)atoi(argv[2]),0);
    if(pd<0){vcls(pd,"pidfd_open");return 0;}
    long r=syscall(SYS_pidfd_send_signal,pd,0,NULL,0);close(pd);vcls(r,"pidfd_send_signal(sig0)");
#else
    rep("INCONCLUSIVE","pidfd_send_signal-undefined-in-headers");
#endif
  }else if(!strcmp(op,"pidfdgetfd")&&argc==4){
#ifdef SYS_pidfd_getfd
    int pd=(int)syscall(SYS_pidfd_open,(pid_t)atoi(argv[2]),0);
    if(pd<0){vcls(pd,"pidfd_open");return 0;}
    long r=syscall(SYS_pidfd_getfd,pd,atoi(argv[3]),0);close(pd);if(r>=0)close((int)r);
    vcls(r,"pidfd_getfd");
#else
    rep("INCONCLUSIVE","pidfd_getfd-undefined-in-headers");
#endif
  }else if(!strcmp(op,"perfopen")&&argc==3){
#ifdef SYS_perf_event_open
    struct{unsigned size,type;unsigned long long config;unsigned long long sample_period;
           unsigned long long sample_type,read_format;unsigned long long flags;
           unsigned wakeup,raw_type;unsigned long long raw_config;unsigned branch,extra;}a;
    memset(&a,0,sizeof a);a.size=sizeof a;a.type=0;a.config=0;a.flags=1ULL<<5; /* exclude_kernel */
    long r=syscall(SYS_perf_event_open,&a,sizeof a,(pid_t)atoi(argv[2]),-1,0);
    if(r>=0)close((int)r);vcls(r,"perf_event_open(pid)");
#else
    rep("INCONCLUSIVE","perf_event_open-undefined-in-headers");
#endif
  }else if(!strcmp(op,"keyadd")){
#ifdef SYS_add_key
    long r=syscall(SYS_add_key,"user","sandeval.sweep","payload",7,-3 /* thread keyring */);
    vcls(r,"add_key");
#else
    rep("INCONCLUSIVE","add_key-undefined-in-headers");
#endif
  }else if(!strcmp(op,"uffd")){
#ifdef SYS_userfaultfd
    long r=syscall(SYS_userfaultfd,O_CLOEXEC|O_NONBLOCK);if(r>=0)close((int)r);vcls(r,"userfaultfd");
#else
    rep("INCONCLUSIVE","userfaultfd-undefined-in-headers");
#endif
  }else if(!strcmp(op,"bpfcreate")){
#ifdef SYS_bpf
    unsigned long long a[15]={0};a[0]=1 /*HASH*/;a[1]=8;a[2]=8;a[3]=1;
    long r=syscall(SYS_bpf,0,a,sizeof a);vcls(r,"bpf(MAP_CREATE)");
#else
    rep("INCONCLUSIVE","bpf-undefined-in-headers");
#endif
  }else if(!strcmp(op,"kcmp")&&argc==4){
#ifdef SYS_kcmp
    long r=syscall(SYS_kcmp,(pid_t)atoi(argv[2]),(pid_t)atoi(argv[3]),0 /*KCMP_FILE*/,0,0);
    vcls(r,"kcmp");
#else
    rep("INCONCLUSIVE","kcmp-undefined-in-headers");
#endif
  }else if(!strcmp(op,"mqopen")){
#ifdef SYS_mq_open
    long r=syscall(SYS_mq_open,"/sandeval-sweep",0 /*O_RDONLY*/);if(r>=0)close((int)r);
    vcls(r,"mq_open");
#else
    rep("INCONCLUSIVE","mq_open-undefined-in-headers");
#endif
  }else if(!strcmp(op,"fanotify")){
#ifdef SYS_fanotify_init
    long r=syscall(SYS_fanotify_init,0,0);if(r>=0)close((int)r);vcls(r,"fanotify_init");
#else
    rep("INCONCLUSIVE","fanotify_init-undefined-in-headers");
#endif
  }else if(!strcmp(op,"quotactl")){
#ifdef SYS_quotactl
    long r=syscall(SYS_quotactl,0x0600 /*Q_SYNC*/,NULL,0,0);vcls(r,"quotactl(Q_SYNC)");
#else
    rep("INCONCLUSIVE","quotactl-undefined-in-headers");
#endif
  }else if(!strcmp(op,"clockset")){ /* host-global if allowed; value-preserving write-back */
#ifdef SYS_clock_settime
    struct timespec ts;if(clock_gettime(CLOCK_REALTIME,&ts))vcls(-1,"clock_gettime");
    else{long r=syscall(SYS_clock_settime,CLOCK_REALTIME,&ts);vcls(r,"clock_settime(current)");}
#else
    rep("INCONCLUSIVE","clock_settime-undefined-in-headers");
#endif
  }else if(!strcmp(op,"mlockall")){
    long r=syscall(SYS_mlockall,1 /*MLOCK_CURRENT*/);vcls(r,"mlockall(current)");
  }else if(!strcmp(op,"vhangup")){
#ifdef SYS_vhangup
    long r=syscall(SYS_vhangup);vcls(r,"vhangup");
#else
    rep("INCONCLUSIVE","vhangup-undefined-in-headers");
#endif
  }else if(!strcmp(op,"acct")){
#ifdef SYS_acct
    long r=syscall(SYS_acct,NULL);vcls(r,"acct(NULL=disable)");
#else
    rep("INCONCLUSIVE","acct-undefined-in-headers");
#endif
  }else if(!strcmp(op,"lookupdcookie")){
#ifdef SYS_lookup_dcookie
    long r=syscall(SYS_lookup_dcookie,0,NULL,0);vcls(r,"lookup_dcookie");
#else
    rep("INCONCLUSIVE","lookup_dcookie-undefined-in-headers");
#endif
  }else{rep("INCONCLUSIVE","unknown-op");}
  return 0;
}
CEOF
else
  echo "NOTE: no cc/gcc — kernel-syscall probes will be skipped (helper-unavailable)." >&2
fi

trap 'jobs -p | xargs -r kill 2>/dev/null
      umount "$SCRATCH/mnt" "$SCRATCH/p" 2>/dev/null
      [ "$OUT_WAS_MNT" = 0 ] && umount "$OUT" 2>/dev/null
      rm -f "$OUT/snap" "$OUT/f" "$OUT/f1" 2>/dev/null
      rm -rf "$SCRATCH" 2>/dev/null' EXIT

# ============================ 0. PREFLIGHT ============================
sec "0. PREFLIGHT"
echo "kernel: $(uname -r)   date: $(date -u +%FT%TZ)"
echo "uid: $(id -u 2>/dev/null)   $(grep -m1 '^CapEff:' /proc/self/status 2>/dev/null | tr -s '\t' ' ')"
[ "$(id -u 2>/dev/null)" = 0 ] && echo "WARNING: running as ROOT — deny-verdicts are weak evidence (capability gates are all open). Any ALLOW on a deny-wanted check is still a real finding, but treat this run as privileged-context recon, not conformance proof. Run as the agent user for meaningful denies." >&2
rm -rf "$SAN"
hcheck landlock-abi info landlock-abi
# sanity: if these "fail", IN/OUT are reversed or IN is unusable — verdicts unreliable
check sanity-in-mkdir    allow mkdir -p "$SAN"
check sanity-in-write    allow sh -c "echo x > \"\$1/f\"" sh "$SAN"
check sanity-execute-true info /bin/true
if [ "${GOT[sanity-in-mkdir]:-}" != allow ] || [ "${GOT[sanity-in-write]:-}" != allow ]; then
  echo "WARNING: IN-dir sanity failed — in/out dirs likely reversed or unusable; treat all verdicts as suspect." >&2
fi
rec info-seccomp-status info allow "$(grep -m2 -E '^(Seccomp|NoNewPrivs):' /proc/self/status 2>/dev/null | tr -s '\n\t:' '   ')"

# ===================== 1. FS ACCESS OUT OF POLICY =====================
sec "1. FS operations on OUT (expected deny)"
check out-mkdir       deny mkdir -p "$OUT/d1"
check out-creat       deny touch "$OUT/f1"
check out-write       deny sh -c "echo x > \"\$1/f1\"" sh "$OUT"
check out-append      deny sh -c "echo x >> \"\$1/f1\"" sh "$OUT"
check out-truncate    deny truncate -s 1 "$OUT/f1"
if [ -f "$SEED" ]; then
  check out-unlink     deny rm "$SEED"          # operator-seeded; rm -f would mask ENOENT as ALLOW
  ln -sf "$SEED" "$SAN/seedlnk"                 # readable out-of-policy file reached
  check out-symlink-read deny sh -c 'dd if="\$1" bs=1 count=1 2>/dev/null && echo readable' sh "$SAN/seedlnk"   # deny resolution; content stays out of telemetry
else
  rec out-unlink info skip "seed $SEED operator-side to enable"
  rec out-symlink-read info skip "seed $SEED operator-side to enable"
fi
check out-read-etc-passwd  info sh -c 'head -c 60 /etc/passwd 2>&1'
check out-read-etc-hostname info sh -c 'head -c 60 /etc/hostname 2>&1'
check out-read-shadow      deny sh -c 'dd if=/etc/shadow bs=1 count=1 2>/dev/null && echo readable'          # verdict only: no content in telemetry
check out-read-ssh-hostkey deny sh -c 'dd if=/etc/ssh/ssh_host_ed25519_key bs=1 count=1 2>/dev/null && echo readable'
check out-read-root-ssh    deny sh -c 'dd if=/root/.ssh/id_rsa bs=1 count=1 2>/dev/null && echo readable'

# ===================== 2. FS CREATION CLASSES =========================
sec "2. Creation classes (in-policy sanity / out-of-policy deny)"
check in-mkfifo       allow mkfifo "$SAN/fifo"
check in-symlink      allow ln -sf /etc/hostname "$SAN/lnk"
check in-exec-home    info sh -c 'cp /bin/true "$1/true" && "$1/true" && echo EXEC-OK' sh "$SAN"
check out-hardlink    deny ln /etc/hostname "$SAN/hl"             # cross-boundary link
check out-rename      deny mv "$SAN/f" "$OUT/f"
# btrfs subvolume/snapshot via RAW ioctl — the mkdir-hook-bypass class needs no
# userspace tool; ENOTTY on non-btrfs = honest inconclusive
hcheck in-btrfs-subvol  allow subvol "$SAN"
hcheck out-btrfs-subvol deny subvol "$OUT"                        # target out-of-policy: open or ioctl must deny
hcheck out-btrfs-snap   deny snap "$SAN" "$OUT"

# ===================== 3. IOCTL-DRIVEN BYPASS CLASS ===================
sec "3. ioctl-driven operations (hook-coverage gaps)"
if have cp; then
  check out-reflink    deny cp --reflink=always "$SAN/f" "$OUT/f"
fi
hcheck out-ficlone    deny ficlone "$SAN/f" "$OUT/f"              # FICLONE ioctl across the boundary
if have chattr; then
  if chattr +i "$SCRATCH/f" 2>/dev/null; then
    rec in-chattr-immutable info allow "ioctl FS_IOC_SETFLAGS permitted"
    chattr -i "$SCRATCH/f" 2>/dev/null
  else rec in-chattr-immutable info deny "FS_IOC_SETFLAGS refused"; fi
else rec in-chattr-immutable info skip "no chattr"; fi
if [ "$SAFE" = 0 ] && have mkswap && have swapon; then
  dd if=/dev/zero of="$SCRATCH/swap" bs=1M count=8 status=none
  mkswap "$SCRATCH/swap" >/dev/null 2>&1
  check out-swapon deny swapon "$SCRATCH/swap"   # CAP_SYS_ADMIN probe — HOST-GLOBAL if allowed
  swapoff "$SCRATCH/swap" 2>/dev/null
  rm -f "$SCRATCH/swap"
else rec out-swapon info skip "gated(off — --safe)"; fi
hcheck helper-mknod-open   deny mknodopen "$SAN/dev-null-clone"  # mknod then READ it
hcheck helper-open-byhandle deny byhandle "$SAN/f"                # CAP_DAC_READ_SEARCH probe
hcheck helper-loopctl      info loopctl                              # loop-device reachability
hcheck helper-tiocsti      deny tiocsti                              # keystroke-injection ioctl

# ===================== 3b. IOCTL ROUTE ENUMERATION ====================
# No kernel API enumerates an fd's accepted ioctls — ENOTTY probing IS the
# heuristic. Table-driven scan of security-relevant families per fd type;
# every request becomes its own baseline entry so route additions are visible
# as NEW lines in --check diffs.
sec "3b. ioctl route enumeration (REACHABLE / DENIED / NOTTY per request)"
if [ -x "$HELPER" ]; then
  tl="$SCRATCH/targets"   # plain files, not process substitution: <(...) breaks where /dev/fd is absent
  printf '%s\n' "$SAN/f" "$SAN" /dev/tty /dev/loop-control /dev/mapper/control /dev/kvm /dev/net/tun /dev/input/event0 /dev/fb0 /dev/sda /dev/nvme0n1 /dev/dri/card0 > "$tl"
  while IFS= read -r tgt; do
    [ -n "$tgt" ] || continue
    short=$(basename "$tgt")
    [ $VERBOSE = 1 ] && echo "  \$ helper ioctlscan $tgt"
    timeout 15 "$HELPER" ioctlscan "$tgt" > "$SCRATCH/scan.out" 2>&1
    while read -r v req rest; do
      case "$v" in
        REACHABLE) rec "ioctl-$short-$req" info allow "$tgt $rest";;
        DENIED)    rec "ioctl-$short-$req" info deny "$tgt $rest";;
        NOTTY)     rec "ioctl-$short-$req" info notty "$tgt $rest";;
        ERR)       rec "ioctl-$short-$req" info err "$tgt $rest";;
        SKIP)      rec "ioctl-$short-$req" info skip "$tgt $rest";;
      esac
    done < "$SCRATCH/scan.out"
  done < "$tl"
else
  rec ioctl-scan info skip "helper-unavailable(no cc)"
fi

# ===================== 3c. MODERN SYSCALL SURFACE ======================
# Denylists age: each new kernel interface is a new syscall number that a
# classic denylist does not name. Every probe here is permission-only or
# value-preserving, and each becomes its own baseline entry.
sec "3c. modern syscall surface (new numbers a classic denylist misses)"
if [ -x "$HELPER" ]; then
  mkdir -p "$SCRATCH/mm-src" "$SCRATCH/mm-dest"
  hcheck helper-opentree      deny opentree "$SCRATCH/mm-src"
  hcheck helper-movemount     deny movemount "$SCRATCH/mm-src" "$SCRATCH/mm-dest"
  hcheck helper-fsopen        deny fsopen
  hcheck helper-mountsetattr  deny mountsetattr
  hcheck helper-pvreadv       deny pvreadv 1
  hcheck helper-pidfdsig      deny pidfdsig 1
  hcheck helper-pidfdgetfd    deny pidfdgetfd 1 0
  hcheck helper-perfopen      deny perfopen 1
  hcheck helper-keyadd        deny keyadd
  hcheck helper-uffd          deny uffd
  hcheck helper-bpfcreate     deny bpfcreate
  hcheck helper-kcmp          deny kcmp 1 $$
  hcheck helper-mqopen        deny mqopen
  hcheck helper-fanotify      deny fanotify
  hcheck helper-quotactl      deny quotactl
  if [ "$SAFE" = 0 ]; then
    hcheck helper-clockset    deny clockset
  else rec helper-clockset info skip "gated(--safe)"; fi
  hcheck helper-mlockall      deny mlockall
  hcheck helper-vhangup       deny vhangup
  hcheck helper-acct          deny acct
  hcheck helper-lookupdcookie deny lookupdcookie
else
  rec helper-surface info skip "helper-unavailable(no cc)"
fi

# ===================== 4. MOUNT / NAMESPACE ===========================
sec "4. Mount & namespace (expected deny)"
check mnt-bind        deny mount --bind "$SCRATCH" "$OUT"
check mnt-tmpfs       deny sh -c 'mkdir -p "$1/mnt" && mount -t tmpfs none "$1/mnt"' sh "$SCRATCH"
check mnt-proc        deny sh -c 'mkdir -p "$1/p" && mount -t proc proc "$1/p"' sh "$SCRATCH"
check ns-unshare-m    deny unshare -m true
check ns-unshare-U    deny unshare -U true
check ns-unshare-ur   deny unshare -U -r true
check ns-unshare-net  deny unshare -n true
hcheck ns-chroot      deny chroot "$SCRATCH"          # chroot(2) itself is the signal (no exec needed)
hcheck helper-setns-mnt deny setns /proc/1/ns/mnt

# ===================== 5. PROC/SYS & KERNEL KNOBS =====================
sec "5. proc/sys & kernel interfaces (write-back = no host mutation)"
kwriteback knob-core-pattern /proc/sys/kernel/core_pattern
kwriteback knob-modprobe     /proc/sys/kernel/modprobe
if [ "$SAFE" = 0 ]; then
  check knob-sysrq-h deny sh -c "echo h > /proc/sysrq-trigger"   # 'h'=help, harmless
fi
if [ "$SAFE" = 0 ]; then
  hcheck knob-clock-settime deny clockset        # nudges clock µs forward, never back
else rec knob-clock-settime info skip "gated(off — --safe)"; fi
check read-kcore      deny sh -c "head -c1 /proc/kcore"
check read-kallsyms   info head -c1 /proc/kallsyms
check read-init-env   deny sh -c 'f=/proc/1/environ; if [ -r "$f" ]; then printf "readable %s bytes sha256:%s\n" "$(wc -c <"$f")" "$(sha256sum "$f" 2>/dev/null | cut -c1-16)"; else cat "$f"; fi'  # verdict only: NEVER copy env content into telemetry
check read-init-cmdline info sh -c 'tr "\\0" " " < /proc/1/cmdline 2>&1 | head -c 60'
check read-self-caps  info sh -c "grep Cap /proc/self/status"

# ===================== 6. KERNEL SUBSYSTEM SYSCALLS ===================
sec "6. Kernel subsystem syscalls (defense-in-depth; override via --expect)"
hcheck ks-bpf          deny bpf
hcheck ks-perf         deny perf
hcheck ks-userfaultfd  deny uffd
hcheck ks-io_uring     deny uring        # ALLOW here => pair seccomp with policy
hcheck ks-keyring-add  info keyring
hcheck ks-finit-module deny finitmod
hcheck ks-kexec        deny kexec

# ===================== 7. DEVICES =====================================
sec "7. Device nodes"
hcheck dev-kmsg-open   deny openw /dev/kmsg
hcheck dev-mem-open    deny openw /dev/mem
hcheck dev-kmem-open   deny openw /dev/kmem
hcheck dev-port-open   deny openw /dev/port
hcheck dev-console-open deny openw /dev/console
hcheck dev-ldpreload-open deny openw /etc/ld.so.preload
[ -S /var/run/docker.sock ] && hcheck dev-docker-sock deny openw /var/run/docker.sock

# ===================== 8. PROCESS / IPC ===============================
sec "8. Process & IPC"
hcheck ipc-ptrace-child  allow ptrace-self
hcheck ipc-ptrace-sibling info ptrace-sibling   # same-uid NON-child: the agent-to-agent case
hcheck ipc-ptrace-init   deny ptrace-init
hcheck ipc-pvm-init      deny pvm 1             # process_vm_readv on init (bytes never printed)
hcheck ipc-pidfd-getfd   deny pidfdgetfd 1      # steal fds from init
check proc-kill0-init  info kill -0 1
check proc-1-ns-open   deny sh -c "exec 3< /proc/1/ns/mnt"
hcheck net-abstract-bind info abstract landscan-probe
hcheck fs-landlock-compose allow llcompose        # self-restriction must stack, not break

# ===================== 9. PRIVILEGE RECON =============================
sec "9. Privilege surface (informational)"
if have capsh; then rec priv-cap-bounding info allow "$(capsh --print 2>/dev/null | grep -m1 CapBnd)"; else rec priv-cap-bounding info skip "no capsh"; fi
check priv-sudo        info sh -c "sudo -n true 2>&1"
rec priv-setuid-count info allow "$(find /usr/bin /bin /usr/sbin /sbin -maxdepth 1 -perm -4000 2>/dev/null | wc -l) setuid binaries visible"

# ==================== 10. RESOURCE LIMITS =============================
sec "10. Resource limits (config: memory=4g cpus=2 pids=512)"
for f in memory.max memory.current pids.max cpu.max io.max io.stat; do
  [ -r "/sys/fs/cgroup/$f" ] && printf '  cgroup %-16s %s\n' "$f" "$(head -c 80 /sys/fs/cgroup/$f | tr '\n' ' ')"
done
for f in /sys/fs/cgroup/pids/pids.max; do   # cgroup v1
  [ -r "$f" ] && printf '  cgroup %-16s %s\n' "pids/pids.max" "$(head -c 80 "$f" | tr '\n' ' ')"
done
hcheck rsrc-memhog     deny memhog "${LANDSCAN_MEMHOG_MB:-$(mem_target_mb)}"
PIDS_MAX=${LANDSCAN_PIDS_PROBE:-}
if [ -z "$PIDS_MAX" ]; then
  PIDS_MAX=$(cat /sys/fs/cgroup/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids/pids.max 2>/dev/null || echo 600)
fi
case "$PIDS_MAX" in ''|*[!0-9]*) PIDS_MAX=600;; esac   # also catches 'max'
[ "$PIDS_MAX" -gt 900 ] && PIDS_MAX=900
[ "$PIDS_MAX" -lt 5 ] && PIDS_MAX=5
n=0
while [ "$n" -lt "$PIDS_MAX" ]; do
  before=$(jobs -r | wc -l)
  sleep 20 2>/dev/null &
  after=$(jobs -r | wc -l)
  if [ "$after" -le "$before" ]; then break; fi        # fork failed: at the real ceiling; do NOT retry-stall
  n=$after
done
sleep 1
rec rsrc-pids-ceiling info allow "forked $n before stall (assumed ceiling=$PIDS_MAX) — compare vs config pids=512"
jobs -p | xargs -r kill 2>/dev/null; wait 2>/dev/null
FILL_MB=${LANDSCAN_FILL_MB:-$(fill_target_mb)}
if have dd; then
  out=$(timeout 60 dd if=/dev/zero of="$SCRATCH/fill" bs=1M count="$FILL_MB" 2>&1 | tail -1)
  rec rsrc-disk-fill info allow "$out (expect EDQUOT/ENOSPC if quota exists)"; rm -f "$SCRATCH/fill"
fi

# ==================== 11. EGRESS CHANNEL MAP ==========================
sec "11. Egress channel map (informational; config allows 80/443/8443)"
CAN=${LANDSCAN_CANARY:-canary.invalid}
tcp_probe(){ if timeout 6 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then echo open; else echo closed; fi; }
for p in 80 443 8443 22 9999; do
  rec "net-tcp-$p" info "$(tcp_probe "$CAN" $p)" "→ $CAN:$p"
done
if have curl; then
  code=$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' 'https://1.1.1.1/dns-query?name=example.com' 2>/dev/null); [ "$code" = 000 ] && code=blocked
  rec net-doh info allow "$code DoH-over-443"
  mcode=$(curl -s --max-time 4 -o /dev/null -w '%{http_code}' http://169.254.169.254/ 2>/dev/null); [ "$mcode" = 000 ] && mcode=blocked
  rec net-metadata info allow "$mcode cloud-metadata"
else
  rec net-doh info skip "no curl"; rec net-metadata info skip "no curl"
fi
rec net-dns-udp info allow "$(getent hosts example.com >/dev/null 2>&1 && echo resolving || echo no-resolve) arbitrary-DNS"
have dig && rec net-dns-arbitrary-ns info allow "$(dig +short @1.1.1.1 example.com >/dev/null 2>&1 && echo reachable || echo blocked) direct-NS-query"
for port in 2375 2376 8080 9090; do
  rec "net-local-$port" info "$(tcp_probe 127.0.0.1 $port) localhost-daemon"
done
hcheck net-rawsock deny rawsock
hcheck net-pktsock deny pktsock
hcheck net-netlink-route info netlink   # ALLOW = host route table readable

# ==================== SUMMARY / BASELINE ==============================
echo
echo "=== SUMMARY ==="
tot=${#ORDER[@]}
echo "checks: $tot · as-expected/info: $((tot-UNEX)) · UNEXPECTED:$UNEX"
[ $UNEX -gt 0 ] && echo "investigate:$UNEXLIST"
if [ -n "$BASELINE" ]; then
  for n in "${ORDER[@]}"; do printf '%s\t%s\t%s\n' "$n" "${GOT[$n]}" "${DETAIL[$n]}" >> "$BASELINE"; done
  echo "baseline written: $BASELINE"
fi
if [ ${#OLD[@]} -gt 0 ]; then
  echo "--- diff vs $CHECK ---"
  for n in "${ORDER[@]}"; do
    o=${OLD[$n]:-}; g=${GOT[$n]}; w=${OVR[$n]:-${WANT[$n]}}
    [ -z "$o" ] && { echo "  NEW      $n ($g)"; continue; }
    [ "$o" = "$g" ] && continue
    if [ "$g" = "$w" ]; then echo "  IMPROVED $n: $o → $g"
    elif [ "$o" = "$w" ]; then echo "  REGRESSION $n: $o → $g"
    else echo "  CHANGED  $n: $o → $g"; fi
  done
fi
if [ "$ADOPT" = 1 ]; then
  mkdir -p "$STATE"
  : > "$STATE/expect.tsv"
  for n in "${ORDER[@]}"; do
    case "${WANT[$n]}" in info) continue;; esac
    printf '%s\t%s\n' "$n" "${GOT[$n]}" >> "$STATE/expect.tsv"
  done
  echo "expect table adopted: $STATE/expect.tsv (future runs treat these verdicts as expected)"
fi
echo "SWEEP COMPLETE"
exit $([ $UNEX -eq 0 ] && echo 0 || echo 1)
