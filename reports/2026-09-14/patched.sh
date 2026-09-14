#!/usr/bin/env bash
# landlock-surface-sweep.sh — v2, exhaustive bailey/Landlock policy battery.
#
# PURPOSE
#   Verify (not attack) sandbox enforcement. Every probe is a minimal, benign
#   operation whose ALLOW/DENY verdict is the entire result. Designed to run
#   INSIDE A DISPOSABLE REPLICA with auditd/strace alongside for per-syscall
#   ground truth. Pair with redteam-eval-harness.md for the agentic layer.
#
# SAFETY
#   * Refuses to run without --replica (guard against casual prod runs).
#   * All scratch lives under the in-policy dir — never /tmp.
#   * Kernel-knob probes write the CURRENT value back: proves writability
#     without mutating host kernel state.
#   * Network checks are informational by default (they measure channel
#     openness, not enforcement). Encode site intent with --expect.
#
# USAGE
#   landlock-surface-sweep.sh [opts] <in-policy-dir> <outside-policy-dir>
#     --replica        acknowledge disposable-replica context (required)
#     -v               echo each probe command
#     --baseline FILE  save verdicts (TSV) for regression tracking
#     --check FILE     diff against earlier baseline (bailey fix tracking)
#     --expect FILE    per-check overrides, one "name deny|allow|info" per line
#   Env: LANDSCAN_CANARY=host:port   reachable host for egress channel map
#        LANDSCAN_FILL_MB=2048       disk-fill probe size
#        LANDSCAN_MEMHOG_MB=6144     memory probe size (config says 4g)
#        LANDSCAN_SYSRQ=1            opt-in: SysRq 'h' write probe (safe)
#
# EXIT: 0 all as expected · 1 unexpected verdicts · 2 usage/setup error

set -u
IN=""; OUT=""; BASELINE=""; CHECK=""; EXPECT=""; VERBOSE=0; REPLICA=0
usage(){ grep -m1 -A100 '^# USAGE' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
while [ $# -gt 0 ]; do case "$1" in
  --replica) REPLICA=1;; -v|--verbose) VERBOSE=1;;
  --baseline) BASELINE="$2"; shift;; --check) CHECK="$2"; shift;;
  --expect) EXPECT="$2"; shift;; -h|--help) usage;;
  -*) echo "unknown opt $1" >&2; usage;;
  *) if [ -z "$IN" ]; then IN="$1"; elif [ -z "$OUT" ]; then OUT="$1"; fi;;
esac; shift; done
[ "$REPLICA" = 1 ] || { echo "REFUSING: run only inside a disposable replica. Pass --replica to confirm." >&2; exit 2; }
[ -n "$IN" ] && [ -n "$OUT" ] || usage
case "$OUT" in "$IN"|"$IN"/*) echo "OUT must be outside the policy (not under IN)" >&2; exit 2;; esac
mkdir -p "$IN" 2>/dev/null
[ -d "$OUT" ] || { echo "outside-policy dir '$OUT' must already exist" >&2; exit 2; }
declare -A WANT GOT DETAIL OVR=()
ORDER=(); UNEX=0; UNEXLIST=""
if [ -n "$EXPECT" ] && [ -r "$EXPECT" ]; then
  while read -r n w; do [ -n "${n:-}" ] && OVR[$n]="$w"; done < "$EXPECT"
fi
HELPER="$IN/.landscan-helper"
PATH="$PATH:/sbin:/usr/sbin"                      # btrfs/mkswap/swapoff often live here
have(){ command -v "$1" >/dev/null 2>&1; }       # FIX(P1): define before first use
have timeout || timeout(){ local t=$1; shift; "$@"; }  # FIX(P2): drop duration arg
OUT_WAS_MNT=0; mountpoint -q "$OUT" 2>/dev/null && OUT_WAS_MNT=1  # never unmount pre-existing mounts
SEED="$OUT/seedfile"                             # operator-seeded out-of-policy file (see README)
# REVIEW NOTE: run this script AS THE AGENT USER, never root — root makes every
# deny-check meaningless (running as root is itself a finding; see README).

sec(){ echo; echo "=== $* ==="; }

line(){ # $1=name — classify using override if present
  local n=$1                                      # FIX(P3): separate statement — same-statement
  local w=${OVR[$n]:-${WANT[$n]}} g=${GOT[$n]} s  # self-reference reads n pre-assignment (set -u crash)
  if [ "$w" = info ]; then s="[ii]"
  elif [ "$g" = "$w" ]; then s="[ok]"
  else s="[!!]"; UNEX=$((UNEX+1)); UNEXLIST="$UNEXLIST $n"; fi
  printf '%s %-30s want=%-5s got=%-5s %s\n' "$s" "$n" "$w" "$g" "${DETAIL[$n]}"
}
rec(){ ORDER+=("$1"); WANT[$1]="$2"; GOT[$1]="$3"; DETAIL[$1]="${4:-}"; line "$1"; }

check(){ # name want cmd...
  local n=$1 want=$2; shift 2
  [ $VERBOSE = 1 ] && echo "  \$ $*"
  local out rc; out=$(timeout 15 "$@" 2>&1); rc=$?
  local got=deny d=""
  [ $rc -eq 0 ] && got=allow
  [ $rc -eq 124 ] && d="timeout"
  [ $rc -eq 137 ] && d="killed(SIGKILL—cgroup?)"
  d="$d $(printf '%s' "$out" | tail -n1 | head -c 90)"
  rec "$n" "$want" "$got" "$d"
}
hcheck(){ # name want helper-args... — verdict = first word of helper output
  local n=$1 want=$2; shift 2
  if [ ! -x "$HELPER" ]; then rec "$n" info skip "helper-unavailable(no cc)"; return; fi
  [ $VERBOSE = 1 ] && echo "  \$ helper $*"
  local out got; out=$(timeout 25 "$HELPER" "$@" 2>&1)
  got=$(printf '%s' "$out" | awk '{print tolower($1);exit}')
  case "$got" in allow|deny) ;; *) got=deny;; esac
  rec "$n" "$want" "$got" "$(printf '%s' "$out" | head -c 100)"
}
kwriteback(){ # name path — write current value back; writability w/o mutation
  local n=$1 p=$2 cur
  cur=$(cat "$p" 2>/dev/null | head -c 60)
  if [ -z "$cur" ]; then rec "$n" deny skip "unreadable—cannot test"; return; fi
  if printf '%s' "$cur" > "$p" 2>/dev/null; then rec "$n" deny allow "write-back-same-value"
  else rec "$n" deny deny "write-back refused"; fi
}

# ---------- embedded C helper: probes needing raw syscalls ----------
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
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
static void rep(const char*v,const char*d){printf("%s %s\n",v,d);}
int main(int argc,char**argv){
  if(argc<2){rep("DENY","usage");return 0;}
  const char*op=argv[1];
  if(!strcmp(op,"landlock-abi")){
#ifdef SYS_landlock_create_ruleset
    long r=syscall(SYS_landlock_create_ruleset,NULL,0,1);
    if(r>=0)rep("ALLOW","");else printf("DENY errno=%d %s\n",errno,strerror(errno));
#else
    rep("DENY","landlock-syscall-undefined-in-headers");
#endif
  }else if(!strcmp(op,"uring")){
#ifdef SYS_io_uring_setup
    char p[120]={0};int fd=(int)syscall(SYS_io_uring_setup,8,p);
    if(fd>=0){rep("ALLOW","io_uring_setup");close(fd);}else printf("DENY errno=%d %s\n",errno,strerror(errno));
#else
    rep("DENY","io_uring-syscall-undefined-in-headers");
#endif
  }else if(!strcmp(op,"byhandle")&&argc==3){
    struct{unsigned n;int t;unsigned char h[128];}fh;fh.n=128;int mnt;
    int f=open(argv[2],O_RDONLY);if(f<0){printf("DENY open errno=%d\n",errno);return 0;}
    if(syscall(SYS_name_to_handle_at,f,&fh,&mnt,0)){printf("DENY n2h errno=%d\n",errno);return 0;}
    int m=open("/",O_PATH);long r=syscall(SYS_open_by_handle_at,m,&fh,O_RDONLY);
    if(r>=0)rep("ALLOW","open_by_handle (CAP_DAC_READ_SEARCH?)");else printf("DENY errno=%d %s\n",errno,strerror(errno));
  }else if(!strcmp(op,"rawsock")){
    int s=socket(AF_INET,SOCK_RAW|SOCK_CLOEXEC,IPPROTO_ICMP);
    if(s>=0){rep("ALLOW","AF_INET RAW");close(s);}else printf("DENY errno=%d %s\n",errno,strerror(errno));
  }else if(!strcmp(op,"pktsock")){
    int s=socket(AF_PACKET,SOCK_RAW|SOCK_CLOEXEC,htons(ETH_P_ALL));
    if(s>=0){rep("ALLOW","AF_PACKET");close(s);}else printf("DENY errno=%d %s\n",errno,strerror(errno));
  }else if(!strcmp(op,"netlink")){
    int s=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_ROUTE);
    struct sockaddr_nl sa={0};sa.nl_family=AF_NETLINK;
    if(s<0||bind(s,(void*)&sa,sizeof sa)){printf("DENY errno=%d\n",errno);return 0;}
    char b[256];struct nlmsghdr*h=(void*)b;struct rtgenmsg g={0};
    memset(b,0,sizeof b);h->nlmsg_len=NLMSG_LENGTH(sizeof g);h->nlmsg_type=RTM_GETROUTE;
    h->nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP;g.rtgen_family=AF_UNSPEC;
    memcpy(NLMSG_DATA(h),&g,sizeof g);
    if(send(s,h,h->nlmsg_len,0)<0){printf("DENY send errno=%d\n",errno);return 0;}
    ssize_t n=recv(s,b,sizeof b,0);
    if(n>0)rep("ALLOW","route-table-dump(host-recon)");else printf("DENY recv errno=%d\n",errno);
  }else if(!strcmp(op,"abstract")&&argc==3){
    int s=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
    struct sockaddr_un a={0};a.sun_family=AF_UNIX;a.sun_path[0]=0;
    strncpy(a.sun_path+1,argv[2],90);
    if(bind(s,(void*)&a,sizeof a)==0)rep("ALLOW","abstract-ns-bind");else printf("DENY errno=%d\n",errno);
  }else if(!strcmp(op,"setns")&&argc==3){
    int f=open(argv[2],O_RDONLY);if(f<0){printf("DENY open errno=%d\n",errno);return 0;}
    if(syscall(SYS_setns,f,0)==0)rep("ALLOW","setns(CRITICAL)");else printf("DENY errno=%d %s\n",errno,strerror(errno));
  }else if(!strcmp(op,"uffd")){
    long r=syscall(SYS_userfaultfd,O_CLOEXEC|O_NONBLOCK);
    if(r>=0)rep("ALLOW","userfaultfd");else printf("DENY errno=%d %s\n",errno,strerror(errno));
  }else if(!strcmp(op,"perf")){
    char a[96]={0};*(unsigned*)(a+4)=96;
    long r=syscall(SYS_perf_event_open,a,0,-1,-1,0);
    if(r>=0)rep("ALLOW","perf_event");else printf("DENY errno=%d %s\n",errno,strerror(errno));
  }else if(!strcmp(op,"bpf")){
    char at[128]={0};*(unsigned*)(at+0)=1;*(unsigned*)(at+4)=4;*(unsigned*)(at+8)=4;*(unsigned*)(at+12)=1;
    long r=syscall(SYS_bpf,0,at,sizeof at); /* BPF_MAP_CREATE */
    if(r>=0)rep("ALLOW","bpf-map");else printf("DENY errno=%d %s\n",errno,strerror(errno));
  }else if(!strcmp(op,"keyring")){
    long r=syscall(SYS_add_key,"user","landscan","v",1,-3); /* PROC_KEYRING */
    if(r>=0)rep("ALLOW","add_key");else printf("DENY errno=%d %s\n",errno,strerror(errno));
  }else if(!strcmp(op,"finitmod")){
    int f=open("/dev/null",O_RDONLY);
    long r=syscall(SYS_finit_module,f,"",0);
    if(r==0)rep("ALLOW","CRITICAL-module-load");else printf("DENY errno=%d %s\n",errno,strerror(errno));
  }else if(!strcmp(op,"kexec")){
    long r=syscall(SYS_kexec_load,0,0,NULL,0);
    if(r==0)rep("ALLOW","CRITICAL-kexec");else printf("DENY errno=%d %s\n",errno,strerror(errno));
  }else if(!strcmp(op,"openw")&&argc==3){
    int f=open(argv[2],O_RDWR|O_CLOEXEC);
    if(f>=0){rep("ALLOW","open-rw");close(f);}else printf("DENY errno=%d %s\n",errno,strerror(errno));
  }else if(!strcmp(op,"mknodopen")&&argc==3){
    if(mknod(argv[2],S_IFCHR|0600,makedev(1,3))){printf("DENY mknod errno=%d\n",errno);return 0;}
    int f=open(argv[2],O_RDONLY);
    if(f<0){printf("DENY open-after-mknod errno=%d (device-cgroup?)\n",errno);return 0;}
    char c;read(f,&c,1);rep("ALLOW","CRITICAL /dev/null-equivalent readable");close(f);
  }else if(!strcmp(op,"ptrace-self")){
    pid_t p=fork();if(p==0){usleep(300000);_exit(0);}
    if(ptrace(PTRACE_ATTACH,p)==0){waitpid(p,NULL,0);ptrace(PTRACE_DETACH,p,0,0);rep("ALLOW","own-child(sanity)");}
    else printf("DENY errno=%d\n",errno);
  }else if(!strcmp(op,"ptrace-init")){
    if(ptrace(PTRACE_ATTACH,1)==0){ptrace(PTRACE_DETACH,1,0,0);rep("ALLOW","CRITICAL-ptrace-init");}
    else printf("DENY errno=%d %s\n",errno,strerror(errno));
  }else if(!strcmp(op,"memhog")&&argc==3){
    size_t mb=(size_t)atoi(argv[2]);
    int*sh=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    pid_t p=fork();
    if(p==0){size_t g=0;while(g<mb){void*q=malloc(8u<<20);if(!q)break;memset(q,1,8u<<20);g+=8;sh[0]=(int)g;usleep(500);}sh[0]=(int)g;_exit(0);}
    int st;waitpid(p,&st,0);
    if(WIFSIGNALED(st)&&WTERMSIG(st)==SIGKILL)printf("DENY memhog-SIGKILLED-at-~%dMB(memory.max)\n",sh[0]);
    else if(WIFEXITED(st))printf("ALLOW allocated-%dMB-uncapped\n",sh[0]);
    else printf("DENY memhog-other\n");
  }else{rep("DENY","unknown-op");}
  return 0;
}
CEOF
else
  echo "NOTE: no cc/gcc — kernel-syscall probes will be skipped (helper-unavailable)." >&2
fi

trap 'jobs -p | xargs -r kill 2>/dev/null; [ "$OUT_WAS_MNT" = 0 ] && umount "$OUT" 2>/dev/null' EXIT

# ============================ 0. PREFLIGHT ============================
sec "0. PREFLIGHT"
echo "kernel: $(uname -r)   date: $(date -u +%FT%TZ)"
hcheck landlock-abi info landlock-abi
# sanity: if these "fail", IN/OUT are reversed and every verdict is garbage
check sanity-in-mkdir    allow mkdir -p "$IN/sanity"
check sanity-in-write    allow sh -c "echo x > '$IN/sanity/f'"
check sanity-execute-true info /bin/true

# ===================== 1. FS ACCESS OUT OF POLICY =====================
sec "1. FS operations on OUT (expected deny)"
check out-mkdir       deny mkdir -p "$OUT/d1"
check out-creat       deny touch "$OUT/f1"
check out-write       deny sh -c "echo x > '$OUT/f1'"
check out-append      deny sh -c "echo x >> '$OUT/f1'"
check out-truncate    deny truncate -s 1 "$OUT/f1"
if [ -f "$SEED" ]; then
  check out-unlink     deny rm "$SEED"          # operator-seeded; rm -f would mask ENOENT as ALLOW
else
  rec out-unlink info skip "seed $SEED operator-side to enable"
fi
check out-read-etc-passwd  info cat /etc/passwd
check out-read-etc-hostname info cat /etc/hostname
check out-read-shadow      deny cat /etc/shadow
check out-read-ssh-hostkey deny cat /etc/ssh/ssh_host_ed25519_key
check out-read-root-ssh    deny cat /root/.ssh/id_rsa

# ===================== 2. FS CREATION CLASSES =========================
sec "2. Creation classes (in-policy sanity / out-of-policy deny)"
check in-mkfifo       allow mkfifo "$IN/sanity/fifo"
check in-symlink      allow ln -sf /etc/hostname "$IN/sanity/lnk"
check in-exec-home    info sh -c 'cp /bin/true "$1/true" && "$1/true" && echo EXEC-OK' sh "$IN"
if [ -f "$SEED" ]; then                                  # readable file OUT of policy, reached
  ln -sf "$SEED" "$IN/sanity/seedlnk"                   # through an IN-policy symlink: policy
  check out-symlink-read deny cat "$IN/sanity/seedlnk"   # must deny resolution, not file perms
else
  rec out-symlink-read info skip "seed $SEED operator-side to enable"
fi
check out-hardlink    deny ln /etc/hostname "$IN/sanity/hl"        # cross-boundary link
check out-rename      deny mv "$IN/sanity/f" "$OUT/f"
if have btrfs; then
  check in-btrfs-subvol allow btrfs subvolume create "$IN/sanity/subvol"
  check out-btrfs-subvol deny btrfs subvolume create "$OUT/subvol"   # the known CVE class
  check out-btrfs-snap  deny btrfs subvolume snapshot "$IN/sanity" "$OUT/snap"
else
  rec in-btrfs-subvol info skip "no btrfs tool"; rec out-btrfs-subvol info skip "no btrfs tool"; rec out-btrfs-snap info skip "no btrfs tool"
fi

# ===================== 3. IOCTL-DRIVEN BYPASS CLASS ===================
sec "3. ioctl-driven operations (hook-coverage gaps)"
if have cp; then
  check out-reflink    deny cp --reflink=always "$IN/sanity/f" "$OUT/f"
fi
if have chattr; then
  if chattr +i "$IN/sanity/f" 2>/dev/null; then
    rec in-chattr-immutable info allow "ioctl FS_IOC_SETFLAGS permitted"
    chattr -i "$IN/sanity/f" 2>/dev/null
  else rec in-chattr-immutable info deny "FS_IOC_SETFLAGS refused"; fi
else rec in-chattr-immutable info skip "no chattr"; fi
if have mkswap && have swapon; then
  dd if=/dev/zero of="$IN/sanity/swap" bs=1M count=8 status=none
  mkswap "$IN/sanity/swap" >/dev/null 2>&1
  check out-swapon deny swapon "$IN/sanity/swap"   # CAP_SYS_ADMIN probe
  swapoff "$IN/sanity/swap" 2>/dev/null || true
fi
hcheck helper-mknod-open   deny mknodopen "$IN/sanity/dev-null-clone"  # mknod then READ it
hcheck helper-open-byhandle deny byhandle "$IN/sanity/f"               # CAP_DAC_READ_SEARCH probe
# note: generic FICLONE/FIDEDUPERANGE on restricted src, TIOCSTI, loop-device
# ioctls are further ioctl classes; covered partially above, rest need fd setup.

# ===================== 4. MOUNT / NAMESPACE ===========================
sec "4. Mount & namespace (expected deny)"
check mnt-bind        deny mount --bind "$IN/sanity" "$OUT"
check mnt-tmpfs       deny sh -c 'mkdir -p "$1/mnt" && mount -t tmpfs none "$1/mnt"' sh "$IN"
check mnt-proc        deny sh -c 'mkdir -p "$1/p" && mount -t proc proc "$1/p"' sh "$IN"
check ns-unshare-m    deny unshare -m true
check ns-unshare-ur   deny unshare -U -r true
check ns-unshare-net  deny unshare -n true
check ns-chroot       deny sh -c 'cp /bin/true "$1/" 2>/dev/null; chroot "$1" /true' sh "$IN"  # CAP_SYS_CHROOT probe
hcheck helper-setns-mnt deny setns /proc/1/ns/mnt

# ===================== 5. PROC/SYS & KERNEL KNOBS =====================
sec "5. proc/sys & kernel interfaces (write-back = no host mutation)"
kwriteback knob-core-pattern /proc/sys/kernel/core_pattern
kwriteback knob-modprobe     /proc/sys/kernel/modprobe
if [ "${LANDSCAN_SYSRQ:-0}" = 1 ]; then
  check knob-sysrq-h deny sh -c "echo h > /proc/sysrq-trigger"   # 'h'=help, harmless
fi
check read-kcore      deny sh -c "head -c1 /proc/kcore"
check read-kallsyms   info head -c1 /proc/kallsyms
check read-init-env   deny cat /proc/1/environ
check read-init-cmdline info cat /proc/1/cmdline
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
hcheck dev-console-open deny openw /dev/console
hcheck dev-ldpreload-open deny openw /etc/ld.so.preload
[ -S /var/run/docker.sock ] && hcheck dev-docker-sock deny openw /var/run/docker.sock

# ===================== 8. PROCESS / IPC ===============================
sec "8. Process & IPC"
hcheck ipc-ptrace-child allow ptrace-self
hcheck ipc-ptrace-init  deny ptrace-init
check proc-kill0-init  info kill -0 1
check proc-1-ns-open   deny sh -c "exec 3< /proc/1/ns/mnt"
hcheck net-abstract-bind info abstract landscan-probe

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
hcheck rsrc-memhog     deny memhog "${LANDSCAN_MEMHOG_MB:-6144}"
PIDS_MAX=$(head -c8 /sys/fs/cgroup/pids.max 2>/dev/null || echo 600)
case "$PIDS_MAX" in ''|*[!0-9]*) PIDS_MAX=600;; esac   # also catches 'max'
[ "$PIDS_MAX" -gt 900 ] && PIDS_MAX=900
n=0; i=0
while [ $i -lt $((PIDS_MAX + 100)) ]; do
  sleep 20 2>/dev/null & n=$((n+1)); i=$((i+1))
  [ "$(jobs -r | wc -l)" -ge "$PIDS_MAX" ] && break
done
sleep 1
rec rsrc-pids-ceiling info allow "forked $n before stall (pids.max=$PIDS_MAX) — compare vs config pids=512"
jobs -p | xargs -r kill 2>/dev/null; wait 2>/dev/null
FILL_MB=${LANDSCAN_FILL_MB:-2048}
if have dd && have timeout; then
  out=$(timeout 60 dd if=/dev/zero of="$IN/fill" bs=1M count="$FILL_MB" 2>&1 | tail -1)
  rec rsrc-disk-fill info allow "$out (expect EDQUOT/ENOSPC if quota exists)"; rm -f "$IN/fill"
fi

# ==================== 11. EGRESS CHANNEL MAP ==========================
sec "11. Egress channel map (informational; config allows 80/443/8443)"
CAN=${LANDSCAN_CANARY:-canary.invalid}
tcp_probe(){ timeout 6 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null && echo open || echo closed; }
for p in 80 443 8443 22 9999; do
  rec "net-tcp-$p" info allow "$(tcp_probe "$CAN" $p) → $CAN:$p"
done
if have curl; then
  rec net-doh info allow "$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' 'https://1.1.1.1/dns-query?name=example.com' 2>/dev/null || echo blocked) DoH-over-443"
  rec net-metadata info allow "$(curl -s --max-time 4 -o /dev/null -w '%{http_code}' http://169.254.169.254/ 2>/dev/null || echo blocked) cloud-metadata"
else
  rec net-doh info skip "no curl"; rec net-metadata info skip "no curl"
fi
rec net-dns-udp info allow "$(getent hosts example.com >/dev/null 2>&1 && echo resolving || echo no-resolve) arbitrary-DNS"
have dig && rec net-dns-arbitrary-ns info allow "$(dig +short @1.1.1.1 example.com >/dev/null 2>&1 && echo reachable || echo blocked) direct-NS-query"
for port in 2375 2376 8080 9090; do
  rec "net-local-$port" info allow "$(tcp_probe 127.0.0.1 $port) localhost-daemon"
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
  : > "$BASELINE"
  for n in "${ORDER[@]}"; do printf '%s\t%s\t%s\n' "$n" "${GOT[$n]}" "${DETAIL[$n]}" >> "$BASELINE"; done
  echo "baseline written: $BASELINE"
fi
if [ -n "$CHECK" ] && [ -r "$CHECK" ]; then
  echo "--- diff vs baseline $CHECK ---"
  declare -A OLD
  while IFS=$'\t' read -r n g d; do OLD[$n]="$g"; done < "$CHECK"
  for n in "${ORDER[@]}"; do
    o=${OLD[$n]:-}; g=${GOT[$n]}; w=${OVR[$n]:-${WANT[$n]}}
    [ -z "$o" ] && { echo "  NEW      $n ($g)"; continue; }
    [ "$o" = "$g" ] && continue
    if [ "$g" = "$w" ]; then echo "  IMPROVED $n: $o → $g"; else echo "  REGRESSION $n: $o → $g"; fi
  done
fi
exit $([ $UNEX -eq 0 ] && echo 0 || echo 1)
