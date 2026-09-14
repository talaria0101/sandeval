# HANDOFF / RESUME — sweep v4 (2026-09-14, session ending)

## State: WORKING, committed to main
- v4 = v3 + zero-flag automation + ioctl route enumeration + raw btrfs ioctls.
- tests/run-tests.sh: ALL GREEN (incl. new zero-flag auto-mode + --adopt tests).
- Replica battery (LANDSCAN_PIDS_PROBE=25 etc): 134 checks, rc=1 (17 unexpected = real
  sandbox findings), baseline written.

## Done this pass
- Flags -> defaults: IN/OUT auto-discovered (OUT = first write-denied dir from
  /opt /var/tmp /mnt /srv /run /media /tmp, else /tmp+notice); auto-baseline +
  auto-diff via .landscan-state/latest.tsv (OLD preloaded before overwrite);
  --adopt writes .landscan-state/expect.tsv, auto-loaded next run; --safe gates
  host-global probes (sysrq/swap/clock) which are ON by default now.
- Heuristic sizing: memhog=1.25x memory.max (else 2% RAM, 256-1024MB);
  fill=2% free (64-2048MB); env overrides still win.
- btrfs: subvol/snap via RAW ioctl in C helper (BTRFS_IOC_SUBVOL_CREATE_S /
  SNAP_CREATE_S, pid-suffixed names for idempotency) — no btrfs-tool dependency;
  ENOTTY = honest inconclusive on non-btrfs.
- ioctlscan helper op: table-driven enumeration per fd (FS_IOC_GETFLAGS/SETFLAGS-
  clear/FSGETXATTR, FIBMAP, TIOCSTI, TIOCCONS, TIOCGWINSZ, LOOP_CTL_GET_FREE,
  DM_VERSION, DM_LIST_DEVICES, KVM_GET_API_VERSION, TUNSETIFF, EVIOCGNAME,
  FBIOGET_VSCREENINFO, SG_IO INQUIRY) over targets: scratch file+dir, /dev/tty,
  loop-control, mapper/control, kvm, net/tun, input/event0, fb0, sda, nvme0n1,
  dri/card0. Verdicts: REACHABLE/DENIED/NOTTY/ERR -> per-request baseline entries.

## Environment gotchas found (keep these!)
- /dev/fd ABSENT in this sandbox: process substitution <(...) FAILS
  ("/dev/fd/63: No such file or directory"). Never use < <(); use temp files.
- $HOME=/state/home and bash 5.3 TILDE-EXPANDS the replacement in ${var//pat/~}
  -> "~" became "/state/home". Use "-", never "~", as replacement char.
- Helper arg counts: subvol takes 1 arg (name auto via getpid), snap takes 2.

## Remaining (next session)
1. Cosmetic: ioctl-* check names in output start with full path (short= name is
   long); consider basename for display. (grep '^\[.\] ioctl-' didn't match for
   unknown reason — names DO appear in output/baseline; investigate trivially.)
2. README: document auto mode, --safe/--adopt, .landscan-state, ioctl enumeration
   (v4 sections not yet written into README; HANDOFF covers facts).
3. Full test suite re-run after the last two fixes (process-substitution removal +
   short= rename) — suite was green before them; battery green after.
4. Consider: FIDEDUPERANGE + FS_IOC_SETFLAGS-with-real-flags probes; tune ioctlscan
   arg for TUNSETIFF to avoid interface creation on cap-full sandboxes (currently
   non-persistent, auto-destroyed on close).

## UPDATE (same day, continuation)
- [DONE] ioctl names now basename-based (ioctl-tty-TIOCSTI, ioctl-f-FIBMAP, ...);
  the "grep didn't match" mystery was a bad pattern: '^\[.\] ' cannot match
  '[ii]' — use '^\[..\] '. No code issue.
- [DONE] README: auto mode, --safe/--adopt, .landscan-state, ioctl enumeration,
  raw btrfs ioctls, portability notes.
- [DONE] Full test suite re-run after all fixes: ALL TESTS PASSED (8 groups).
- [DONE] Zero-flag auto battery validated on real replica: 134 checks, 40 ioctl
  entries, auto-OUT=/opt discovered, auto-baseline written, rc=1 (17 unexpected
  = genuine findings: chroot, pidfd_getfd-init, io_uring, ptrace-child, etc).
- Remaining idea (optional): FIDEDUPERANGE probe; per-request 'want' tuning for
  REACHABLE-classified dangerous ioctls (currently all info).
