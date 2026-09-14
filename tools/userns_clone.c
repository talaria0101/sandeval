/*
 * userns_clone.c — probe for the seccomp denylist missing `clone(2)`.
 *
 * bailey denies `unshare(2)` and `setns(2)` but not `clone(2)`. Cloning with
 * CLONE_NEWUSER nonetheless creates a new user namespace in which the caller
 * is mapped to root and holds a full capability set. This program is the
 * smallest proof: it clones a child into a new user namespace and prints the
 * child's CapEff from /proc/self/status.
 *
 * Build:  cc -O2 -o userns_clone userns_clone.c
 * Exit:   0 = clone succeeded (capabilities printed), 1 = clone blocked,
 *         2 = setup failure.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int child(void *arg) {
    (void)arg;
    char buf[8192];
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0)
        _exit(3);
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0)
        n = 0;
    buf[n] = '\0';
    /* Print only the two lines that matter, so the caller can grep them. */
    for (char *line = strtok(buf, "\n"); line; line = strtok(NULL, "\n")) {
        if (strncmp(line, "CapEff:", 7) == 0 || strncmp(line, "CapPrm:", 7) == 0 ||
            strncmp(line, "NSpid:", 6) == 0)
            dprintf(1, "%s\n", line);
    }
    _exit(0);
}

int main(void) {
    const size_t stack_size = 1 << 20;
    char *stack = malloc(stack_size);
    if (!stack) {
        perror("malloc");
        return 2;
    }
    /* The child entry, the top of its stack, and the namespace flag. */
    int pid = clone(child, stack + stack_size, CLONE_NEWUSER | SIGCHLD, NULL);
    if (pid < 0) {
        perror("clone");
        return 1;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 2;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 2;
}
