/*
 * io_uring_open.c — compare a direct openat(2) with IORING_OP_OPENAT.
 *
 * Landlock and seccomp hooks were retrofitted onto io_uring years after the
 * subsystem shipped, so a policy enforced on openat(2) may not be enforced on
 * the async path. The helper opens the same path twice: once directly, once
 * through a 4-entry ring, always O_WRONLY. Any fd the ring returns is proven
 * with a real write(2) of one byte — an fd we cannot write to proves nothing.
 *
 * argv: <path>
 * Exit codes classify the outcome; stdout carries key=value detail lines.
 *   10  uring fd returned AND write accepted     -> true bypass
 *   11  both open attempts denied                -> control holds
 *   12  the direct open already succeeded        -> bad precondition
 *   13  io_uring_setup returned ENOSYS           -> kernel too old
 *   14  io_uring_setup/enter failed otherwise    -> see setup_errno/enter_errno
 *   15  uring fd returned but write() -> EBADF   -> flag encoding unclear
 *   16  uring fd returned, write denied          -> policy honoured via uring
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
#ifndef SYS_io_uring_enter
#define SYS_io_uring_enter 426
#endif
#ifndef IORING_ENTER_GETEVENTS
#define IORING_ENTER_GETEVENTS (1U << 0)
#endif

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    const int flags = O_WRONLY;

    int direct = open(path, flags);
    if (direct >= 0) {
        printf("direct=OK\n");
        close(direct);
        return 12;
    }
    printf("direct_errno=%d\n", errno);

    struct io_uring_params p;
    memset(&p, 0, sizeof(p));
    int ring = (int)syscall(SYS_io_uring_setup, 4, &p);
    if (ring < 0) {
        printf("setup_errno=%d\n", errno);
        return (errno == ENOSYS) ? 13 : 14;
    }
    printf("setup=OK sq_entries=%u cq_entries=%u\n", p.sq_entries, p.cq_entries);

    size_t sq_sz = (size_t)p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cq_sz = (size_t)p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    unsigned char *sq = mmap(NULL, sq_sz, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQ_RING);
    unsigned char *cq = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_CQ_RING);
    struct io_uring_sqe *sqes = mmap(NULL, (size_t)p.sq_entries * sizeof(struct io_uring_sqe),
                                     PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                                     ring, IORING_OFF_SQES);
    if (sq == MAP_FAILED || cq == MAP_FAILED || sqes == MAP_FAILED) {
        printf("mmap=FAIL\n");
        return 14;
    }

    struct io_uring_sqe *sqe = &sqes[0];
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_OPENAT;
    sqe->fd = AT_FDCWD;
    sqe->addr = (unsigned long)path;
    /* Kernels differ on where OPENAT reads its flags; set every plausible
     * slot so an honest write(2) probe, not an encoding accident, decides. */
    sqe->off = (__u64)(unsigned)flags;
    sqe->open_flags = (unsigned)flags;
    sqe->len = 0;

    unsigned *sq_head = (unsigned *)(sq + p.sq_off.head);
    unsigned *sq_tail = (unsigned *)(sq + p.sq_off.tail);
    unsigned *sq_array = (unsigned *)(sq + p.sq_off.array);
    unsigned *cq_head = (unsigned *)(cq + p.cq_off.head);
    unsigned *cq_tail = (unsigned *)(cq + p.cq_off.tail);
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(cq + p.cq_off.cqes);

    unsigned tail = *sq_tail;
    sq_array[tail & (p.sq_entries - 1)] = 0; /* SQE index 0 */
    *sq_tail = tail + 1;

    int ret = (int)syscall(SYS_io_uring_enter, ring, 1U, 1U, IORING_ENTER_GETEVENTS, NULL);
    if (ret < 0) {
        printf("enter_errno=%d\n", errno);
        close(ring);
        return 14;
    }
    for (int i = 0; i < 5000 && *cq_head == *cq_tail; i++) {
        usleep(1000);
    }
    if (*cq_head == *cq_tail) {
        printf("cqe=TIMEOUT\n");
        close(ring);
        return 14;
    }
    struct io_uring_cqe cqe = cqes[*cq_head & (p.cq_entries - 1)];
    *cq_head = *cq_head + 1;
    close(ring);

    printf("cqe_res=%d\n", cqe.res);
    if (cqe.res < 0) {
        printf("uring_errno=%d\n", -cqe.res);
        return 11;
    }

    int fd = cqe.res;
    ssize_t w = write(fd, "s", 1);
    if (w == 1) {
        printf("uring_write=OK\n");
        close(fd);
        return 10;
    }
    printf("uring_write_errno=%d\n", errno);
    close(fd);
    return (errno == EBADF) ? 15 : 16;
}
