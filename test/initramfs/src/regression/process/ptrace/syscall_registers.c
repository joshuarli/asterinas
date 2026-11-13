// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int await(pid_t child, int *status)
{
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 1;
    do {
        pid_t got = waitpid(child, status, __WALL | WNOHANG);
        if (got == child) return 0;
        if (got < 0 && errno != EINTR) return 1;
        struct timespec delay = { .tv_nsec = 1000000 };
        nanosleep(&delay, NULL);
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return 1;
    } while (now.tv_sec - start.tv_sec < 5);
    fputs("ptrace syscall-register wait timed out\n", stderr);
    return 1;
}

int main(void)
{
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) || raise(SIGSTOP)) _exit(2);
        if (syscall(SYS_getpid) != 12345) _exit(3);
        if (syscall(SYS_getpid) != parent) _exit(4);
        if (syscall(SYS_getpid) != 54321) _exit(5);
        _exit(0);
    }
    int status, reaped = 0, failed = await(child, &status);
    if (!failed && (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)) failed = 1;
    if (!failed && ptrace(PTRACE_SETOPTIONS, child, 0,
        PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)) failed = 1;
    unsigned stops = 0, calls = 0;
    int entry = 1;
    while (!failed) {
        if (ptrace(PTRACE_SYSCALL, child, 0, 0) || await(child, &status)) {
            failed = 1;
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            reaped = 1;
            failed = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
            if (failed) fprintf(stderr, "tracee ended with wait status %#x\n", status);
            break;
        }
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != (SIGTRAP | 0x80) || ++stops > 100) {
            failed = 1;
            break;
        }
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, child, 0, &regs)) { failed = 1; break; }
        if (entry) {
            if ((long)regs.rax != -ENOSYS) {
                fprintf(stderr, "syscall entry rax=%ld; expected %d\n", (long)regs.rax, -ENOSYS);
                failed = 1;
                break;
            }
            if (regs.orig_rax == SYS_getpid) {
                calls++;
                if (calls == 1) {
                    regs.orig_rax = (unsigned long)-1;
                    regs.rax = 12345;
                    if (ptrace(PTRACE_SETREGS, child, 0, &regs)) failed = 1;
                } else if (calls == 2) {
                    if (ptrace(PTRACE_POKEUSER, child,
                        (void *)__builtin_offsetof(struct user_regs_struct, orig_rax),
                        (void *)SYS_getppid)) failed = 1;
                }
            }
        } else if (calls == 3 && regs.orig_rax == SYS_getpid) {
            regs.rax = 54321;
            if (ptrace(PTRACE_SETREGS, child, 0, &regs)) failed = 1;
        }
        entry = !entry;
    }
    if (!reaped) {
        if (kill(child, SIGKILL) || await(child, &status)) failed = 1;
    }
    failed |= calls != 3;
    if (!failed) puts("ptrace syscall registers: entry, skip, replacement and return edits passed");
    return failed;
}
