// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) abort();
    return now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int await(pid_t pid, int *status)
{
    long deadline = milliseconds() + 10000;
    do {
        pid_t got = waitpid(pid, status, __WALL | WNOHANG);
        if (got == pid) return 0;
        if (got < 0 && errno != EINTR) { perror("waitpid"); return 1; }
        usleep(1000);
    } while (milliseconds() < deadline);
    puts("PTRACE_WITNESS_TIMEOUT");
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--child") == 0) {
        syscall(SYS_getpid);
        _exit(42);
    }
    setbuf(stdout, NULL);
    if (geteuid() == 0 && (setgroups(0, NULL) || setgid(1000) || setuid(1000))) {
        perror("drop tracer privileges");
        return 1;
    }
    if (prctl(PR_SET_DUMPABLE, 1)) return 1;
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (!child) {
        close(pipefd[0]);
        if (ptrace(PTRACE_TRACEME, 0, 0, 0)) _exit(2);
        execl("/proc/self/exe", "ptrace-unprivileged", "--child", NULL);
        _exit(3);
    }
    close(pipefd[1]);
    printf("PTRACE_WITNESS_CHILD %d\n", child);
    int status;
    int failed = await(child, &status);
    int reaped = !failed && (WIFEXITED(status) || WIFSIGNALED(status));
    if (!failed && (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)) failed = 1;
    if (!failed) {
        char byte;
        if (read(pipefd[0], &byte, 1) != 0) { perror("exec pipe not closed"); failed = 1; }
    }
    close(pipefd[0]);
    if (!failed && ptrace(PTRACE_SETOPTIONS, child, 0,
        PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK |
        PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL)) {
        perror("set options"); failed = 1;
    }
    unsigned stops = 0;
    unsigned getpid_stops = 0;
    while (!failed) {
        if (ptrace(PTRACE_SYSCALL, child, 0, 0)) { perror("resume"); failed = 1; break; }
        if (await(child, &status)) { failed = 1; break; }
        if (WIFEXITED(status)) { reaped = 1; failed = WEXITSTATUS(status) != 42; break; }
        if (WIFSIGNALED(status)) { reaped = 1; failed = 1; break; }
        if (!WIFSTOPPED(status) || ++stops > 1000) { failed = 1; break; }
        struct user_regs_struct registers;
        if (ptrace(PTRACE_GETREGS, child, 0, &registers)) { perror("get registers"); failed = 1; break; }
        if (WSTOPSIG(status) == (SIGTRAP | 0x80) && registers.orig_rax == SYS_getpid)
            getpid_stops++;
    }
    failed |= getpid_stops != 2;
    if (failed && !reaped) {
        kill(child, SIGKILL);
        if (!await(child, &status) && !WIFEXITED(status) && !WIFSIGNALED(status)) failed = 1;
    }
    printf("PTRACE_WITNESS_RESULT %s stops=%u\n", failed ? "fail" : "pass", stops);
    return failed;
}
