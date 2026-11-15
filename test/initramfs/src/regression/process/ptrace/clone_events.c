// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static int child_fn(void *arg)
{
    (void)arg;
    _exit(0);
}

static int run_case(int clone_case)
{
    pid_t tracee = fork();
    if (tracee == 0) {
        static char stack[65536];
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) || raise(SIGSTOP))
            _exit(10);
        signal(SIGUSR1, SIG_IGN);
        pid_t child = clone_case ? clone(child_fn, stack + sizeof(stack), SIGUSR1, NULL) : fork();
        if (child == 0)
            _exit(0);
        if (child < 0)
            _exit(11);
        if (!clone_case)
            waitpid(child, NULL, 0);
        _exit(0);
    }
    int status;
    unsigned long child = 0;
    int event = clone_case ? PTRACE_EVENT_CLONE : PTRACE_EVENT_FORK;
    if (tracee < 0 || waitpid(tracee, &status, 0) != tracee || !WIFSTOPPED(status) ||
        ptrace(PTRACE_SETOPTIONS, tracee, 0, PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE) ||
        ptrace(PTRACE_CONT, tracee, 0, 0) || waitpid(tracee, &status, 0) != tracee ||
        (status >> 8) != (SIGTRAP | (event << 8)) ||
        ptrace(PTRACE_GETEVENTMSG, tracee, 0, &child) || child == 0 ||
        waitpid((pid_t)child, &status, __WALL) != (pid_t)child ||
        !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP ||
        ptrace(PTRACE_CONT, (pid_t)child, 0, 0) || ptrace(PTRACE_CONT, tracee, 0, 0)) {
        fprintf(stderr, "case %d failed: status=%x child=%lu\n", clone_case, status, child);
        return 1;
    }
    pid_t stopped;
    while ((stopped = waitpid(-1, &status, __WALL)) > 0) {
        if (WIFSTOPPED(status)) {
            if (ptrace(PTRACE_CONT, stopped, 0, 0))
                return 1;
        } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    if (run_case(0) || run_case(1)) {
        puts("WITNESS_PTRACE_CLONE_FAIL");
        return 1;
    }
    puts("WITNESS_PTRACE_CLONE_PASS");
    return 0;
}
