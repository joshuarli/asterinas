// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static void timeout(int sig)
{
    (void)sig;
    _exit(1);
}

int main(void)
{
    signal(SIGALRM, timeout);
    alarm(30);
    pid_t tracee = fork();
    if (tracee == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) || raise(SIGSTOP))
            _exit(2);
        for (int i = 0; i < 200; i++) {
            pid_t child = fork();
            if (child == 0)
                _exit(0);
            if (child < 0 || waitpid(child, NULL, 0) != child)
                _exit(3);
        }
        _exit(0);
    }
    int status;
    if (tracee < 0 || waitpid(tracee, &status, 0) != tracee ||
        ptrace(PTRACE_SETOPTIONS, tracee, 0, PTRACE_O_TRACEFORK) ||
        ptrace(PTRACE_CONT, tracee, 0, 0))
        return 1;
    for (;;) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0)
            return 1;
        if (WIFSTOPPED(status)) {
            if (ptrace(PTRACE_CONT, pid, 0, 0))
                return 1;
        } else if (pid == tracee) {
            if (!WIFEXITED(status) || WEXITSTATUS(status))
                return 1;
            puts("WITNESS_FORK_EXIT_PASS");
            return 0;
        }
    }
}
