// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    int ready[2];
    if (pipe(ready)) { perror("pipe"); return 1; }
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        char byte;
        close(ready[1]);
        (void)!read(ready[0], &byte, 1);
        _exit(0);
    }
    close(ready[0]);
    siginfo_t info;
    memset(&info, 0xff, sizeof(info));
    if (waitid(P_PID, child, &info, WEXITED | WNOHANG | WNOWAIT) != 0) { perror("waitid"); return 1; }
    if (info.si_signo != 0 || info.si_pid != 0) {
        fprintf(stderr, "waitid WNOHANG left si_signo=%d si_pid=%d\n", info.si_signo, info.si_pid);
        return 1;
    }
    close(ready[1]);
    memset(&info, 0, sizeof(info));
    if (waitid(P_PID, child, &info, WEXITED) != 0 || info.si_signo != SIGCHLD || info.si_pid != child ||
        info.si_code != CLD_EXITED || info.si_status != 0) {
        fprintf(stderr, "waitid exit report: signo=%d pid=%d code=%d status=%d\n",
                info.si_signo, info.si_pid, info.si_code, info.si_status);
        return 1;
    }
    puts("waitid_nohang PASS");
    return 0;
}
