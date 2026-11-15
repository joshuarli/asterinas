// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void handler(int sig)
{
    (void)sig;
}

static int run_case(int handled)
{
    int ready[2];
    if (pipe(ready)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]);
        struct sigaction action = { .sa_handler = handler, .sa_flags = SA_RESTART };
        sigemptyset(&action.sa_mask);
        if (handled && sigaction(SIGUSR1, &action, NULL)) _exit(2);
        if (!handled) {
            pid_t grandchild = fork();
            if (grandchild < 0) _exit(2);
            if (grandchild == 0) { usleep(400000); _exit(0); }
        }
        if (write(ready[1], "x", 1) != 1) _exit(2);
        struct timespec req = { .tv_sec = 2 }, rem = {0};
        int result = nanosleep(&req, &rem);
        if (handled) _exit(result == -1 && errno == EINTR ? 0 : 1);
        _exit(result == 0 ? 0 : 1);
    }
    close(ready[1]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 1;
    close(ready[0]);
    usleep(100000);
    int status;
    if (handled) {
        if (kill(child, SIGUSR1)) return 1;
    } else {
        if (kill(child, SIGSTOP) || waitpid(child, &status, WUNTRACED) != child ||
            !WIFSTOPPED(status) || kill(child, SIGCONT)) return 1;
    }
    if (waitpid(child, &status, 0) != child) return 1;
    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

int main(void)
{
    int stopped = run_case(0);
    int handled = run_case(1);
    printf("stop_continue=%s handled_sa_restart=%s\n", stopped ? "FAIL" : "PASS", handled ? "FAIL" : "PASS");
    return stopped || handled;
}
