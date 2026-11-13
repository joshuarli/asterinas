// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int report_fd;

static void *replace(void *unused)
{
    (void)unused;
    pid_t tid = syscall(SYS_gettid);
    if (write(report_fd, &tid, sizeof(tid)) != sizeof(tid)) _exit(3);
    execl("/proc/self/exe", "ptrace-thread-exec", "--after-exec", NULL);
    _exit(4);
}

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
    fputs("ptrace thread-exec wait timed out\n", stderr);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--after-exec")) _exit(37);
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (!child) {
        close(pipefd[0]);
        report_fd = pipefd[1];
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) || raise(SIGSTOP)) _exit(2);
        pthread_t worker;
        if (pthread_create(&worker, NULL, replace, NULL) || pthread_join(worker, NULL)) _exit(5);
        _exit(6);
    }
    close(pipefd[1]);
    int status, reaped = 0, failed = await(child, &status);
    unsigned long former_tid = 0;
    unsigned execs = 0, stops = 0;
    if (!failed && (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)) failed = 1;
    if (!failed && ptrace(PTRACE_SETOPTIONS, child, 0,
        PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL)) failed = 1;
    while (!failed) {
        if (ptrace(PTRACE_SYSCALL, child, 0, 0) || await(child, &status)) {
            failed = 1;
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            reaped = 1;
            failed = !WIFEXITED(status) || WEXITSTATUS(status) != 37;
            if (failed) fprintf(stderr, "exec tracee ended with wait status %#x\n", status);
            break;
        }
        if (!WIFSTOPPED(status) || ++stops > 1000) { failed = 1; break; }
        if ((unsigned)status >> 16 == PTRACE_EVENT_EXEC) {
            execs++;
            if (ptrace(PTRACE_GETEVENTMSG, child, 0, &former_tid)) failed = 1;
        }
    }
    if (!reaped) {
        if (kill(child, SIGKILL) || await(child, &status)) failed = 1;
    }
    pid_t worker_tid = 0;
    if (read(pipefd[0], &worker_tid, sizeof(worker_tid)) != sizeof(worker_tid)) failed = 1;
    char byte;
    if (read(pipefd[0], &byte, 1) != 0 || close(pipefd[0])) failed = 1;
    if (execs != 0 || former_tid != 0 || worker_tid <= 0 || worker_tid == child) {
        fprintf(stderr, "exec events=%u former tid=%lu worker=%d leader=%d\n",
            execs, former_tid, worker_tid, child);
        failed = 1;
    }
    if (!failed && (waitpid(child, &status, __WALL | WNOHANG) != -1 || errno != ECHILD)) failed = 1;
    if (!failed) puts("ptrace thread exec: untraced worker replaces leader without a stale death report");
    return failed;
}
