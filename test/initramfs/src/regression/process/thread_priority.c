// SPDX-License-Identifier: MPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define IO(level) ((2 << 13) | (level))
static pthread_barrier_t ready;
static pid_t worker_tid;
static int base;
static char *self;

static void need(int ok, const char *what)
{
    if (!ok) { perror(what); exit(1); }
}

static int nice_of(int which, id_t who)
{
    errno = 0;
    int value = getpriority(which, who);
    need(errno == 0, "getpriority");
    return value;
}

static void meet(void)
{
    int result = pthread_barrier_wait(&ready);
    need(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD, "priority barrier");
}

static void *worker(void *unused)
{
    (void)unused;
    worker_tid = syscall(SYS_gettid);
    need(nice_of(PRIO_PROCESS, 0) == base + 1, "pthread inherits caller niceness");
    need(syscall(SYS_ioprio_get, 1, 0) == IO(3), "pthread inherits caller I/O priority");
    need(setpriority(PRIO_PROCESS, 0, base + 3) == 0, "change worker niceness");
    need(syscall(SYS_ioprio_set, 1, 0, IO(5)) == 0, "change worker I/O priority");
    meet();
    meet();
    need(nice_of(PRIO_PROCESS, 0) == base + 4, "targeted worker niceness");
    need(syscall(SYS_ioprio_get, 1, 0) == IO(6), "targeted worker I/O priority");
    meet();
    meet();
    need(nice_of(PRIO_PROCESS, 0) == base + 5, "process-group selector changes worker");
    meet();
    meet();
    int expected = getuid() == 0 ? base + 5 : base + 6;
    need(nice_of(PRIO_PROCESS, 0) == expected, "user selector changes worker");
    char nice_text[16], io_text[16];
    snprintf(nice_text, sizeof(nice_text), "%d", expected);
    snprintf(io_text, sizeof(io_text), "%d", IO(6));
    char *args[] = {self, "--verify", nice_text, io_text, NULL};
    pid_t child = fork();
    need(child >= 0, "fork from worker");
    if (!child) {
        alarm(15);
        if (nice_of(PRIO_PROCESS, 0) != expected || syscall(SYS_ioprio_get, 1, 0) != IO(6)) _exit(10);
        execv(self, args);
        _exit(11);
    }
    int status;
    need(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
         "fork and exec preserve calling worker priorities");
    return NULL;
}

int main(int argc, char **argv)
{
    alarm(120);
    if (argc == 4) {
        need(nice_of(PRIO_PROCESS, 0) == atoi(argv[2]), "exec preserves niceness");
        need(syscall(SYS_ioprio_get, 1, 0) == atoi(argv[3]), "exec preserves I/O priority");
        return 0;
    }
    self = argv[0];
    if (setsid() < 0) need(errno == EPERM && getpgrp() == getpid(), "own process group");
    base = nice_of(PRIO_PROCESS, 0);
    need(base <= 12, "need room for monotonically increasing test niceness");
    need(setpriority(PRIO_PROCESS, 0, base + 1) == 0, "set main niceness");
    need(syscall(SYS_ioprio_set, 1, 0, IO(3)) == 0, "set main I/O priority");
    need(pthread_barrier_init(&ready, NULL, 2) == 0, "initialize priority barrier");
    pthread_t thread;
    need(pthread_create(&thread, NULL, worker, NULL) == 0, "create priority worker");
    meet();
    need(nice_of(PRIO_PROCESS, 0) == base + 1, "worker changes leave main niceness unchanged");
    need(nice_of(PRIO_PROCESS, worker_tid) == base + 3, "read worker by tid");
    need(syscall(SYS_ioprio_get, 1, 0) == IO(3), "worker changes leave main I/O priority unchanged");
    need(syscall(SYS_ioprio_get, 1, worker_tid) == IO(5), "read worker I/O priority");
    need(setpriority(PRIO_PROCESS, worker_tid, base + 4) == 0, "set worker by tid");
    need(syscall(SYS_ioprio_set, 1, worker_tid, IO(6)) == 0, "set worker I/O priority by tid");
    meet();
    meet();
    need(nice_of(PRIO_PGRP, 0) == base + 1, "process-group minimum spans threads");
    need(setpriority(PRIO_PGRP, 0, base + 5) == 0, "set group priority");
    need(nice_of(PRIO_PROCESS, 0) == base + 5, "group selector changes main");
    meet();
    meet();
    if (getuid() != 0) {
        need(nice_of(PRIO_USER, getuid()) == base + 5, "user minimum spans threads");
        need(setpriority(PRIO_USER, getuid(), base + 6) == 0, "set own isolated user priority");
    }
    meet();
    need(pthread_join(thread, NULL) == 0, "join priority worker");
    need(pthread_barrier_destroy(&ready) == 0, "destroy priority barrier");
    errno = 0;
    need(getpriority(PRIO_PROCESS, worker_tid) == -1 && errno == ESRCH, "joined thread is no longer a priority target");
    errno = 0;
    need(getpriority(PRIO_PROCESS, INT_MAX) == -1 && errno == ESRCH, "missing priority target");
    errno = 0;
    need(setpriority(99, 0, 0) == -1 && errno == EINVAL, "invalid priority selector");
    return 0;
}
